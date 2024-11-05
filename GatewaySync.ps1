<#
.SYNOPSIS
This script synchronises the NSX-T distributed firewall policy to T-1 Gateway firewalls

.DESCRIPTION
The script uses terraform to sync a set of replacement NSX-T services to work around a limitation 
in implementation of Application Layer Gateway functionality on the gateway firewall

It then downloads the DFW firewall policy and modfies to to use the replacement services and removes
any negated sources or destinations as this functionality is not currently present.

The file GatewayServiceMap.json details the services to be replaced

The file ExcludedGW.json file contains an array of T-1 Gateway firewall to be excluded from the sync 
process

.PARAMETER NSXT
The fully qualified name or IP address of the NSX-T manager

.PARAMETER Credentials
a powershell credential object for connecting to the NSX manager

.EXAMPLE
Create a credential object by using the command $Creds = get-credential

GatewaySync.ps1 -NSXT labnst01.lab.com -Credentials $Creds
#>
Param(
    [STRING]$NSXT = "labnst01.lab.com",
    [Parameter(mandatory=$true)]
    [PSCredential]$Credentials
)
#Requires -Modules Poshstache

# First test that it is possible to log into the NSX manager with defined credentials
try {
    $user = $Credentials.UserName
    $pass = $Credentials.GetNetworkCredential().Password
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("${user}:${pass}")
    $base64 = [System.Convert]::ToBase64String($bytes)
    $RestHeader = @{Authorization = "Basic ${base64}"; Accept = "application/json"}
    $null = Invoke-WebRequest -Uri "https://$NSXT/api/v1/proxy/config" -Method 'GET' -Headers $RestHeader -SkipCertificateCheck
} catch {
    Write-Host "Error - Failed to authenticate to NSX-T Manager '$NSXT', either the address is incorrect or the credentials supplied are invalid" -ForegroundColor Red
    Exit
}

$Location = Get-Location 
$Location = $Location.Path


if(!(test-path "$location\Templates\main.tf") -or !(test-path "$location\Templates\variables.tf") -or !(test-path "$location\Templates\StandardServices.tf") -or !(test-path "$location\Templates\GatewayFW.template")){
    Write-Host "Error - Failed to locate all required template files" -ForegroundColor Red
    Exit
}
# If StandardServices folder doesn't exist, create it
$StandardServicesPath = test-path "$Location\StandardServices"
if(!$StandardServicesPath){ New-item "$Location\StandardServices" -ItemType Directory | out-null}

# If Gateway folder doesn't exist, create it
$StandardServicesPath = test-path "$Location\Gateway"
if(!$StandardServicesPath){ New-item "$Location\Gateway" -ItemType Directory | out-null}

# If terraform folder doesn't exist, create it
$StandardServicesPath = test-path "$Location\Terraform"
if(!$StandardServicesPath){ New-item "$Location\Terraform" -ItemType Directory | out-null}

# copy relevant tf files for the standard services
copy-item "$location\Templates\*.tf" "$Location\StandardServices"



# Set environment variables for Terraform to use avoiding writing credentials into terraform files
Set-Item -Path env:TF_VAR_nsx_manager -Value $NSXT
Set-Item -Path env:TF_VAR_user_name -Value $user
Set-Item -Path env:TF_VAR_password -Value $pass
Set-Item -Path env:TF_DATA_DIR -Value "$Location\Terraform\.terraform"

# Load mapping file - used to remove ALG services from gateway policies
$Mapping = get-content "$Location\GatewayServiceMap.json" | convertfrom-json -AsHashtable
if ($Null -eq $Mapping ){
    Write-Host "Error - service mapping file is blank or missing" -ForegroundColor Red
    Exit
}

# We need to do a terraform sync to ensure replacement services are present 
$TerraformFolder = "$Location\StandardServices"

# If needed initialize terraform
Try{
    $TFTest = terraform.exe -chdir="$TerraformFolder" plan -no-color -json | convertfrom-json
} catch {
    Write-Host "Error - Terraform executable does not appear to be in the windows path" -ForegroundColor Red
    Exit
}
if ($($TFTest.diagnostic.detail) -like "*Plugin reinitialization required. Please run*" -or $($TFTest.diagnostic.detail) -like "*The following dependency selections recorded in the lock file are inconsistent with the current configuration*"){
    Try {
        terraform -chdir="$TerraformFolder" init -no-color | out-null
    } catch {
        Write-Host "Error - Unable to initialise terraform" -ForegroundColor Red
        Exit
    }
    write-host "Terraform has been initialised"
}

Write-Host "Sync of standard services starting"
$TFPlan = terraform -chdir="$TerraformFolder" plan -no-color -json | convertfrom-json
if ($($TFPlan."@level") -contains "error"){
    write-host" The terraform plan contains errors" -ForegroundColor Red
    $TFPlan | convertto-json -depth 100
    Exit
} else {
    $Applied = terraform -chdir="$TerraformFolder" apply --auto-approve -no-color -json | ConvertFrom-Json
    $Applied | convertto-json -depth 100 | Set-Content "$TerraformFolder\applied.json"
    $SummaryOutputs = $Applied | Where-Object {$_.type -eq "change_summary"} | Where-Object {$_."@message" -notlike "Plan: *"}
    foreach ($Output in $SummaryOutputs){
        Write-Host "$($Output."@message")"
    }
    if ($($Output."@message") -notlike "Apply complete!*"){
        write-host "The terraform apply for standard services does not appear to have completed succesfully" -ForegroundColor Red
        write-host "Please examine $TerraformFolder\applied.json for details" -ForegroundColor Red
        Exit
    } else {
        Write-Host "Sync of standard services completed"
    }
}

# Get all Services from the NSX Manager
$PageSize = 512
$Cursor = ''
$AllServices = @()
do {
    $Uri = "https://$NSXT/policy/api/v1/infra/services?page_size=${PageSize}&cursor=${cursor}"
    $Services = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Headers $RestHeader -Uri $Uri -NoProxy
    $AllServices += $Services.results
    $Cursor = "$($Services.Cursor)"
} until ([string]::IsNullOrEmpty($Cursor))

# Get all policies from the NSX Manager
$PageSize = 512
$Cursor = ''
$AllPolicies = @()
do {
    $Uri = "https://$NSXT/policy/api/v1/infra/domains/default/security-policies?page_size=${PageSize}&cursor=${cursor}"
    $Policies = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Headers $RestHeader -Uri $Uri -NoProxy
    $AllPolicies += $Policies.results
    $Cursor = "$($Policies.Cursor)"
} until ([string]::IsNullOrEmpty($Cursor))

# Remove the default layer2 section as it's irrelevant for a gateway firewall
$AllPolicies = $AllPolicies | Where-Object {$_.id -ne "default-layer2-section"}

# Ensure that order of policies is maintained by sorting on internal sequence number
$FirewallTable = $AllPolicies | Sort-Object -Property internal_sequence_number

# Get rules for each policy section
$FWRules = @{}
foreach($PolicySection in $FirewallTable){
    $Uri = "https://$NSXT/policy/api/v1$($PolicySection.path)"
    $RawRules = Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Headers $RestHeader -Uri $Uri -NoProxy
    $FWRules.Add($($PolicySection.display_name),$RawRules)
}

# Create an ordered array list of the policies with their rules contained
$GWPolicies = New-Object -TypeName "System.Collections.ArrayList"
$Policies = $FWRules.keys
foreach($Key in $Policies ){
    $Policy = $FWRules.$Key
    [void]$GWPolicies.Add($Policy)
}
$GWPolicies = $GWPolicies | Sort-Object -Property internal_sequence_number


# Get all T-1s from NSX Manager
$PageSize = 512
$Cursor = ''
$AllT1s = @()
do {
    $Uri = "https://$NSXT/policy/api/v1/infra/tier-1s?page_size=${PageSize}&cursor=${cursor}"
    $T1s= Invoke-RestMethod -SkipCertificateCheck -Method 'GET' -Headers $RestHeader -Uri $Uri -NoProxy
    $AllT1s += $T1s.results
    $Cursor = "$($T1s.Cursor)"
} until ([string]::IsNullOrEmpty($Cursor))


# Load in the array of GW firewalls to exclude from sychronisation
[ARRAY]$ExcludedGW = get-content "$Location\ExcludedGW.json" | convertfrom-json

# Filter down to T-1 with Gateway Firewall Enabled and remove excluded gateway firewalls
$GWFW_T1s = @()
Foreach($T1 in $AllT1s){
    If($($T1.disable_firewall) -eq $False -and $ExcludedGW -notcontains $($T1.display_name)){
        $GWFW_T1s+= $T1
    }
}
write-host "$($GWFW_T1s.count) T-1 gateway firewalls identified to synchronize policy to"

# Define the terraform folder to use for syncing to gateway firewall
$TerraformFolder = "$Location\Gateway"

# Remove previous TF files
remove-item "$TerraformFolder\*.tf" -force | out-null

# Copy base terraform files
copy-item -Path "$location\Templates\main.tf" -Destination $TerraformFolder
copy-item -Path "$location\Templates\variables.tf" -Destination $TerraformFolder

# Define terraform file for each Gateway firewall
foreach ($GWFW_T1 in $GWFW_T1s){
    $scope = $GWFW_T1.path
    $GWName = $GWFW_T1.display_name
    $GatewayList = New-Object -TypeName "System.Collections.ArrayList"
    foreach ($GatewayPolicy in $GWPolicies){
        if($($GatewayPolicy.category) -eq "Emergency"){
            $Seq = 0
        } elseif ($($GatewayPolicy.category) -eq "Infrastructure"){
            $Seq = 20000
        } elseif ($($GatewayPolicy.category) -eq "Environment"){
            $Seq = 40000
        } elseif ($($GatewayPolicy.category) -eq "Application"){
            $Seq = 60000
        }
        $GatewayRules = New-Object -TypeName "System.Collections.ArrayList"
        $RuleHash =@{}
        foreach($Rule in $GatewayPolicy.rules){
            [STRING]$disabled = $Rule.disabled
            [STRING]$logged = $Rule.logged
            [STRING]$destinations_excluded = $Rule.destinations_excluded
            [STRING]$sources_excluded = $Rule.sources_excluded
            $RuleDetails = [PSCustomObject]@{
                display_name = $Rule.display_name
                destination_groups = ($Rule.destination_groups -join '","')
                destinations_excluded = $destinations_excluded.ToLower()
                disabled = $disabled.ToLower()
                logged = $logged.ToLower()
                notes = $rule.notes
                profiles =($Rule.profiles -join '","')
                services = ($Rule.services -join '","')
                source_groups = ($Rule.source_groups -join '","')
                sources_excluded = $sources_excluded.ToLower()
                log_label = $Rule.log_label
                action = $Rule.action
                scope = $scope
            }
            # Any rule with "ANY" remove the any to allow terraform to create it
            $Negated = $false
            if($RuleDetails.services -eq "ANY"){
                $RuleDetails = $RuleDetails | Select-Object -Property * -ExcludeProperty services
            }
            if($RuleDetails.profiles -eq "ANY"){
                $RuleDetails = $RuleDetails | Select-Object -Property * -ExcludeProperty profiles
            }
            if($RuleDetails.source_groups -eq "ANY"){
                $RuleDetails = $RuleDetails | Select-Object -Property * -ExcludeProperty source_groups
            }
            if($RuleDetails.destination_groups -eq "ANY"){
                $RuleDetails = $RuleDetails | Select-Object -Property * -ExcludeProperty destination_groups
            }

            # if negated sources or destnation remove to allow terraform to create an "ANY"
            if($RuleDetails.destinations_excluded -eq "true"){
                $RuleDetails = $RuleDetails | Select-Object -Property * -ExcludeProperty destination_groups
                $RuleDetails = $RuleDetails | Select-Object -Property * -ExcludeProperty destinations_excluded
                $Negated = $true
            }
            if($RuleDetails.sources_excluded -eq "true"){
                $RuleDetails = $RuleDetails | Select-Object -Property * -ExcludeProperty source_groups
                $RuleDetails = $RuleDetails | Select-Object -Property * -ExcludeProperty sources_excluded
                $Negated = $true
            }
            if ($Negated -eq $true -and $($Rule.action) -eq "DROP"){
                # Not adding the rule as it would drop traffic with a source or dest of ANY
                write-host "Warning - Rule $($Ruledetails.display_name) from policy section $() dropped as it would result in a drop with ANY as source or destination" -foreground DarkYellow
            } else {
                [void]$GatewayRules.Add($Ruledetails)
            }
        }

        # Need to change the sequence number of the default layer 3 policy as the GWFW has a different maximum
        if ($($GatewayPolicy.sequence_number) -eq 2147483647){
            [STRING]$newSeq = 999999
        } else {
            [STRING]$newSeq = $Seq + $($GatewayPolicy.sequence_number)
        }   
        if($GatewayRules.count -ne 0){
            $ResourceName = $($GatewayPolicy.display_name) -replace '[^a-zA-Z0-9]','' # Need to keep resource names terraform compatible
            $RuleHash.Add("rules",$GatewayRules)
            $RuleHash.Add("Name",$($GatewayPolicy.display_name))
            $RuleHash.Add("ResourceName",$ResourceName)
            $RuleHash.Add("Seq",$newSeq)
            $RuleHash.Add("GWName",$GWName)
            [void]$GatewayList.Add($RuleHash)
        }
    }
    $Hash = @{}
    $Hash.Add("Gateways",$GatewayList)
    $JsonConfig = $Hash | convertto-json -depth 100 | Out-String

    # Create terraform file for each GW firewall and replace the ALG services
    ConvertTo-PoshstacheTemplate -InputFile "$Location\Templates\GatewayFW.template" -ParametersObject $jsonConfig | Out-File "$TerraformFolder\$GWName.tf" -Force -Encoding "UTF8"
    if ($Null -ne $Mapping){
        $TFFile = get-content "$TerraformFolder\$GWName.tf"
        foreach($Key in $Mapping.Keys){
            $SourceService = $AllServices | Where-Object {$_.display_name -eq $Key}
            $SourcePath = $SourceService.path
            $MappedService = $AllServices | Where-Object {$_.display_name -eq $($Mapping.$Key)}
            $MappedPath = $MappedService.path
            if($Null -ne $MappedPath -and $Null -ne $SourcePath){
                $TFFile = $TFFile -replace $SourcePath,$MappedPath
            }
        }
        $TFFile | set-content "$TerraformFolder\$GWName.tf" -Force -Encoding "UTF8"
    }

}


# We need to do a terraform sync to ensure replacement services are present 
$TerraformFolder = "$Location\Gateway"

# If needed initialize terraform
Try{
    $TFTest = terraform.exe -chdir="$TerraformFolder" plan -no-color -json | convertfrom-json
} catch {
    Write-Host "Error - Terraform executable does not appear to be in the windows path" -ForegroundColor Red
    Exit
}
if ($($TFTest.diagnostic.detail) -like "*Plugin reinitialization required. Please run*" -or $($TFTest.diagnostic.detail) -like "*The following dependency selections recorded in the lock file are inconsistent with the current configuration*"){
    Try {
        terraform -chdir="$TerraformFolder" init -no-color | out-null
    } catch {
        Write-Host "Error - Unable to initialise terraform" -ForegroundColor Red
        Exit
    }
    write-host "Terraform has been initialised"
}

Write-Host "Sync of Gateway policies starting"
$TFPlan = terraform -chdir="$TerraformFolder" plan -no-color -json | convertfrom-json
if ($($TFPlan."@level") -contains "error"){
    write-host" The terraform plan contains errors" -ForegroundColor Red
    $TFPlan | convertto-json -depth 100
    Exit
} else {
    $Applied = terraform -chdir="$TerraformFolder" apply --auto-approve -no-color -json | ConvertFrom-Json
    $Applied | convertto-json -depth 100 | Set-Content "$TerraformFolder\applied.json"
    $SummaryOutputs = $Applied | Where-Object {$_.type -eq "change_summary"}  | Where-Object {$_."@message" -notlike "Plan: *"}
    foreach ($Output in $SummaryOutputs){
        Write-Host "$($Output."@message")"
    }
    if ($($Output."@message") -notlike "Apply complete!*"){
        write-host "The terraform apply for Gateway Firewall does not appear to have completed succesfully" -ForegroundColor Red
        write-host "Please examine $TerraformFolder\applied.json for details" -ForegroundColor Red
        Exit
    } else {
        Write-Host "Sync of gateway firewall policies completed"
    }
}