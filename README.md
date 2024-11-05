# VMware Explore Barcelona NSX Sync script demo
The script synchronises NSX-T Distributed firewall policy to T-1 Gateway firewalls.  

As there are a couple of limitations in the NSX-T gateway firewall implementation this script replaces certain Application Layer Gateway (ALG) services with new services using hard coded port ranges.  
Additionally as the gateway firewall does not supprt "negated" source or destination groups these have to be replaced with "ANY". Where the firewall action for these rules is "DROP" the script does not sync the rule as this will drop traffic that would otherwise have been allowed.  

## Instructions  

Clone the repository to a folder on a Windows machine, terraform must have been installed previously and be in the PATH environment variable and internet access needs to be available for initialisation of the terraform provider.  

Windows Powershell is not supprted due to certificate handling issues.  

Create a powershell credential object i.e. $Creds = Get-Credential  

Then in the VMwareExplore folder run the Script  .\GatewaySync.ps1 -NSXT \<FQDN of NSX manager\> -credentials $Creds
