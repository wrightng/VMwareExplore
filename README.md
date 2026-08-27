# NSX Distributed Firewall to Gateway Firewall Synchronization

## Summary

This project synchronizes VMware NSX Distributed Firewall (DFW) policies to eligible Tier-1 Gateway Firewalls. It retrieves security policies and rules from NSX Manager, adapts settings that are not supported by Gateway Firewall, generates Terraform configuration for each target Tier-1 gateway, and applies the resulting configuration through the VMware NSX Terraform provider.

The script also creates replacement services for Application Layer Gateway (ALG) services that cannot be used directly by Gateway Firewall. Service substitutions are defined in `GatewayServiceMap.json`, while Tier-1 gateways that must not receive synchronized policies are listed in `ExcludedGW.json`.

## Process Description

1. **Authenticate with NSX Manager**

	The script creates a Basic Authentication header from the supplied PowerShell credential and verifies connectivity to NSX Manager before making changes.

2. **Validate and prepare the workspace**

	Required Terraform and Poshstache template files are validated. The `StandardServices`, `Gateway`, and `Terraform` working directories are created when they do not already exist.

3. **Synchronize replacement services**

	Terraform configuration from `Templates/StandardServices.tf` is copied into the `StandardServices` directory. Terraform is initialized when required, and the replacement services are planned and applied before firewall policies are processed.

4. **Retrieve NSX configuration**

	The script retrieves all NSX services, DFW security policies, policy rules, and Tier-1 gateways through the NSX Policy API. Paginated API responses are collected until all results have been returned.

5. **Select target gateways**

	Only Tier-1 gateways with Gateway Firewall enabled are selected. Gateways named in `ExcludedGW.json` are removed from the target list.

6. **Transform DFW policies**

	DFW policies retain their category ordering and are converted into Gateway Firewall policies. During conversion:

	- `ANY` values are omitted where Terraform represents them by an absent property.
	- Negated source or destination groups are replaced by `ANY`, because Gateway Firewall does not support these exclusions.
	- Non-allow rules containing negated groups are omitted to avoid unintentionally broad drop or reject behavior.
	- The default Layer 2 policy is excluded because it is not applicable to Gateway Firewall.
	- The default Layer 3 policy sequence number is adjusted to fit the Gateway Firewall sequence range.
	- ALG services are replaced according to `GatewayServiceMap.json` when both source and replacement services exist.

7. **Generate and apply Gateway Firewall configuration**

	A Terraform file is generated for each selected Tier-1 gateway using `Templates/GatewayFW.template`. Terraform then plans and applies the complete Gateway Firewall configuration. Apply output is written to `Gateway/applied.json` for troubleshooting and audit purposes.

## Requirements

- PowerShell 7 or later. Windows PowerShell is not supported because the script relies on certificate-handling parameters available in modern PowerShell.
- Terraform available through the system `PATH`.
- The PowerShell `Poshstache` module.
- Network access to NSX Manager.
- NSX credentials with permission to read DFW configuration and create or update services and Gateway Firewall policies.
- Internet access when Terraform needs to download or initialize the NSX provider.

Install Poshstache if it is not already available:

```powershell
Install-Module Poshstache -Scope CurrentUser
```

## Configuration

Review these files before running the synchronization:

- `GatewayServiceMap.json` maps unsupported source services to Gateway Firewall-compatible replacement services.
- `ExcludedGW.json` contains the display names of Tier-1 gateways that must not be processed.
- `Templates/` contains the Terraform and Poshstache templates used to generate working configuration.

The generated `Gateway`, `StandardServices`, and `Terraform` directories are excluded from source control.

## Usage

Run the script from the repository root:

```powershell
$Credentials = Get-Credential
.\GatewaySync.ps1 -NSXT nsx-manager.example.com -Credentials $Credentials
```

Review the Terraform output and generated apply logs if synchronization does not complete successfully.

## Limitations

- Built-in NSX malicious-IP groups are restricted to DFW rules and cannot be referenced directly by Gateway Firewall policies.
- Negated groups cannot be represented exactly on Gateway Firewall. The script applies conservative handling to avoid creating overly broad deny rules.
- The script synchronizes policies into the `LocalGatewayRules` category and manages the generated resources through Terraform state.
