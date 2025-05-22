# Power Platform to Azure Secure Connectivity: DIY Guide

## Overview
This guide walks you through securely connecting your Power Platform environment to Azure resources (Key Vault, Storage Accounts, Azure SQL) using private networking and VNet integration. It is based on a practical scenario and scripts, enabling you to test and validate the setup yourself.

---

## Scenario
You will:
- Set up a Power Pages portal for support staff to check shipping details.
- Use a Power Automate flow to retrieve a secret from Azure Key Vault and access a shipping portal.
- See the impact of changing Key Vault network configuration on connectivity.

---

## Prerequisites
- **Azure Subscription** with permissions to create resources
- **Power Platform Managed Environment** (required for VNet integration)
- **PowerShell 5.1** (for some legacy scripts)
- **Azure PowerShell Module** installed

---

## Key Requirements
- **Managed Environment**: Enhanced governance and required for VNet integration.
- **VNet & Subnet**: 
  - Dedicated VNets in both Australia East and Southeast Australia
  - Subnet sized for your workload (at least /26 for production, /27 for dev/test)
  - Subnet delegated to `Microsoft.PowerPlatform/enterprisePolicies`
- **Dual Region**: Both regions are required for high availability.

---

## Implementation Steps

### 1. Clone or Download Scripts
Clone this repository or download the scripts to your local machine.

### 2. Configure Azure Resources
Run the provided `azure-environment.ps1` PowerShell script. This will:
- Create a resource group
- Deploy Key Vault and add a secret
- Grant user access to Key Vault secrets
- Create VNets and subnets in both regions
- Register the subscription for Power Platform
- Delegate subnets and set up enterprise policies
- Assign reader role to Power Platform admin
- Configure Power Platform environment
- Set up private endpoints, DNS, and VNet peering
- Restrict Key Vault access to only the specified subnets
- (Optional) Clean up resources

> **Note:** Some steps require running additional scripts from the `powershell/enterprisePolicies` directory. Follow the comments in `azure-environment.ps1` for guidance.

### 3. Key Vault Security Approaches
- **Service Endpoint Method**: Restrict Key Vault firewall to allow only Power Platform subnets and enable service endpoints (not fully private).
- **Private Endpoint Method (Recommended)**: Create private endpoints, configure VNet linking, set up VNet peering, and create private DNS records for full privacy.

### 4. Test Connectivity
- Use your Power Pages application to test secure connectivity to Key Vault.
- Modify Key Vault network settings to observe the effect on connectivity.

---

## Troubleshooting
- Ensure you are using PowerShell 5.1 for scripts that require `System.Windows.Forms`.
- Verify user email addresses and permissions when granting Key Vault access.
- Check subnet delegation and address space sizing.

---

## Clean Up
To remove all resources, run the cleanup section at the end of `azure-environment.ps1` (removes the resource group).

---

## References
- [Microsoft Docs: Power Platform VNet Integration](https://learn.microsoft.com/en-us/power-platform/admin/vnet-integration)
- [Enterprise Policies GitHub Scripts](https://github.com/microsoft/PowerApps-Samples/tree/main/powershell/enterprisePolicies)

---

## Support
If you have questions, please open an issue or leave a comment.

---

**Happy testing!**
