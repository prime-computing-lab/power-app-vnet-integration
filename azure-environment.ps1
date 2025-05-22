# Azure PowerShell script to set up resources for Power App integration

# https://forwardforever.com/setting-up-power-platform-vnet-integration/
# Connect to Azure
Connect-AzAccount

# Set the subscription context
$subscriptionId = (Get-AzContext).Subscription.Id
Set-AzContext -SubscriptionId $subscriptionId

# Variables
$resourceGroupName = "rg-test-power-app-int"
$location = "australiaeast"
$keyVaultName = "kv-power-app-int-2025"
$secretName = "shippingCredentials"
$secretValue = "suP3rSecr3t!"

# Create a new resource group
Write-Host "Creating resource group $resourceGroupName in $location..."
New-AzResourceGroup -Name $resourceGroupName -Location $location

# Create a new key vault
Write-Host "Creating key vault $keyVaultName..."
$keyVaultParams = @{
    Name = $keyVaultName
    ResourceGroupName = $resourceGroupName
    Location = $location
    Sku = "Standard"
    EnabledForDeployment = $true
    EnabledForTemplateDeployment = $true
    EnabledForDiskEncryption = $true
    EnableRbacAuthorization = $false
}
New-AzKeyVault @keyVaultParams

# Convert secret to secure string
$secureSecretValue = ConvertTo-SecureString -String $secretValue -AsPlainText -Force

# Add a secret to the key vault
Write-Host "Adding secret $secretName to key vault..."
Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName -SecretValue $secureSecretValue

Write-Host "Setup completed successfully!"

# Grant access to key vault secret for specific user
$userEmail = ""
$userObjectId = (Get-AzADUser -UserPrincipalName $userEmail).Id

# Check if user exists
if ($null -eq $userObjectId) {
    Write-Error "User $userEmail not found. Please verify the email address."
    exit
}

# Grant secret permissions to the user
# Key Vault permissions for secrets: get, list, set, delete, backup, restore, recover, purge
Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName `
                          -ResourceGroupName $resourceGroupName `
                          -ObjectId $userObjectId `
                          -PermissionsToSecrets get,list

Write-Host "Access granted to $userEmail for secrets in key vault $keyVaultName"

####
# test power pages connectivity to key vault
# https://supportportal-9cda.powerappsportals.com/shipping-credentials/

###########################
#### Power Platform Vnet Injection

# create vnet and subnet /24 in australiaeast
$vNetRegionAE = "australiaeast"
$vNetNameAE = "vnet-power-platform-test-ae"
$vNetAddressPrefixAE = "192.168.0.0/16"
$vNetSubnetNameAE = "subnet-power-platform-test-ae"
$vNetSubnetAddressPrefixAE = "192.168.1.0/24"
$vNetAE = New-AzVirtualNetwork -ResourceGroupName $resourceGroupName `
    -Location $vNetRegionAE `
    -Name $vNetNameAE `
    -AddressPrefix $vNetAddressPrefixAE
$vNetSubnetAE = Add-AzVirtualNetworkSubnetConfig -Name $vNetSubnetNameAE `
    -AddressPrefix $vNetSubnetAddressPrefixAE `
    -VirtualNetwork $vNetAE
$vNetAE | Set-AzVirtualNetwork

# create vnet and subnet /24 in australiasoutheast
$vNetRegionASE = "australiasoutheast"
$vNetNameASE = "vnet-power-platform-test-ase"
$vNetAddressPrefixASE = "192.169.0.0/16"
$vNetSubnetNameASE = "subnet-power-platform-test-ase"
$vNetSubnetAddressPrefixASE = "192.169.1.0/24"
$vNetASE = New-AzVirtualNetwork -ResourceGroupName $resourceGroupName `
    -Location $vNetRegionASE `
    -Name $vNetNameASE `
    -AddressPrefix $vNetAddressPrefixASE
$vNetSubnetASE = Add-AzVirtualNetworkSubnetConfig -Name $vNetSubnetNameASE `
    -AddressPrefix $vNetSubnetAddressPrefixASE `
    -VirtualNetwork $vNetASE
$vNetASE | Set-AzVirtualNetwork

# register the subscription for Microsoft.PowerPlatform
./PowerApps-Samples-Sparse/powershell/enterprisePolicies/SetupSubscriptionForPowerPlatform.ps1

# delegate the subnet to Power Platform Enterprise Policies
./powershell\enterprisePolicies\SubnetInjection\SetupVnetForSubnetDelegation.ps1

# create the vnet injection enterprise policy
$vnetIdAE = $vNetAE.Id
$vnetIdASE = $vNetASE.Id
$enterprisePolicyName = "Power-Platform-Test-Vnet-Injection-Enterprise-Policy"
./powershell\enterprisePolicies\SubnetInjection\CreateSubnetInjectionEnterprisePolicy.ps1


# assign reader role to Power Platform Admin https://learn.microsoft.com/en-us/power-platform/admin/customer-managed-key#grant-reader-role-to-a-power-platform-administrator
$powerPlatformAdminUserId = ""
$enterprisePolicyResourceId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.PowerPlatform/enterprisePolicies/$enterprisePolicyName"
New-AzRoleAssignment -ObjectId $powerPlatformAdminUserId -RoleDefinitionName Reader -Scope $enterprisePolicyResourceId

# configure power platform environment
./PowerApps-Samples-Sparse/powershell/enterprisePolicies/InstallPowerAppsCmdlets.ps1
 
$powerPlaftformEnvironmentId = ""
./powershell\enterprisePolicies\SubnetInjection\NewSubnetInjection.ps1


#########
# Create Private Endpoint for Key Vault
# Define variables for private endpoint subnet
$privEndpointSubnetName = "subnet-priv-endpoint-ae"
$privEndpointSubnetAddressPrefix = "192.168.2.0/24"
$privDnsZoneName = "privatelink.vaultcore.azure.net"
$privEndpointName = "$keyVaultName-private-endpoint"

Write-Host "Creating subnet for private endpoint..."
# Get the virtual network
$vNet = Get-AzVirtualNetwork -Name $vNetNameAE -ResourceGroupName $resourceGroupName

# Add the private endpoint subnet
Add-AzVirtualNetworkSubnetConfig -Name $privEndpointSubnetName `
    -AddressPrefix $privEndpointSubnetAddressPrefix `
    -VirtualNetwork $vNet | Set-AzVirtualNetwork

# Get the updated virtual network and the subnet
$vNet = Get-AzVirtualNetwork -Name $vNetNameAE -ResourceGroupName $resourceGroupName
$privEndpointSubnet = Get-AzVirtualNetworkSubnetConfig -Name $privEndpointSubnetName -VirtualNetwork $vNet

Write-Host "Creating private DNS zone..."
# Create the private DNS zone
$privateDnsZone = New-AzPrivateDnsZone -ResourceGroupName $resourceGroupName `
    -Name $privDnsZoneName

Write-Host "Creating virtual network link..."
# Create DNS network link
$vNetLinkName = "$vNetNameAE-link"
$vNetLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $resourceGroupName `
    -ZoneName $privDnsZoneName `
    -Name $vNetLinkName `
    -VirtualNetworkId $vNet.Id

$vNet = Get-AzVirtualNetwork -Name $vNetNameASE -ResourceGroupName $resourceGroupName
$vNetLinkName = "$vNetNameASE-link"
$vNetLink = New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $resourceGroupName `
    -ZoneName $privDnsZoneName `
    -Name $vNetLinkName `
    -VirtualNetworkId $vNet.Id

# vnet peering of vnetAE and vnetASE
$vNetAE = Get-AzVirtualNetwork -Name $vNetNameAE -ResourceGroupName $resourceGroupName
$vNetASE = Get-AzVirtualNetwork -Name $vNetNameASE -ResourceGroupName $resourceGroupName
$vNetAE | Add-AzVirtualNetworkPeering -Name "$vNetNameAE-to-$vNetNameASE" `
    -RemoteVirtualNetworkId $vNetASE.Id
$vNetASE | Add-AzVirtualNetworkPeering -Name "$vNetNameASE-to-$vNetNameAE" `
    -RemoteVirtualNetworkId $vNetAE.Id


Write-Host "Creating private endpoint for Key Vault $keyVaultName..."
# Get the Key Vault resource
$keyVault = Get-AzKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName

# Create private endpoint
$privateEndpointConnection = New-AzPrivateLinkServiceConnection -Name "$privEndpointName-connection" `
    -PrivateLinkServiceId $keyVault.ResourceId `
    -GroupId "vault"

$privateEndpoint = New-AzPrivateEndpoint -ResourceGroupName $resourceGroupName `
    -Name $privEndpointName `
    -Location $vNetRegionAE `
    -Subnet $privEndpointSubnet `
    -PrivateLinkServiceConnection $privateEndpointConnection

Write-Host "Creating private DNS record..."
# Get the private IP address of the private endpoint
$privateEndpoint = Get-AzPrivateEndpoint -Name $privEndpointName -ResourceGroupName $resourceGroupName
$networkInterface = Get-AzNetworkInterface -ResourceId ($privateEndpoint.NetworkInterfaces[0].Id)
$privateIpAddress = $networkInterface.IpConfigurations[0].PrivateIpAddress

# Create A record in the private DNS zone
$recordSet = New-AzPrivateDnsRecordSet -ResourceGroupName $resourceGroupName `
    -ZoneName $privDnsZoneName `
    -Name $keyVaultName `
    -RecordType A `
    -Ttl 3600

Add-AzPrivateDnsRecordConfig -RecordSet $recordSet -Ipv4Address $privateIpAddress

Set-AzPrivateDnsRecordSet -RecordSet $recordSet

Write-Host "Private endpoint for Key Vault created successfully."

# disable public access to the key vault
Update-AzKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -PublicNetworkAccess Disabled

Write-Host "Public access to Key Vault $keyVaultName has been disabled."

# Get subnet resource IDs
$subnetAE = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Network/virtualNetworks/$vNetNameAE/subnets/$vNetSubnetNameAE"
$subnetASE = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Network/virtualNetworks/$vNetNameASE/subnets/$vNetSubnetNameASE"

# Build the network ACL object
$networkAcls = @{
    DefaultAction = "Deny"
    Bypass = "AzureServices"
    IpRules = @()
    VirtualNetworkRules = @(
        @{
            Id = $subnetAE
            IgnoreMissingVnetServiceEndpoint = $false
        }
        @{
            Id = $subnetASE
            IgnoreMissingVnetServiceEndpoint = $false
        }
    )
}

# Update Key Vault network ACLs to allow only these subnets
Update-AzKeyVault `
    -VaultName $keyVaultName `
    -ResourceGroupName $resourceGroupName `
    -NetworkAcl $networkAcls

Write-Host "Key Vault $keyVaultName now allows access only from specified subnets."

# cleanup
# delete the resource group
Remove-AzResourceGroup -Name $resourceGroupName -Force