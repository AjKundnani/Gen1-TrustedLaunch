<#
.SYNOPSIS
Upgrades Azure VM from Gen1 to Trusted Launch Configuration with OS State preserved.    

.DESCRIPTION
    PREREQUISITES:
        1. On-board to Gen1 to Trusted launch VM private preview at https://aka.ms/Gen1ToTLUpgrade.
        2. Az.Compute, Az.Accounts PowerShell Module
        3. Current Gen 1 VM is running.
        4. VM Contributor rights on resource group.
        5. If backup is enabled, Gen1 VM backup is configured with Enhanced policy.
            1. Existing backup can be migrated to Enhanced policy using preview https://aka.ms/formBackupPolicyMigration.
        6. ASR is not enabled for Gen1 VM. ASR currently does not supports Trusted launch VMs.
        7. SSE CMK if enabled should be disabled during upgrade. It should be re-enabled post-upgrade.
        8. Azure IaaS VM Agent should be installed and healthy.

    STEPS:
        1. Create csv with VMName, ResourceGroupName, EnableSecureBoot parameters.
        2. Execute PowerShell script which will:
            1. Check if current VM Size is compatible with Trusted launch.
            2. Execute MBR to GPT OS Disk boot partition conversion.
            3. De-allocate or Stop VM.
            4. Update VM to Gen2-Trusted launch.
            5. Start VM.
        3. Validate health of workload and virtual machine.
        4. Re-enable SSE CMK and disk encryptions.

.PARAMETER subscriptionId
Subscription ID for Gen1 VM & target Gen2 VM.

.PARAMETER tenantDomain
Primary AAD Domain Name for authentication. (For example, contoso.onmicrosoft.com)

.PARAMETER csvLocation
Local file path location of csv containing vmName, vmResourceGroupName, enableSecureBoot details.

.PARAMETER vmName
(Csv input parameter) Gen1 VM Resource Name.

.PARAMETER vmResourceGroupName
(Csv input parameter) Resource Group for Gen1 VM & target Gen2 VM.

.PARAMETER enableSecureBoot
(Csv input parameter) If target Trusted Launch VM should be deployed with Secure Boot enabled (TRUE) or disabled (FALSE). This option should be disabled if VM is hosting custom or unsigned boot drivers which cannot be attested.

.EXAMPLE
    .\Convert-Gen1ToTLVM.ps1 -subscriptionId <subscriptionId> -tenantDomain <aadTenantDomain> -vmName <gen1VmName> -targetVmName <gen2VmName> -vmResourceGroupName <gen1VmResourceGroup> -workingDirectory "<localPathForOsDiskDownload>"
    
    Convert Gen1 VM to Trusted Launch VM using different VM Name and same resource group.
    
.EXAMPLE
    .\Upgrade-Gen1ToTL.ps1 -subscriptionId $subscriptionId -tenantDomain contoso.onmicrosoft.com -csvLocation "C:\Temp\sampleCsv.csv"
    
    Upgrade all VMs provided in csv from Gen1 to Trusted launch with specific parameter values.

.LINK
    https://aka.ms/TrustedLaunch

.LINK
    https://aka.ms/TrustedLaunchUpgrade
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]

param (
    [Parameter(Mandatory = $true, HelpMessage = "Azure Subscription Id or Guid")]
    [string][ValidateNotNullOrEmpty()]$subscriptionId,
    [Parameter(Mandatory = $true, HelpMessage = "Azure Tenant domain")]
    [string][ValidateNotNullOrEmpty()]$tenantDomain,
    [Parameter(Mandatory = $true, HelpMessage = "Location of csv containing Gen1 VM(s) details - vmName, vmResourceGroupName, EnableSecureBoot.")]
    [string][ValidateNotNullOrEmpty()]$csvLocation
)

#region - Functions
Function Add-AzPSAccount {
	<#
	.SYNOPSIS
		Login Azure Account

	.DESCRIPTION
		Login Azure Account

	.PARAMETER subscriptionID
		Specify Azure Subscription ID

	.INPUTS
		None

	.OUTPUTS
		$TenantID
#>
	[CmdletBinding()]
	[OutputType([boolean])]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$subscriptionID,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$tenantDomain,
        [Parameter(Mandatory=$false, HelpMessage = "The cloud environment to logon to.")]
        [string]$environment
	)

	try {
		#region - Enable-AzAccount()
        $paramConnectAzAccount = @{
            subscriptionId = $subscriptionID
            Tenant       = $tenantDomain
            Environment  = $environment
            ErrorAction    = 'Stop'
        }
        Connect-AzAccount @paramConnectAzAccount
		return $true
		#endregion
	} catch [system.exception] {
		$messageTxt = "Error in Enable-AzAccount() `n$($psitem.Exception.Message)"
        Write-Output $messageTxt
		return
	}
}
function Get-ErrorLevel {
	<#
	.SYNOPSIS
		Get ERRORLEVEL variable value
	
	.DESCRIPTION
		Get ERRORLEVEL variable value
	
	.OUTPUTS
		None.
	
	.NOTES	
	#>
	
	#region - Get ERRORLEVEL variable value
	$script:ERRORLEVEL
	#endregion
}
function Set-ErrorLevel {
	<#
	.SYNOPSIS
		Set ERRORLEVEL variable value
	
	.DESCRIPTION
		Set ERRORLEVEL variable value
	
	.PARAMETER level
		ERRORLEVEL level [int] parameter.
	
	.OUTPUTS
		$ERRORLEVEL
	
	.NOTES		
	#>
	
	param
	(
		[Parameter(Mandatory = $false)]
		[int]$level = 0
	)
	
	#region - Set Errorlevel
	$script:ERRORLEVEL = $level
	#endregion
}
#endregion

#region - Validate Pre-Requisites
try {
    Set-Errorlevel 0 | Out-Null
    Get-Errorlevel | Out-Null

    $azPsModule = @(
        'Az.Accounts',
        'Az.Compute'
    )

    foreach ($azModule in $azPsModule) {
        If ((Get-Module $azModule -listavailable).count -gt 0) {
            $messageTxt = "Located $azModule on local machine."
            Write-Output $messageTxt
        }
        else {
            $messagetxt = "$azModule could not be located, proceeding with Az Module install."
            Write-warning $messageTxt
            Install-Module Az -Confirm:$false -Force -ErrorAction 'Stop'
        }
    }

    if ((Test-Path $csvLocation) -eq $true) {
        $messageTxt = "Csv location validated $csvLocation"
        Write-Output $messageTxt
    }
    else {
        $messageTxt = "Csv location $csvLocation cannot be found."
        Write-Error $csvLocation
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
catch [system.exception] {
    $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
    Write-Output $messageTxt
    Set-ErrorLevel -1
    exit $ERRORLEVEL
}
#endregion

#region - Connect Azure Subscription
If ($ERRORLEVEL -eq 0) {
    try {
        $messageTxt = "Connecting to Subscription $subscriptionId under $tenantDomain"
        Write-Output $messageTxt
        Add-AzPSAccount -subscriptionId $subscriptionId -tenantDomain $tenantDomain -environment $environment | Out-Null
    }
    catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }    
}
#endregion

#region - Main script
$importVmArray = Import-Csv $csvLocation -ErrorAction 'Stop'
foreach ($importVm in $importVmArray) {
    $vmName                 = $importVm.vmName
    $vmResourceGroupName    = $importVm.vmResourceGroupName
    $enableSecureBoot       = [system.convert]::ToBoolean($importVm.enableSecureBoot)
    [bool]$gen2Vm           = $false

    $messageTxt = "Processing VM $vmName under resource group $vmResourceGroupName with Secure boot $($importVm.enableSecureBoot)"
    Write-Output $messageTxt

    If ($ERRORLEVEL -eq 0) {
        try {
            #region - Current VM Configuration
            $messageTxt = "Mapping existing configuration for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
    
            $currentVmParam = @{
                ResourceGroupName = $vmResourceGroupName
                Name              = $vmName
                ErrorAction       = 'Stop'
            }
            $currentVm = Get-AzVM @currentVmParam
    
            $CurrentVMConfig = @{
                osdisk          = $currentvm.StorageProfile.OsDisk
                vmsize          = $currentvm.HardwareProfile.VmSize
                location        = $currentVm.Location
            }
            
            $osDiskParam = @{
                ResourceGroupName = $currentVm.ResourceGroupName
                Name              = $CurrentVMConfig.osdisk.Name
                ErrorAction       = 'Stop'
            }
            $currentOsDisk = Get-AzDisk @osDiskParam
    
            $currentOsDiskConfig = @{
                sku         = $currentOsDisk.sku.Name
                diskSize    = $currentOsDisk.DiskSizeGB
                HyperVGen   = $currentOsDisk.HyperVGeneration
                osType      = $currentOsDisk.OsType
                encryption  = $currentOsDisk.Encryption
            }
    
            if ($currentOsDiskConfig.HyperVGen -eq "V2") {
                $messageTxt = "VM $vmName under resource group $vmResourceGroupName is running as Gen2. MBR2GPT conversion will be skipped."
                Write-Output $messageTxt
                [bool]$gen2Vm = $true
            }
            if ($currentOsDiskConfig.osType -eq "Linux") {
                $messageTxt ="OS Type of Source VM is $($currentOsDiskConfig.osType)."
                Write-Output $messageTxt
            }
            #endregion
    
            #region - Validate SKU Support
            $messageTxt = "Validating VM SKU $($CurrentVMConfig.vmsize) for $vmname is supported for Trusted launch"
            Write-Output $messageTxt
    
            $gen2Support = $null
            $tlvmSupport = $null
    
            $skuDetail = Get-AzComputeResourceSku -Location $($CurrentVMConfig.location) -ErrorAction 'Stop' | `
                            Where-Object {$psitem.Name -eq $($CurrentVMConfig.vmsize)}
    
            $gen2Support =  $skuDetail | Select-Object -Property Capabilities -ExpandProperty Capabilities | Where-Object {$psitem.Name -eq "HyperVGenerations"}
            $tlvmSupport =  $skuDetail | Select-Object -Property Capabilities -ExpandProperty Capabilities | Where-Object {$psitem.Name -eq "TrustedLaunchDisabled"}
    
            if (($gen2Support.value.Split(",")[-1] -eq "V2") -and !($tlvmSupport)) {
                $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) supported for TLVM. Proceeding to create TLVM."
                Write-Output $messageTxt
            } else {
                $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) not supported for Trusted launch. Update VM Size to Trusted launch Supported SKU. For more details, https://aka.ms/TrustedLaunch"
                Write-Error $messageTxt
                Set-ErrorLevel -1
                exit $ERRORLEVEL
            }
            #endregion
        } catch [System.Exception] {
            $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
            Write-Output $messageTxt
            Set-ErrorLevel -1
            exit $ERRORLEVEL
        }
    }

    if ($ERRORLEVEL -eq 0) {
        try {
            #region - Upgrade VM to Trusted launch
            if ($gen2Vm -eq $false) {
                $messageTxt = "Executing MBR to GPT conversion on $vmname"
                Write-Output $messageTxt
    
                if ($currentOsDiskConfig.osType -eq "Linux") {
                    $messageTxt = "Linux OS type is currently not supported in preview."
                    Write-Error $messageTxt
                    Set-ErrorLevel -1
                    exit $ERRORLEVEL
                } else {
                    $commandId = "RunPowerShellScript"
                    $scriptString = "MBR2GPT /convert /allowFullOS"
                }
    
                $paramInvokeAzVMRunCommand = @{
                    ResourceGroupName = $vmResourceGroupName
                    VMName            = $vmName
                    CommandId         = $commandId
                    ScriptString      = $scriptString
                    ErrorAction       = 'Stop'
                }
                Invoke-AzVMRunCommand @paramInvokeAzVMRunCommand    
            }
    
            $messageTxt = "De-allocating $vmname"
            Write-Output $messageTxt
    
            $paramStopAzVm = @{
                ResourceGroupName   = $vmResourceGroupName
                Name                = $vmName
                Force               = $true
                Confirm             = $false
                ErrorAction         = 'Stop'
            }
            Stop-AzVm @paramStopAzVm | Out-Null
    
            $messageTxt = "Updating security type for $vmname to Trusted launch"
            Write-Output $messageTxt
    
            $paramUpdateAzVm = @{
                ResourceGroupName   = $vmResourceGroupName
                VM                  = $currentVm
                SecurityType        = 'TrustedLaunch'
                EnableVtpm          = $true
                ErrorAction         = 'Stop'
            }
            if ($enableSecureBoot -eq $true) {
                $paramUpdateAzVm.Add('EnableSecureBoot', $true)
            } else {$paramUpdateAzVm.Add('EnableSecureBoot', $false)}
            Update-AzVM @paramUpdateAzVm | Out-Null
    
            $messageTxt = "Starting $vmname"
            Write-Output $messageTxt
    
            $paramStartAzVm = @{
                ResourceGroupName   = $vmResourceGroupName
                Name                = $vmName
                ErrorAction         = 'Stop'
            }
            Start-AzVM @paramStartAzVm | Out-Null
            #endregion    
        } catch [System.Exception] {
            $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
            Write-Output $messageTxt
            Set-ErrorLevel -1
            exit $ERRORLEVEL
        }
    }
}
#endregion