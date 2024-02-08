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
Subscription ID for Gen1 VM.

.PARAMETER tenantDomain
Primary AAD Domain Name for authentication. (For example, contoso.onmicrosoft.com)

.PARAMETER csvLocation
Local file path location of csv containing vmName, vmResourceGroupName, enableSecureBoot details.

.PARAMETER vmName
(Csv input parameter) Resource Name of Gen1 VM to be upgraded

.PARAMETER vmResourceGroupName
(Csv input parameter) Resource Group for Gen1 VM.

.PARAMETER enableSecureBoot
(Csv input parameter) If target Trusted Launch VM should be deployed with Secure Boot enabled (TRUE) or disabled (FALSE). This option should be disabled if VM is hosting custom or unsigned boot drivers which cannot be attested.

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
            Tenant         = $tenantDomain
            ErrorAction    = 'Stop'
        }
        if ($environment) {
            $paramConnectAzAccount.Add('Environment', $environment)
        }
        Connect-AzAccount @paramConnectAzAccount
		return $true
		#endregion
	} catch [system.exception] {
		$messageTxt = "Error in Enable-AzAccount() `n$($psitem.Exception.Message)"
        Write-Error $messageTxt
        Set-ErrorLevel -1
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

    $azPsModule = @(@{
        ModuleName = 'Az.Accounts'
        Version    = [version]"2.8.0"
    },
    @{
        ModuleName = 'Az.Compute'
        Version    = [version]"6.0.0"
    })

    foreach ($azModule in $azPsModule) {
        $module = Get-Module -ListAvailable -Name $azModule.ModuleName

        # Check if the module is available
        if ($module) {
            # Check if the module version is greater than or equal to the minimum version
            if ($module.Version -ge $azModule.Version) {
                $messagetxt = "Module $($azModule.ModuleName) with minimum version $($azModule.Version) is available."
                Write-Output $messageTxt
            } else {
                $messagetxt = "Module $($azModule.ModuleName)  is available, but its version is lower than the minimum version $($azModule.Version). Upgrading module on local machine."
                Write-warning $messageTxt
                Update-Module $($azModule.ModuleName) -ErrorAction 'Stop' -Confirm:$false -Force
            }
        } else {
            $messagetxt = "Module $($azModule.ModuleName) is not available, proceeding with Az Module install."
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
    if ($importVm.enableSecureBoot) {
        $enableSecureBoot       = [system.convert]::ToBoolean($importVm.enableSecureBoot)
    } else {$enableSecureBoot = $true}
    [bool]$gen2Vm           = $false
    [bool]$tlVm             = $false

    $messageTxt = "Processing VM $vmName under resource group $vmResourceGroupName with Secure boot $($importVm.enableSecureBoot)"
    Write-Output $messageTxt

    If ($ERRORLEVEL -eq 0) {
        try {
            #region - Current VM Configuration
            $messageTxt = "Mapping existing configuration for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
    
            $paramGetAzVm = @{
                ResourceGroupName = $vmResourceGroupName
                Name              = $vmName
                ErrorAction       = 'Stop'
            }
            $currentVm = Get-AzVM @paramGetAzVm
    
            $CurrentVMConfig = @{
                osdisk          = $currentvm.StorageProfile.OsDisk
                vmsize          = $currentvm.HardwareProfile.VmSize
                location        = $currentVm.Location
                securityType    = $currentVm.SecurityProfile.SecurityType
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
                if ($CurrentVMConfig.securityType) {
                    $messagetxt = "VM $vmName under resource group $vmResourceGroupName is already Trusted launch, no further action required."
                    Write-Output $messagetxt
                    [bool]$tlVm = $true
                    [bool]$gen2Vm = $true
                } else {
                    $messageTxt = "VM $vmName under resource group $vmResourceGroupName is running as Gen2. MBR2GPT conversion will be skipped."
                    Write-Output $messageTxt
                    [bool]$gen2Vm = $true
                }
            }
            if ($currentOsDiskConfig.osType -eq "Linux") {
                $paramGetAzVm = @{
                    ResourceGroupName = $vmResourceGroupName
                    Name              = $vmName
                    Status            = $true
                    ErrorAction       = 'Stop'
                }
                $currentOs = Get-AzVM @paramGetAzVm
                $messageTxt ="OS Type of Source VM is $($currentOsDiskConfig.osType) and OS Name is $($currentOs.OsName)."
                Write-Output $messageTxt
            }
            #endregion
    
            #region - Validate SKU Support
            If ($gen2Vm -eq $false) {
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
            #region - MBR to GPT conversion
            if ($gen2Vm -eq $false) {
                if ($currentOsDiskConfig.osType -eq "Linux") {
                    $messageTxt = "Executing grub installation and MBR to GPT conversion on $vmname"
                    Write-Output $messageTxt
                    $commandId = "RunShellScript"
                    switch ($currentOs.OsName) {
                        "Ubuntu" {
                            $scriptString = "gdisk /dev/sda \
                                            partprobe /dev/sda \
                                            grub-install /dev/sda"
                        }
                        default {
                            $scriptString = "gdisk /dev/sda \
                                            partprobe /dev/sda \
                                            grub2-install /dev/sda"
                        }
                    }
                } else {
                    $messageTxt = "Executing MBR to GPT conversion on $vmname"
                    Write-Output $messageTxt
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
                $mbrToGpt = Invoke-AzVMRunCommand @paramInvokeAzVMRunCommand
                Write-Output $mbrToGpt

                # if ($currentOsDiskConfig.osType -ne "Linux") {
                #     if ($mbrToGpt.ToString().Contains("Conversion completed successfully")) {
                #         $messagetxt = "MBR to GPT conversion for Windows $vmname completed successfully."
                #         Write-Output $messagetxt
                #     } else {
                #         $messagetxt = "MBR to GPT conversion for Windows $vmname failed. Terminating script execution."
                #         # Write-Error $messagetxt
                #         # Set-ErrorLevel -1
                #     }
                # }
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
            if ($tlvm -eq $false) {
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
            }
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