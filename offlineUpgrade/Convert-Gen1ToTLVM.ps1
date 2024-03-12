<#
.SYNOPSIS
Convert Azure VM from Gen1 to Trusted Launch Configuration with OS State preserved.    

.DESCRIPTION
    PREREQUISITES:
        1. Windows 10/11 Virtual Machine in same geography as source VM.
        2. MBR2GPT Utility (In-Built with Windows 10/11)
        3. Az.Compute (5.1.1), Az.Accounts PowerShell Module
        4. Current Gen 1 VM is running.
        5. VM Contributor rights on resource group.
        6. For Linux VMs, MBR to GPT disk conversion needs to be executed locally using gdisk.

    STEPS:
        1. Detect current OS version running in VM.
        2. Check current VM SKU and it is compatible with Gen 2.
        3. De-allocate current VM and Download OS Disk VHD.
        4. Mount VHD (Windows Only)
        5. Execute MBR2GPT utility - Look for errors if any. (Windows Only)
        6. Create new Gen 2 Disk in same RG.
        7. Upload converted VHD using AZCOPY
        9. Detach data disks.
        10. Spin up new VM with new Gen 2 Disk and existing data disks.
        11. Validate health of domain joined Windows VMs.

    POST-CONVERSION STEPS:
        1. Re-install or restore VM extensions on Gen2 VM.
        2. Enable Monitoring Diagnostics settings on Gen2 VM.
        3. Enable Backup, Monitoring, DR for Gen2 VM.
    
    POTENTIAL CHALLENGES:
        1. Domain joined machines might need to run Reset-ComputerMachinePassword.
        2. Intermittent Paging file error with Windows 2012.

.PARAMETER subscriptionId
Subscription ID for Gen1 VM & target Gen2 VM.

.PARAMETER tenantDomain
Primary AAD Domain Name for authentication. (For example, contoso.onmicrosoft.com)

.PARAMETER vmName
Gen1 VM Resource Name.

.PARAMETER vmResourceGroupName
Resource Group for Gen1 VM & target Gen2 VM.

.PARAMETER targetVmName
(Optional) If target Gen2 VM Name should be different from Gen1 VM.

.PARAMETER sameTargetVmName
(Optional) If target Gen2 VM Name should be same as Gen1 VM.
Note: Gen1 VM will be removed to support same resource group and same VM Name scenario.

.PARAMETER targetVmRgName
(Optional) If target Gen2 VM and OS disk should be setup in different resource group than Gen1.
Note: Data disk & NIC associated with Gen1 VM will continue reside in Gen1 VM resource group and will need to be moved outside script.

.PARAMETER disableSecureBoot
(Optional) If target Trusted Launch VM should be deployed with Secure Boot disabled. This option would be needed if VM is hosting custom or unsigned boot drivers which cannot be attested.

.PARAMETER disableTrustedLaunch
(Optional) If target VM should be Gen2-Only and not enable Trusted Launch configuration. This option would be needed if you're using certain features not supported with Trusted Launch at present like ASR.

.PARAMETER workingDirectory
Local directory used to download OS Disk on Windows 10/11 machine where MBR2GPT Utility will be executed.

.PARAMETER downloadAndConvertOnly
(Optional) Download and Convert OS disk only. Script will not upload or deploy converted VM. This can be used to control the stages of script. Script will run end-to-end if both downloadAndConvertOnly and uploadAndDeployOnly parameters are not used.

.PARAMETER uploadAndDeployOnly
(Optional) Upload OS disk and deploy converted VM only. This parameter assumes script has already been executed with downloadAndConvertOnly and required files are in place already. Script will run end-to-end if both downloadAndConvertOnly and uploadAndDeployOnly parameters are not used.

.PARAMETER cleanupGen1Resources
(Optional) Remove Gen1 VM and OS Disk post conversion.

.PARAMETER retainImageReference
(Optional) Use this switch to retain Publisher, Offer and SKU image attributes of Gen1 VM using Azure Compute Gallery

.PARAMETER disableVmEncryption
(Optional) Disable Azure VM encryption at time of execution of script. Encryption will need to be manually re-enabled post deployment. NOTE: This option will not work if any of the VM Disk is configured with Customer-Managed Key encryption.

.PARAMETER enablePremiumDiskTier
(Optional) Change Gen1 OS Disk to Premium SSD for improved download time. Converted disk will be uploaded with original disk tier.

.EXAMPLE
    .\Convert-Gen1ToTLVM.ps1 -subscriptionId <subscriptionId> -tenantDomain <aadTenantDomain> -vmName <gen1VmName> -targetVmName <gen2VmName> -vmResourceGroupName <gen1VmResourceGroup> -workingDirectory "<localPathForOsDiskDownload>"
    
    Convert Gen1 VM to Trusted Launch VM using different VM Name and same resource group.
    
.EXAMPLE
    .\Convert-Gen1ToTLVM.ps1 -subscriptionId <subscriptionId> -tenantDomain <aadTenantDomain> -vmName <gen1VmName> -sameTargetVmName -vmResourceGroupName <gen1VmResourceGroup> -workingDirectory "<localPathForOsDiskDownload>"
    
    Convert Gen1 VM to Trusted Launch VM using the same VM Name and same resource group. Note: Gen1 VM will be removed to support this scenario.

.EXAMPLE
    .\Convert-Gen1ToTLVM.ps1 -subscriptionId <subscriptionId> -tenantDomain <aadTenantDomain> -vmName <gen1VmName> -sameTargetVmName -vmResourceGroupName <gen1VmResourceGroup> -targetVmRgName <gen2VmResourceGroup> -workingDirectory "<localPathForOsDiskDownload>"

    Convert Gen1 VM to Gen2 VM using the same VM Name and different resource group. Note: Data disk & NIC associated with Gen1 VM will continue reside in Gen1 VM resource group and will need to be moved outside script.
    
.EXAMPLE
    .\Convert-Gen1ToTLVM.ps1 -subscriptionId <subscriptionId> -tenantDomain <aadTenantDomain> -vmName <gen1VmName> -targetVmName <gen2VmName> -vmResourceGroupName <gen1VmResourceGroup> -workingDirectory "<localPathForOsDiskDownload>" -cleanupGen1Resources
    
    Convert Gen1 VM to Trusted Launch VM using different VM Name and same resource group. Clean-up Gen1 VM resources post-conversion

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-machines/generation-2

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.compute/new-azvm?view=azps-9.1.0
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]

param (
    [Parameter(Mandatory = $true, HelpMessage = "Target Azure Subscription Id")]
    [string][ValidateNotNullOrEmpty()]$subscriptionId,
    [Parameter(Mandatory = $true, HelpMessage = "Azure Tenant domain if conversion executed in Azure")]
    [string][ValidateNotNullOrEmpty()]$tenantDomain,
    [Parameter(Mandatory=$false, HelpMessage = "The cloud environment where the VM exists.")]
    [ValidateSet("AzureCloud","AzureChinaCloud","AzureUSGovernment")]
    [string]$environment='AzureCloud',
    [Parameter(Mandatory = $true, HelpMessage = "Name of source VM")]
    [string][ValidateNotNullOrEmpty()]$vmName,
    [Parameter(Mandatory = $true, HelpMessage = "Source VM resource group if conversion executed in Azure")]
    [string][ValidateNotNullOrEmpty()]$vmResourceGroupName,
    [Parameter(Mandatory = $false, HelpMessage = "Name of Target Gen2 VM")]
    [string][ValidateNotNullOrEmpty()]$targetVmName,
    [Parameter(Mandatory = $false, HelpMessage = "Resource Group Name of Target Gen2 VM")]
    [string][ValidateNotNullOrEmpty()]$targetVmRgName,
    [Parameter(Mandatory = $false, HelpMessage = "Use same name for target Gen2 VM.")]
    [switch]$sameTargetVmName,
    [Parameter(Mandatory = $false, HelpMessage = "Disable secure boot for target VM")]
    [switch]$disableSecureBoot,
    [Parameter(Mandatory = $false, HelpMessage = "Use in case target VM should be Gen2-Only and not enable Trusted Launch configuration")]
    [switch]$disableTrustedLaunch,
    [Parameter(Mandatory = $true, HelpMessage = "Working directory for script on local machine for conversion")]
    [string][ValidateNotNullOrEmpty()]$workingDirectory,
    [Parameter(Mandatory = $false, HelpMessage = "Use this switch to execute download and conversion of OS Disk only. Upload and VM deployment will not be executed.")]
    [switch]$downloadAndConvertOnly,
    [Parameter(Mandatory = $false, HelpMessage = "Use this switch to execute Upload OS Disk and VM deployment only. This parameter assumes OS Disk and required files are already in-place. Ensure to execute script with downloadAndConvertOnly first.")]
    [switch]$uploadAndDeployOnly,
    [Parameter(Mandatory = $false, HelpMessage = "Gen1 VM and OS Disk which has been converted will be removed.")]
    [switch]$cleanupGen1Resources,
    [Parameter(Mandatory = $false, HelpMessage = "Use this switch if retaining image reference attributes: Publisher, Offer, SKU is mandatory.")]
    [switch]$retainImageReference,
    [Parameter(Mandatory = $false, HelpMessage = "Use this switch to disable Azure VM encryption during conversion. Encryption will be re-enabled post conversion.")]
    [switch]$disableVmEncryption,
    [Parameter(Mandatory = $false, HelpMessage = "Use this switch to convert Gen1 VM OS Disk to Premium SSD for faster download time. Disk tier will be reverted to original post conversion.")]
    [switch]$enablePremiumDiskTier
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

function Write-InitLog {
    param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$logDirectory
	)
    try {
        $logStamp = (Get-Date -Format yy.MM.dd-HH.mm.ss)
        $script:logFile = "$logDirectory\Gen1-TLVM-Migration-" + $logStamp + '.log'
    } catch [system.exception] {
        $messageTxt = "Error Exception Occurred `nWrite-InitLog()  `n$($psitem.Exception.Message)"
        Write-Output $messageTxt
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}

function Write-LogEntry {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$logMessage,
        [Parameter(Mandatory = $false)]
        [int]$logSeverity = 1,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$logComponent
    )

    try {
        if (([system.math]::Round((Get-Item $logFile -ErrorAction SilentlyContinue).Length / 1MB, 2)) -gt 10) {
            Write-InitLog
        }
        $time = Get-Date -Format 'HH:mm:ss.ffffff'
        $date = Get-Date -Format 'MM-dd-yyyy'
        $message = "<![LOG[$logMessage" + "]LOG]!><time=`"$time`" date=`"$date`" component=`"$logComponent`" context=`"`" type=`"$logSeverity`" thread=`"`" file=`"`">"
        $paramOutFile = @{
            Append    = $true
            Encoding  = 'UTF8'
            FilePath  = $logFile
            NoClobber = $true
        }
        $message | Out-File @paramOutFile
    } catch [system.exception] {
        $messageTxt = "Error Exception Occurred `nWrite-LogEntry()  `n$($psitem.Exception.Message)"
        Write-Output $messageTxt
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Validate Pre-Requisites
try {
    Set-Errorlevel 0 | Out-Null
    Get-Errorlevel | Out-Null

    if ((Test-Path $workingDirectory) -eq $true) {
        $messageTxt = "Working Directory Already Setup $workingDirectory"
        Write-Output $messageTxt
    }
    else {
        $messageTxt = "Setting up working dir $workingDirectory"
        Write-Output $messageTxt
        New-Item -ItemType Directory -Path (Split-Path $workingDirectory -Parent) -Name (Split-Path $workingDirectory -Leaf) -ErrorAction 'Stop' | Out-Null
    }

    if ((Test-Path "$workingDirectory\$vmName") -eq $true) {
        $messageTxt = "Log Directory Already Setup $workingDirectory\$vmName"
        Write-Output $messageTxt
    } else {
        $messageTxt = "Setting up logging dir $workingDirectory\$vmName"
        Write-Output $messageTxt
        New-Item -ItemType Directory -Path $workingDirectory -Name $vmName -ErrorAction 'Stop' | Out-Null
    }
    
    $logDirectory = "$workingDirectory\$vmName\"
    Write-InitLog -logDirectory $logDirectory

    $messageTxt = "Script Version: 1.0.19072023"
    Write-Output $messageTxt
    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
    $messageTxt = $null

    foreach ($key in $MyInvocation.BoundParameters.Keys) {
        $value = (Get-Variable $key).Value
        $messageTxt += [system.string]::concat("Value for parameter $key", " : $value`n")
    }
    Write-Output $messageTxt
    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"

    $azPsModule = @(
        'Az.Accounts',
        'Az.Compute',
        'Az.Network',
        'Az.Storage'
    )

    foreach ($azModule in $azPsModule) {
        If ((Get-Module $azModule -listavailable).count -gt 0) {
            $messageTxt = "Located $azModule on local machine."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
        }
        else {
            $messagetxt = "$azModule could not be located, proceeding with Az Module install."
            Write-warning $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Setup-PreRequisites"
            Install-Module Az -Confirm:$false -Force
        }
    }

    If ((Test-Path "$env:SystemRoot\System32\MBR2GPT.exe") -eq $true) {
        $messageTxt = "Located MBR2GPT Utility under $($env:SystemRoot)\System32."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
    }
    else {
        $messageTxt = "Unable to locate MBR2GPT.exe on local system under $($env:SystemRoot)\System32."
        Write-Error $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Setup-PreRequisites"
        Set-ErrorLevel -1
    }

    If ((Test-Path "$workingDirectory\azCopy.zip") -eq $true) {
        $messageTxt = "azCopy zip already downloaded"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
    } else {
        $messageTxt = "Downloading AzCopy"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"

        Start-BitsTransfer https://aka.ms/downloadazcopy-v10-windows -Destination "$workingDirectory\azCopy.zip" -Priority High
    }

    if ((Test-Path "$workingDirectory\azCopy.zip") -eq $true) {
        If ((Test-Path "$workingDirectory\azCopy\") -eq $true) {
            $messageTxt = "azCopy already setup"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
        } else {
            $messageTxt = "Unzipping AzCopy"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
            Expand-Archive -Path $workingDirectory\azCopy.zip -DestinationPath $workingDirectory\azCopy\ -ErrorAction 'Stop' -Force
        }
        $azCopyDir = (Get-ChildItem -Path $workingDirectory\azCopy\ | Where-Object {$psitem.Name -like "azcopy_windows*"}).Name
        $azCopyDir = "$workingDirectory\azCopy\$azCopyDir\"
        $env:AZCOPY_LOG_LOCATION = $logDirectory
        
        $messageTxt = "Setting up location of azcopy to $azCopyDir"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
    }
    else {
        $messageTxt = "Error in Downloading AZCOPY to $workingDirectory\azCopy.zip"
        Write-Error $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Setup-PreRequisites"
        Set-ErrorLevel -1
    }

    if ($downloadAndConvertOnly) {
        $messageTxt = "Executing script in Download & Convert Only mode. Upload & VM Deployment will not be executed."
        Write-Warning $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
    } elseif ($uploadAndDeployOnly) {
        $messageTxt = "Executing script in Upload & VM deployment Only mode. Assumption is Download & conversion already complete."
        Write-Warning $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Setup-PreRequisites"
    } else {
        $messageTxt = "Staged script execution not selected. Executing end-to-end script."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
    }
}
catch [system.exception] {
    $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
    Write-Output $messageTxt
    Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Setup-PreRequisites"
    Set-ErrorLevel -1
    exit $ERRORLEVEL
}
#endregion

#region - Connect Azure Subscription
If ($ERRORLEVEL -eq 0) {
    try {
        $messageTxt = "Connecting to Subscription $subscriptionId in environment $environment under $tenantDomain"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Connect-AzSubscription"
        Add-AzPSAccount -subscriptionId $subscriptionId -tenantDomain $tenantDomain -environment $environment | Out-Null
    }
    catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Connect-AzSubscription"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Current VM Configuration
If ($ERRORLEVEL -eq 0) {
    try {
        $messageTxt = "Mapping existing configuration for $vmName under $vmResourceGroupName"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
    
        $currentVmParam = @{
            ResourceGroupName = $vmResourceGroupName
            Name              = $vmName
            ErrorAction       = 'Stop'
        }
        $currentVm = Get-AzVM @currentVmParam
    
        $CurrentVMConfig = @{
            osdisk          = $currentvm.StorageProfile.OsDisk
            vmsize          = $currentvm.HardwareProfile.VmSize
            image           = $currentvm.StorageProfile.ImageReference
            dataDisk        = $currentVm.StorageProfile.DataDisks
            location        = $currentVm.Location
            nicCardList     = $currentVm.NetworkProfile.NetworkInterfaces.Id
            bootDiagnostic  = $currentVm.DiagnosticsProfile.BootDiagnostics
            licenseType     = $currentVm.LicenseType
        }

        if ($currentvm.Zones.Count -gt 0) {
            $messageTxt = "Availability zone detected for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            $CurrentVMConfig.Add('zone', $currentVm.Zones[0])
        } else {
            $messageTxt = "No availability zone detected for $vmName under $vmResourceGroupName"
            Write-Warning $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Get-AzVM"
        }

        If ($currentVm.AvailabilitySetReference.Id) {
            $messageTxt = "Availability set $($currentVm.AvailabilitySetReference.Id.split('/')[-1]) configured for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            $CurrentVMConfig.Add('avSetId', $currentVm.AvailabilitySetReference.Id)
        } else {
            $messageTxt = "No availability set configured for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
        }

        if (($currentVm.Extensions | Where-Object {$psitem.VirtualMachineExtensionType -eq "SQLIaaSAgent"}).Count -gt 0) {
            $messageTxt = "SQL Extension detected for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            $CurrentVMConfig.Add('sqlVm', $true)

            $messageTxt = "Capturing resource tags for SQL VM"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            $sqlTags = (Get-AzSQLVM -ResourceGroupName $vmResourceGroupName -Name $vmName -ErrorAction SilentlyContinue).Tags
        }

        if ($currentVm.AdditionalCapabilities.UltraSSDEnabled -eq $true) {
            $messageTxt = "Ultra Disk Compatibility detected for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            $CurrentVMConfig.Add('ultraSSD', $true)
        }

        if ($currentVm.AdditionalCapabilities.HibernationEnabled -eq $true) {
            $messageTxt = "Hibernation enabled for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            $CurrentVMConfig.Add('hibernationEnabled', $true)
        }

        If ($currentVm.ProximityPlacementGroup.Id) {
            $messageTxt = "Proximity Placement Group $($currentVm.ProximityPlacementGroup.Id.split('/')[-1]) configured for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            $CurrentVMConfig.Add('proxPlacementGrp', $currentVm.ProximityPlacementGroup.Id)
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
            $messageTxt = "VM $vmName under resource group $vmResourceGroupName is already running as Gen2, no further action required."
            Write-Error $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-AzVM"
            Set-ErrorLevel -1
        } elseif ($currentOsDiskConfig.osType -eq "Linux") {
            $messageTxt ="OS Type of Source VM is $($currentOsDiskConfig.osType). Ensure disk conversion is completed locally on VM using gdisk before proceeding."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Get-AzVM"
            $title    = 'Confirm'
            $question = 'Continue script execution?'
            $choices  = '&Yes', '&No'
            $decision = $Host.UI.PromptForChoice($title, $question, $choices, -1)
            if ($decision -eq 1) {
                $messageTxt = "User confirmed Linux disk is not yet converted. Terminating Script."
                Write-Error $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-AzVM"
                Set-ErrorLevel -1
            }
        } else {
            $messageTxt = "Validating disk space to support $($currentOsDiskConfig.diskSize) GB download"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"

            $parentVolume = (Split-Path $workingDirectory).Split(':\')[0]
            $availableSize = [system.math]::Round((Get-Volume -DriveLetter $parentVolume -ErrorAction 'Stop').SizeRemaining/1GB,2)

            If ($availableSize -lt $currentOsDiskConfig.diskSize) {
                $messageTxt = "Current selected volume will not support download of OS VHD. Please change the working directory location."
                Write-Error $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-AzVM"
                Set-ErrorLevel -1
            }
            else {
                $messageTxt = "Available space in volume validated. Proceeding."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            }
        }
    }
    catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-AzVM"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Validate SKU Support
if ($ERRORLEVEL -eq 0) {
    try {
        $messageTxt = "Validating VM SKU $($CurrentVMConfig.vmsize) for $vmname is supported for Gen 2"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-SkuFeature"

        [bool]$trustedLaunch = $false
        $gen2Support = $null
        $tlvmSupport = $null

        $skuDetail = Get-AzComputeResourceSku -Location $($CurrentVMConfig.location) -ErrorAction 'Stop' | `
                        Where-Object {$psitem.Name -eq $($CurrentVMConfig.vmsize)}

        $gen2Support =  $skuDetail | Select-Object -Property Capabilities -ExpandProperty Capabilities | Where-Object {$psitem.Name -eq "HyperVGenerations"}
        $tlvmSupport =  $skuDetail | Select-Object -Property Capabilities -ExpandProperty Capabilities | Where-Object {$psitem.Name -eq "TrustedLaunchDisabled"}

        if (($gen2Support.value.Split(",")[-1] -eq "V2") -and !($tlvmSupport) -and !($CurrentVMConfig.ultraSSD) -and !($disableTrustedLaunch)) {
            $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) supported for TLVM. Proceeding to create TLVM."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-SkuFeature"
            $trustedLaunch = $true
        } elseif ($gen2Support.value.Split(",")[-1] -eq "V2") {
            $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) supported for Gen 2. Proceeding."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-SkuFeature"
        } else {
            $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) not supported for Gen 2. Update VM Size to Gen2 Supported SKU. For more details, https://learn.microsoft.com/en-us/azure/virtual-machines/generation-2"
            Write-Error $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-SkuFeature"
            Set-ErrorLevel -1
        }
    }
    catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-SkuFeature"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Validate OS Drive Free space
If ($ERRORLEVEL -eq 0 -and $currentOsDiskConfig.osType -ne "Linux" -and !($uploadAndDeployOnly)) {
    try {
        $messageTxt =  "Checking if OS Volume for $vmName has 500MB free disk available."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-FreeDiskSpace"
        $paramInvokeAzVmRunCommand = @{
            ResourceGroupName = $vmResourceGroupName
            VMName = $vmName
            CommandId = 'RunPowerShellScript'
            ScriptString = @"
                `$driveVolume = (Get-CimInstance -Class Win32_OperatingSystem).SystemDirectory.Split(':')[0]
                `$volumeInfo = Get-Volume | Where-Object {`$psitem.DriveLetter -eq `$driveVolume}
                `$availableMb = [system.math]::Round(`$volumeInfo.SizeRemaining/1MB,2)
                `$totalMb = [system.math]::Round(`$volumeInfo.Size/1MB,2)
                if (`$availableMb -gt 500) {Write-Output "Disk Size Available on volume `$driveVolume is `$availableMb MBs out of `$totalMb MBs"}
                else {Write-Output "FALSE"}
"@
            ErrorAction = 'Stop'
        }
        $volumeInfo = (Invoke-AzVMRunCommand @paramInvokeAzVmRunCommand).Value[0].Message

        if ($volumeInfo -eq "FALSE") {
            $messageTxt = "$vmName OS Drive Volume has less than 500MB drive space available. Conversion cannot be executed."
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Validate-FreeDiskSpace"
            Write-Error $messageTxt
            Set-ErrorLevel -1
        } else {
            $messageTxt = $volumeInfo
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-FreeDiskSpace"
            Write-Output $messageTxt
        }
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Validate-FreeDiskSpace"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Export VM Configuration
If ($ERRORLEVEL -eq 0 -and !($uploadAndDeployOnly)) {
    try {
        $azContext = Get-AzContext
        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRMProfileProvider]::Instance.Profile
        $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
        $azureToken = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)

        $messageTxt = "Exporting VM configurtion for $vmName under resource group $vmResourceGroupName"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Export-Gen1VMConfig"

        switch ($environment) {
            "AzureUSGovernment" {
                [string]$managementUrl = "management.usgovcloudapi.net"
            }
            "AzureChinaCloud" {
                [string]$managementUrl = "management.chinacloudapi.cn"
            }
            default {
                [string]$managementUrl = "management.azure.com"
            }
        }

        $apiUrl = "https://$($managementUrl)/subscriptions/$($subscriptionID)/resourceGroups/$($vmResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$($vmname)?`$expand=userData&api-version=2022-11-01"

        $paramInvokeWebRequest = @{
            Uri                = $apiUrl
            Method             = "GET"
            Headers            = @{ Authorization = "Bearer $($azureToken.AccessToken)" }
            UseBasicParsing    = $true
            ErrorAction        = 'Stop'
        }
        $response = (Invoke-WebRequest @paramInvokeWebRequest).Content
        $jsonFileName = [system.string]::concat($logDirectory,"\ConfigExport-",$vmName,"-",(Get-Date -Format MM.dd-HH.mm),".json")

        $messageTxt = "Exporting VM configurtion to $jsonfileName"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Export-Gen1VMConfig"

        $response | Out-File $jsonFileName
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Export-Gen1VMConfig"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Disable VM Encryption
if ($ERRORLEVEL -eq 0 -and $currentOsDiskConfig.osType -ne "Linux" -and !($uploadAndDeployOnly) -and $disableVmEncryption) {
    try {
        $messageTxt = "Disabling VM encryption for $vmName under resource group $vmResourceGroupName"
        Write-Warning $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Disable-AzVmEncryption"

        $paramDisableAzVMEncryption = @{
            VMName = $vmName
            ResourceGroupName = $vmResourceGroupName
            VolumeType = 'OS'
            Force = $true
            ErrorAction = 'SilentlyContinue'
        }
        Disable-AzVMDiskEncryption @paramDisableAzVMEncryption | Out-Null
    } catch [system.exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Disable-AzVmEncryption"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - De-Allocate VM and download OS Disk
if ($ERRORLEVEL -eq 0 -and !($uploadAndDeployOnly)) {
    try {
        $messageTxt = "De-Allocating VM $vmName under resource group $vmResourceGroupName"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"

        Stop-AzVM -ResourceGroupName $vmResourceGroupName -Name $vmName -Force -ErrorAction 'Stop' | Out-Null

        if ($enablePremiumDiskTier -and $currentOsDiskConfig.sku -ne 'Premium_LRS') {
            $messageTxt = "Changing $($CurrentVMConfig.osdisk.Name) under resource group $vmResourceGroupName to Premium SSD for faster download time."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"

            $currentOsDisk.Sku = [Microsoft.Azure.Management.Compute.Models.DiskSku]::new("Premium_LRS")
            Update-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -Disk $currentOsDisk -ErrorAction 'SilentlyContinue' | Out-Null
        }

        $messageTxt = "Generating Download URL valid for 12 hours."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"
        $downloadDiskSas = (Grant-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -Access 'Read' -DurationInSecond 45000).AccessSAS

        $messageTxt = "Downloading OS Disk using SAS URL generated to $logDirectory\$vmName-osdisk.vhd"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"
        Set-Location $azCopyDir
        .\azcopy copy $downloadDiskSas "$logDirectory\$vmName-osdisk.vhd" --check-md5 "NoCheck"
        Set-Location $workingDirectory
        # Start-BitsTransfer $downloadDiskSas -Destination "$workingDirectory\$vmName-osdisk.vhd" -Priority 'High' -ErrorAction 'Stop'

        if ($enablePremiumDiskTier -and $currentOsDiskConfig.sku -ne 'Premium_LRS') {
            $messageTxt = "Reverting $($CurrentVMConfig.osdisk.Name) under resource group $vmResourceGroupName to $($currentOsDiskConfig.sku)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"

            $currentOsDisk.Sku = [Microsoft.Azure.Management.Compute.Models.DiskSku]::new($($currentOsDiskConfig.sku))
            Update-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -Disk $currentOsDisk -ErrorAction 'SilentlyContinue' | Out-Null
        }

        If ((Test-Path "$logDirectory\$vmName-osdisk.vhd") -eq $true) {
            $messageTxt = "Revoking download URL"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"
            Revoke-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -ErrorAction 'Stop' | Out-Null
            $messageTxt = "VHD Download Successful. Proceeding."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"
        }
        else {
            $messageTxt = "Revoking download URL"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"
            Revoke-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -ErrorAction 'Stop' | Out-Null
            $messageTxt = "Starting VM $vmName under resource group $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"
            Start-AzVM -ResourceGroupName $vmResourceGroupName -Name $vmName -ErrorAction 'Stop' | Out-Null
            $messageTxt = "Error downloading OS VHD."
            Write-Error $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Download-AzDisk"
            Set-ErrorLevel -1
        }
    }
    catch [system.exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Download-AzDisk"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Mount VHD
if ($ERRORLEVEL -eq 0 -and $currentOsDiskConfig.osType -ne "Linux" -and !($uploadAndDeployOnly)) {
    try {
        $messageTxt = "Mounting VHD $logDirectory\$vmName-osdisk.vhd"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Mount-VHD"
        $mountDisk = Mount-DiskImage -ImagePath "$logDirectory\$vmName-osdisk.vhd" -ErrorAction 'Stop'
        
        $messageTxt = "VHD Mounted on $($mountDisk.Number). Validating if disk is already GPT."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Mount-VHD"

        if ((Get-Disk -Number $($mountDisk.Number)).PartitionStyle -eq 'MBR') {
            $messageTxt = "VHD Mounted on Disk $($mountDisk.Number) is using MBR partition. Proceeding with GPT conversion"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Mount-VHD"
        }
        else {
            $messageTxt = "Dismounting VHD"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Mount-VHD"
            Dismount-DiskImage -ImagePath "$logDirectory\$vmName-osdisk.vhd" -ErrorAction 'Stop' | Out-Null
            $messageTxt = "VHD Mounted on Disk $($mountDisk.Number) is not using MBR partition. Exiting"
            Write-Error $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Mount-VHD"
            Set-ErrorLevel -1
        }
    }
    catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Mount-VHD"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Converting MBR to GPT
if ($ERRORLEVEL -eq 0 -and $currentOsDiskConfig.osType -ne "Linux" -and !($uploadAndDeployOnly)) {
    try {
        $messageTxt = "Switching to System32 Directory"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR2GPT"
        Set-Location -Path "$env:SystemRoot\System32\"

        $messageTxt = "Executing MBR2GPT for disk number $($mountDisk.Number)"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR2GPT"
        $mbr2gpt = .\MBR2GPT.exe /disk:$($mountDisk.Number) /convert /allowFullOS /logs:$logDirectory

        Write-Output $mbr2gpt

        $messageTxt = "Validating if disk has been successfully converted to GPT"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR2GPT"
        if ($mbr2gpt -and (Get-Disk -Number $($mountDisk.Number)).PartitionStyle -eq 'GPT') {
            $messageTxt = "VHD Mounted on Disk $($mountDisk.Number) converted successfully"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR2GPT"
        }
        else {
            $messageTxt = "VHD Mounted on $($mountDisk.Number) is not using GPT partition or error in MBR2GPT execution. Exiting"
            Write-Error $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR2GPT"
            Set-ErrorLevel -1
        }
        $messageTxt = "Dismounting VHD"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR2GPT"
        Dismount-DiskImage -ImagePath "$logDirectory\$vmName-osdisk.vhd" -ErrorAction 'Stop' | Out-Null
        Set-Location -Path $workingDirectory
    }
    catch [System.Exception]{
        Set-Location -Path $workingDirectory
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR2GPT"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Create New Az Disk
if ($ERRORLEVEL -eq 0 -and !($downloadAndConvertOnly)) {
    try {
        
        if ($sameTargetVmName -eq $true) {
            $gen2VMName = $vmName
        } elseif ($targetVmName) {
            $gen2VMName = $targetVmName
        } else {
            $gen2VMName = [system.string]::concat($vmName, '-gen2')
        }

        if ($retainImageReference) {
            $gen2DiskName = [system.string]::concat($gen2VMName,'-temp-os-disk')
        } else {
            $gen2DiskName = [system.string]::concat($gen2VMName,'-os-disk')
        }
        [bool]$useExistingGen2Disk = $false
        $existingGen2Disk = $null

        If ($targetVmRgName) {
            $resourceGroup = $targetVmRgName
            $sourceVmRgName = Get-AzResourceGroup -Name $vmResourceGroupName -ErrorAction 'SilentlyContinue'
            if (!(Get-AzResourceGroup -ResourceGroupName $resourceGroup -ErrorAction 'SilentlyContinue' )) {
                $messageTxt = "Setting up resource group $resourceGroup in location $($CurrentVMConfig.location)"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
                $paramNewAzResourceGroup = @{
                    ResourceGroupName = $resourceGroup
                    Location = $CurrentVMConfig.location
                    ErrorAction = 'Stop'
                }
                If ($sourceVmRgName.Tags.Count -gt 0) {
                    $paramNewAzResourceGroup.Add('Tag', $sourceVmRgName.Tags)
                }
                New-AzResourceGroup @paramNewAzResourceGroup | Out-Null
            }
        }
        else {
            $resourceGroup = $vmResourceGroupName
        }

        $existingGen2Disk = Get-AzDisk -ResourceGroupName $resourcegroup -DiskName $gen2DiskName -ErrorAction 'SilentlyContinue'

        If ($existingGen2Disk){
            $messageTxt = "$gen2DiskName already exists under $resourceGroup."
            Write-Warning $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "New-AzDisk"

            If ($existingGen2Disk.HyperVGeneration -eq 'V2') {
                $messageTxt = "$gen2DiskName already configured with Gen2."
                Write-Warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "New-AzDisk"
                $title    = 'Confirm'
                $question = 'Use same disk for Gen2 VM Creation?'
                $choices  = '&Yes', '&No'
                $decision = $Host.UI.PromptForChoice($title, $question, $choices, -1)
                if ($decision -eq 1) {
                    [bool]$useExistingGen2Disk = $false
                    $title    = 'Confirm'
                    $question = 'Delete existing Gen2 OS Disk with same name?'
                    $choices  = '&Yes', '&No'
                    $decision = $Host.UI.PromptForChoice($title, $question, $choices, -1)
                    if ($decision -eq 1) {
                        $messageTxt = "User confirmed not to delete OS Disk. Terminating Script"
                        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "New-AzDisk"
                        Set-ErrorLevel -1
                        Write-Error $messageTxt
                    } else {
                        $messageTxt = "Removing Gen2 OS Disk with same name"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
                        Remove-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -ErrorAction 'Stop' -Force -Confirm:$false | Out-Null
                    }
                } else {
                    $messageTxt = "User confirmed to use existing Gen2 OS Disk"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
                    [bool]$useExistingGen2Disk = $true
                }
            } else {
                $title    = 'Confirm'
                $question = 'Delete existing Gen1 OS Disk with same name?'
                $choices  = '&Yes', '&No'
                $decision = $Host.UI.PromptForChoice($title, $question, $choices, -1)
                if ($decision -eq 1) {
                    $messageTxt = "User confirmed not to delete OS Disk. Terminating Script"
                    Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "New-AzDisk"
                    Set-ErrorLevel -1
                    Write-Error $messageTxt
                } else {
                    $messageTxt = "Removing Gen1 OS Disk with same name"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
                    Remove-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -ErrorAction 'Stop' -Force -Confirm:$false | Out-Null
                }
            }
        }

        if ($useExistingGen2Disk -eq $false) {
            $messageTxt = "Setting up new disk config"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            $newDiskConfigParam = @{
                Location            = $CurrentVMConfig.location
                OsType              = $CurrentVMConfig.osdisk.OsType
                CreateOption        = 'Upload'
                UploadSizeInBytes   = (Get-Item -Path "$logDirectory\$vmName-osdisk.vhd").Length
                HyperVGeneration    = 'v2'
                EncryptionType      = $currentOsDiskConfig.encryption.Type
                ErrorAction         = 'Stop'
            }
            if ($enablePremiumDiskTier -and $currentOsDiskConfig.sku -ne 'Premium_LRS') {
                $messageTxt = "Setting Disk tier to to Premium SSD for faster upload time."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
                $newDiskConfigParam.Add('SkuName', 'Premium_LRS')
            } else {
                $newDiskConfigParam.Add('SkuName', $currentOsDiskConfig.sku)
            }
            if ($CurrentVMConfig.zone) {
                $newDiskConfigParam.Add('Zone', $CurrentVMConfig.zone)
            }
            If ($currentOsDisk.Tags.Count -gt 0) {
                $newDiskConfigParam.Add('Tag', $currentOsDisk.Tags)
            }
            if ($currentOsDiskConfig.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($currentOsDiskConfig.encryption.DiskEncryptionSetId)) {
                $newDiskConfigParam.Add('DiskEncryptionSetId', $currentOsDiskConfig.encryption.DiskEncryptionSetId)
            }
        
            $gen2diskConfig = New-AzDiskConfig @newDiskConfigParam
            if ($trustedLaunch -eq $true) {
                $messageTxt = "Adding trusted launch disk configuration"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
                Set-AzDiskSecurityProfile -Disk $gen2diskConfig -SecurityType "TrustedLaunch" -ErrorAction 'Stop' | Out-Null
            }

            $messageTxt = "Setting up new disk $gen2DiskName under $resourceGroup"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            $paramNewAzDisk = @{
                ResourceGroupName = $resourceGroup
                DiskName = $gen2DiskName
                Disk = $gen2diskConfig
                ErrorAction = 'Stop'
            }
            $gen2OsDisk = New-AzDisk @paramNewAzDisk
            $gen2OsDisk = Get-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2OsDisk.Name -ErrorAction 'SilentlyContinue'

            while ($gen2OsDisk.DiskState -ne "ReadyToUpload") {
                $messageTxt = "Awaiting Disk State update. DiskState: $($gen2OsDisk.DiskState), ProvisioningState: $($gen2OsDisk.ProvisioningState)"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
                Start-Sleep -Seconds 3
                $gen2OsDisk = Get-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2OsDisk.Name -ErrorAction 'SilentlyContinue'
            }

            $messageTxt = "Generating Upload URL for $gen2DiskName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            $gen2diskSas = (Grant-AzDiskAccess -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -DurationInSecond 86400 -Access 'Write' -ErrorAction 'Stop').AccessSAS

            $messageTxt = "Uploading converted vhd to $gen2DiskName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            Set-Location $azCopyDir
            .\azcopy copy "$logDirectory\$vmName-osdisk.vhd" $gen2diskSas
            Set-Location $workingDirectory
            $messageTxt = "Revoking Upload URL"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            Revoke-AzDiskAccess -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -ErrorAction 'Stop' | Out-Null

            if ($enablePremiumDiskTier -and $currentOsDiskConfig.sku -ne 'Premium_LRS') {
                $messageTxt = "Changing $gen2DiskName under resource group $resourceGroup to $($currentOsDiskConfig.Sku)."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"
                $gen2OsDisk.Sku = [Microsoft.Azure.Management.Compute.Models.DiskSku]::new($($currentOsDiskConfig.Sku))
                Update-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -Disk $gen2OsDisk -ErrorAction 'SilentlyContinue' | Out-Null
            }
        } else {
            $gen2OsDisk = $existingGen2Disk
            $messageTxt = "Using existing Gen2 OS Disk $gen2DiskName for VM Create."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
        }
    }
    catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "New-AzDisk"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Setup Shared Image Gallery
If ($ERRORLEVEL -eq 0 -and $retainImageReference -and !($downloadAndConvertOnly)) {
    try {
        $title    = 'Confirm'
        $question = 'Setup new Compute gallery to retain image reference?'
        $choices  = '&Yes', '&No'
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, -1)
        if ($decision -eq 0) {
            $messageTxt = "User confirmed New compute gallery required."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
            $messageTxt = "Setting up temp Azure Compute Gallery to retain image referen attributes."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
            [string]$tempGalleryName = [system.string]::concat($vmName.Replace('-',''), 'tempacg')

            # Setup Image Gallery
            $messageTxt = "Setting up temp gallery with name $tempgalleryName under resource group $resourceGroup"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
            New-AzGallery -ResourceGroupName $resourceGroup -Name $tempGalleryName -location $CurrentVMConfig.location -ErrorAction 'Stop' | Out-Null
        } else {
            $tempGalleryName = Read-Host -Prompt "Enter name of compute gallery in region $($CurrentVMConfig.location)"
            $tempGalleryRg = Read-Host -Prompt "Enter name of compute gallery $tempGalleryName resource group."

            if (Get-AzGallery -ResourceGroupName $tempGalleryRg -Name $tempGalleryName -ErrorAction SilentlyContinue) {
                $messageTxt = "Using gallery $tempgalleryName under resource group $tempGalleryRg"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
                $resourceGroup = $tempGalleryRg
            } else {
                $messageTxt = "Gallery $tempgalleryName under resource group $tempGalleryRg not found."
                [string]$tempGalleryName = [system.string]::concat($vmName.Replace('-',''), 'tempacg')
                # Setup Image Gallery
                $messageTxt = "Setting up temp gallery with name $tempgalleryName under resource group $resourceGroup"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
                New-AzGallery -ResourceGroupName $resourceGroup -Name $tempGalleryName -location $CurrentVMConfig.location -ErrorAction 'Stop' | Out-Null
            }
        }
        
        [string]$tempGalleryDefinition = [system.string]::concat($vmName.Replace('-',''), 'tempdef')
        [string]$osState = "Specialized"

        # Setup Image Definition
        $messageTxt = "Setting up temp definition with name $tempGalleryDefinition under resource group $resourceGroup"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
        $paramNewAzImageDef = @{
            ResourceGroupName = $resourceGroup
            GalleryName       = $tempGalleryName
            Name              = $tempGalleryDefinition
            Publisher         = $CurrentVMConfig.image.Publisher
            Offer             = $CurrentVMConfig.image.Offer
            Sku               = $CurrentVMConfig.image.Sku
            Location          = $CurrentVMConfig.location
            OSState           = $osState
            OsType            = $currentOsDiskConfig.osType
            HyperVGeneration  = 'V2'
            ErrorAction       = 'Stop'
        }
        if ($trustedLaunch -eq $true) {
            $SecurityType = @{Name='SecurityType';Value='TrustedLaunch'}
            $features = @($SecurityType)
            $paramNewAzImageDef.Add('Feature', $features)
        }
        $tempImageDef = New-AzGalleryImageDefinition @paramNewAzImageDef

        # Setup Image Version
        $messageTxt = "Setting up image version 1.0.0 under image definition $tempGalleryDefinition"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
       
        $tempOsDisk = @{
            Source = @{
                Id = $gen2OsDisk.Id
            }
        }
        if ($currentOsDiskConfig.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($currentOsDiskConfig.encryption.DiskEncryptionSetId)) {
            $tempOsDisk.Add('DiskEncryptionSetId', $currentOsDiskConfig.encryption.DiskEncryptionSetId)
        }

        $paramNewAzImageVer = @{
            ResourceGroupName   = $resourceGroup
            GalleryName         = $tempGalleryName
            GalleryImageDefinitionName  = $tempGalleryDefinition
            Name                = "1.0.0"
            Location            = $CurrentVMConfig.location
            OSDiskImage         = $tempOsDisk
            ErrorAction         = 'Stop'
            StorageAccountType  = $currentOsDiskConfig.sku
            AsJob               = $true
        }
        if ($tempDataDiskArray.Count -gt 0) {
            $paramNewAzImageVer.Add('DataDiskImage', $tempDataDiskArray)
        }
        New-AzGalleryImageVersion @paramNewAzImageVer | Out-Null

        $messageTxt = "Waiting 3 minutes (180 seconds) for Image version provisioning."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
        Start-Sleep -Seconds 180
        do {
            $versionCreateStatus = $null
            $versionCreateStatus = Get-AzGalleryImageVersion -ResourceGroupName $resourceGroup -GalleryName $tempGalleryName -GalleryImageDefinitionName $tempGalleryDefinition -Name "1.0.0" -ExpandReplicationStatus
            $messageTxt = "Current replication status - $($versionCreateStatus.ReplicationStatus.AggregatedState) - $($versionCreateStatus.ReplicationStatus.Summary.Progress)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
            $messageTxt = "Current Provisioning Status - $($versionCreateStatus.ProvisioningState)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
            $messageTxt = "Waiting 60 seconds for Image version provisioning."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
            Start-Sleep -Seconds 60
        } while ($versionCreateStatus.ProvisioningState -eq "Creating")

        $messageTxt = "Clearing temp Gen2 OS Disk $gen2DiskName under resource group $resourceGroup"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzComputeGallery"
        Remove-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -Force -ErrorAction 'Stop' | Out-Null
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "New-AzComputeGallery"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Detach resources from existing VM
if ($ERRORLEVEL -eq 0 -and !($downloadAndConvertOnly)) {
    try {
        [bool]$rollBackRequired = $false
        $messageTxt = "Setting up temporary NIC $vmName-temp-nic in same subnet under resource group $vmResourceGroupName"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"

        If ($CurrentVMConfig.nicCardList.Count -eq 1) {
            $messageTxt = "Single NIC Card attached to $vmName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
            $subnetId = (Get-AzNetworkInterface -ResourceId $CurrentVMConfig.nicCardList).IpConfigurations.Subnet.Id
        }
        else {
            $messageTxt = "Multiple NIC Card attached to $vmName. Taking first NIC Card configuration."
            Write-Warning $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Update-AzVM"
            $subnetId = (Get-AzNetworkInterface -ResourceId $CurrentVMConfig.nicCardList[0]).IpConfigurations.Subnet.Id
        }

        if ($subnetId.Count -gt 1) {
            $messageTxt = "Multiple Subnets detected. Taking first SubnetID."
            Write-Warning $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Update-AzVM"
            $subnetId = $subnetId[0]
        }
        $paramNewAzNic = @{
            Name = [system.string]::concat($vmName, "-temp-nic")
            ResourceGroupName = $vmResourceGroupName
            Location = $CurrentVMConfig.location
            SubnetId = $subnetId
            ErrorAction = 'Stop'
            Force = $true
        }
        if ($currentvm.Tags.count -gt 0) {
            $paramNewAzNic.Add('Tag', $currentVm.Tags)
        }
        $tempNic = New-AzNetworkInterface @paramNewAzNic

        $messageTxt = "Attach temp NIC card as primary"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
        $currentVm = Add-AzVMNetworkInterface -VM $currentVm -Id $tempNic.Id -Primary -DeleteOption 'Delete' -ErrorAction 'Stop' 

        $messageTxt = "Remove existing NIC cards"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
        $currentVm = Remove-AzVMNetworkInterface -VM $currentVm -NetworkInterfaceIDs $CurrentVMConfig.nicCardList -ErrorAction 'Stop'
        
        if ($CurrentVMConfig.dataDisk.Count -gt 0) {
            $messageTxt = "Detaching Data disks from $vmName under resource group $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
            $currentVm = Remove-AzVMDataDisk -VM $currentVm -DataDiskNames $CurrentVMConfig.dataDisk.Name -ErrorAction 'Stop'
        }

        $messageTxt = "Updating VM Configuration for Gen1 $vmName"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
        Update-AzVM -VM $currentVm -ResourceGroupName $vmResourceGroupName -ErrorAction 'Stop' | Out-Null
    }
    catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Update-AzVM"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Cleanup Gen1 VM Resources
if ($ERRORLEVEL -eq 0 -and !($downloadAndConvertOnly)) {
    try {
        [bool]$removeVm = $false
        if ($sameTargetVmName -eq $true -and (!($targetVmRgName) -or $targetVmRgName -eq $vmResourceGroupName)) {
            $messageTxt = "To support same $vmName in resource group $vmResourceGroupName, existing Gen1 VM resources needs to be cleaned up."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Remove-AzVM"
            $removeVm = $true
        }
        
        if ($cleanupGen1Resources -eq $true) {
            $messageTxt = "Cleaning up $vmName in resource group $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Remove-AzVM"
            $removeVm = $true
        }

        If ($removeVm -eq $true) {
            $title    = 'Confirm'
            $question = 'Continue Gen1 VM Deletion?'
            $choices  = '&Yes', '&No'
            $decision = $Host.UI.PromptForChoice($title, $question, $choices, -1)
            if ($decision -eq 1) {
                $messageTxt = "User confirmed not to delete Gen1 VM. Terminating Script"
                Write-Error $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Remove-AzVM"
                Set-ErrorLevel -1
            } else {
                $messageTxt = "User confirmed Gen1 VM deletion. Taking disk snapshot $([system.string]::concat($vmName, "-gen1-os-disk-snapshot")) prior to removal."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Remove-AzVM"
                $paramNewAzSnapshotConfig = @{
                    SourceUri = $currentVm.StorageProfile.OsDisk.ManagedDisk.Id
                    Location = $CurrentVMConfig.location
                    CreateOption = 'Copy'
                    HyperVGeneration = 'V1'
                    EncryptionType = $currentOsDiskConfig.encryption.Type
                    ErrorAction = 'SilentlyContinue'
                }
                If ($currentOsDisk.Tags.Count -gt 0) {
                    $paramNewAzSnapshotConfig.Add('Tag', $currentOsDisk.Tags)
                }
                if ($currentOsDiskConfig.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($currentOsDiskConfig.encryption.DiskEncryptionSetId)) {
                    $paramNewAzSnapshotConfig.Add('DiskEncryptionSetId', $currentOsDiskConfig.encryption.DiskEncryptionSetId)
                }
                $snapshot = New-AzSnapshotConfig @paramNewAzSnapshotConfig
                New-AzSnapshot -SnapshotName $([system.string]::concat($vmName, "-gen1-os-disk-snapshot")) `
                -Snapshot $snapshot -ResourceGroupName $vmResourceGroupName -ErrorAction 'SilentlyContinue' | Out-Null

                $messageTxt = "Snapshot complete. Proceeding with removal."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Remove-AzVM"
                Remove-AzVM -ResourceGroupName $vmResourceGroupName -Name $vmName -Force -ErrorAction 'Stop' | Out-Null
                Remove-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -Force -ErrorAction 'Stop' | Out-Null
            }
        }
    }
    catch [System.Exception]{
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Remove-AzVM"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Setup New VM
if (!($downloadAndConvertOnly)) {
    if ($ERRORLEVEL -eq 0 ) {
        try {
            if ($sameTargetVmName -eq $true) {
                $gen2VMName = $vmName
            }
            elseif ($targetVmName) {
                $gen2VMName = $targetVmName
            }
            else {
                $gen2VMName = [system.string]::concat($vmName, '-gen2')
            }
            $gen2DiskName = [system.string]::concat($gen2VMName,'-os-disk')
    
            If ($targetVmRgName) {
                $resourceGroup = $targetVmRgName
                $messageTxt = "Data disk associated with $vmName will not be moved to new resource group and reside in $vmResourceGroupName"
                Write-Warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "New-AzVM"
            }
            else {
                $resourceGroup = $vmResourceGroupName
            }
    
            $messageTxt = "Setting up new VM $gen2vmName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
            $newAzVmConfigParam = @{
                VMName  = $gen2VMName
                VMSize  = $CurrentVMConfig.vmsize
                ErrorAction = 'Stop'
            }
            if ($CurrentVMConfig.zone) {
                $newAzVmConfigParam.Add('Zone', $CurrentVMConfig.zone)
            }
            elseif ($CurrentVMConfig.avSetId) {
                $newAzVmConfigParam.Add('AvailabilitySetId', $CurrentVMConfig.avSetId)
            }
            else {
                $messageTxt = "Gen1 VM $vmName is not using any high availability configuration using Availability Set or Zone."
                Write-Warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "New-AzVM"
            }
            if ($CurrentVMConfig.ultraSSD -eq $true) {
                $newAzVmConfigParam.Add('EnableUltraSSD', $true)
            }
            if ($CurrentVMConfig.hibernationEnabled -eq $true) {
                $newAzVmConfigParam.Add('HibernationEnabled', $true)
            }
            if ($CurrentVMConfig.proxPlacementGrp) {
                $newAzVmConfigParam.Add('ProximityPlacementGroupId', $CurrentVMConfig.proxPlacementGrp)
            }
            if ($CurrentVMConfig.licenseType) {
                $newAzVmConfigParam.Add('LicenseType', $CurrentVMConfig.licenseType)
            }
            $gen2VM = New-AzVMConfig @newAzVmConfigParam
            If ($CurrentVMConfig.nicCardList.Count -eq 1) {
                $gen2VM = Add-AzVMNetworkInterface -VM $gen2VM -Id $CurrentVMConfig.nicCardList -ErrorAction 'Stop'
            }
            else {
                foreach ($existingNic in $CurrentVMConfig.nicCardList) {
                    $gen2VM = Add-AzVMNetworkInterface -VM $gen2VM -Id $existingNic -ErrorAction 'Stop'
                }
            }
    
            if ($retainImageReference) {
                Write-Output "Setting up new VM $gen2vmName using image $tempGalleryDefinition"
                $gen2VM = Set-AzVMSourceImage -VM $gen2VM -Id $tempImageDef.Id -ErrorAction 'Stop'
    
                $setOsDiskParam = @{
                    VM              = $gen2VM
                    Name            = $gen2DiskName
                    StorageAccountType = $currentOsDiskConfig.sku
                    CreateOption    = 'FromImage'
                    Caching         = 'ReadWrite'
                    ErrorAction     = 'Stop'
                }
                switch ($currentOsDiskConfig.osType) {
                    "Linux" {
                        $setOsDiskParam.Add('Linux', $true)
                    }
                    "Windows" {
                        $setOsDiskParam.Add('Windows', $true)
                    }
                    default {
                        $setOsDiskParam.Add('Windows', $true)
                    }
                }
                $gen2VM = Set-AzVMOSDisk @setOsDiskParam
            } else {
                $messageTxt = "Setting up new VM $gen2vmName using OS disk $gen2DiskName"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
                $gen2Disk = Get-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -ErrorAction 'Stop'
                $setOsDiskParam = @{
                    VM              = $gen2VM
                    Name            = $gen2DiskName
                    CreateOption    = 'Attach'
                    ManagedDiskId   = $gen2disk.Id
                    Caching         = 'ReadWrite'
                    ErrorAction     = 'Stop'
                }
                switch ($currentOsDiskConfig.osType) {
                    "Linux" {
                        $setOsDiskParam.Add('Linux', $true)
                    }
                    "Windows" {
                        $setOsDiskParam.Add('Windows', $true)
                    }
                    default {
                        $setOsDiskParam.Add('Windows', $true)
                    }
                }
                if ($currentOsDiskConfig.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($currentOsDiskConfig.encryption.DiskEncryptionSetId)) {
                    $setOsDiskParam.Add('DiskEncryptionSetId', $currentOsDiskConfig.encryption.DiskEncryptionSetId)
                }
                $gen2VM = Set-AzVMOSDisk @setOsDiskParam
            }
    
            If ($CurrentVMConfig.bootDiagnostic.Enabled -eq $true) {
                If ($CurrentVMConfig.bootDiagnostic.StorageUri) {
                    $bootDiagSaName = $CurrentVMConfig.bootDiagnostic.StorageUri.Replace('https://','').Replace('.blob.core.windows.net','').Replace('/','')
                    $bootDiagSaRg = (Get-AzStorageAccount | Where-Object {$psitem.StorageAccountName -eq $bootDiagSaName}).ResourceGroupName
                    if ($bootDiagSaRg) {
                        $messageTxt = "Setting up Un-Managed Boot Diagnostics for $gen2VMName using storage account $bootDiagSaName under resource group $bootDiagSaRg"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
                        Set-AzVMBootDiagnostic -VM $gen2VM -Enable -ResourceGroupName $bootDiagSaRg -StorageAccountName $bootDiagSaName | Out-Null
                    } else {
                        $messageTxt = "Setting up Managed Boot Diagnostics for $gen2VMName"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
                        Set-AzVMBootDiagnostic -VM $gen2VM -Enable | Out-Null
                    }
                }
                else {
                    $messageTxt = "Setting up Managed Boot Diagnostics for $gen2VMName"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
                    Set-AzVMBootDiagnostic -VM $gen2VM -Enable | Out-Null
                }
            }
            else {
                $message = "Boot diagnostics for Gen1 VM $vmName is disabled. Boot diagnostics will be disabled for Gen2 VM $gen2VMName as well."
                Write-Warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "New-AzVM"
            }
    
            if ($trustedLaunch -eq $true) {
                $messageTxt = "Enabling Trusted Launch settings for VM $gen2VMName"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
                $gen2VM = Set-AzVMSecurityProfile -VM $gen2VM -SecurityType "TrustedLaunch" -ErrorAction 'Stop'
                $paramSetAzVmUefi = @{
                    VM = $gen2VM
                    EnableVtpm = $true
                    ErrorAction = 'Stop'
                }
                if ($disableSecureBoot -eq $true) {
                    $paramSetAzVmUefi.Add('EnableSecureBoot',$false)
                } else {
                    $paramSetAzVmUefi.Add('EnableSecureBoot',$true)
                }
                $gen2VM = Set-AzVMUefi @paramSetAzVmUefi
            }
        }
        catch [system.exception] {
            $messageTxt = "Cleanup converted gen2 OS disk $gen2DiskName under $resourceGroup"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
            Remove-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -ErrorAction 'Stop' -Force -Confirm:$false | Out-Null
            $messageTxt = "Enabling Roll-back flag."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
            [bool]$rollBackRequired = $true
            $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "New-AzVM"
            Set-ErrorLevel -1
        }
    }

    if ($ERRORLEVEL -eq 0 ) {
        foreach ($disk in $CurrentVMConfig.dataDisk) {
            $dataDisk = $null
            $dataDisk = Get-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $disk.Name -ErrorAction 'SilentlyContinue'
            If ($dataDisk.Id) {
                $messageTxt = "Adding $($disk.Name) at LUN $($disk.Lun)"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
                $paramAddAzVmDataDisk = @{
                    VM = $gen2VM
                    Name = $disk.Name
                    CreateOption = 'Attach'
                    LUN = $disk.Lun
                    Caching = $disk.Caching
                    ManagedDiskId = $dataDisk.Id
                    ErrorAction = 'SilentlyContinue'
                }
                if ($dataDisk.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($dataDisk.encryption.DiskEncryptionSetId)) {
                    $paramAddAzVmDataDisk.Add('DiskEncryptionSetId', $dataDisk.encryption.DiskEncryptionSetId)
                }
                $gen2VM = Add-AzVMDataDisk @paramAddAzVmDataDisk
            } else {
                $messageTxt = "$($disk.Name) not found under resource group $vmResourceGroupName"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
            }
        }
    }

    if ($ERRORLEVEL -eq 0) {
        try {
            $messageTxt = "Setting up new Gen2 VM $gen2vmname"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
            $paramNewAzVm = @{
                ResourceGroupName = $resourceGroup
                VM = $gen2VM
                Location = $CurrentVMConfig.location
                ErrorAction = 'Stop'
            }
            if ($currentvm.Tags.count -gt 0) {
                $paramNewAzVm.Add('Tag', $currentVm.Tags)
            }
            New-AzVM @paramNewAzVm | Out-Null
        } catch [System.Exception] {
            $checkConvertedVM = $null
            $checkConvertedVM = Get-AzVM -VMName $gen2VMName -ResourceGroupName $resourceGroup -ErrorAction 'SilentlyContinue'
            if ($checkConvertedVM) {
                $messageTxt = "Converted VM $gen2vmname is available under $resourceGroup. No roll-back required."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
            } else {
                $messageTxt = "Cleanup converted gen2 OS disk $gen2DiskName under $resourceGroup"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
                Remove-AzDisk -ResourceGroupName $resourceGroup -DiskName $gen2DiskName -ErrorAction 'Stop' -Force -Confirm:$false | Out-Null
                $messageTxt = "Enabling Roll-back flag."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzVM"
                [bool]$rollBackRequired = $true
            }
            $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "New-AzVM"
            Set-ErrorLevel -1
        }
    }
}
#endregion

#region - Check if machine is domain joined
if ($Errorlevel -eq 0 -and $currentOsDiskConfig.osType -eq 'Windows' -and !($downloadAndConvertOnly)) {
    try {
        [string]$domainJoined = $null
        [string]$domainName = $null
        $messageTxt =  "Checking if Gen2 VM $gen2vmName under resource group $resourceGroup is domain joined"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
        $paramInvokeAzVmRunCommand = @{
            ResourceGroupName = $resourceGroup
            VMName = $gen2VMName
            CommandId = 'RunPowerShellScript'
            ScriptString = "(Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).PartOfDomain"
            ErrorAction = 'Stop'
        }
        $domainJoined = (Invoke-AzVMRunCommand @paramInvokeAzVmRunCommand).Value[0].Message
    
        If ($domainJoined -eq "True") {
            $paramInvokeAzVmRunCommand = @{
                ResourceGroupName = $resourceGroup
                VMName = $gen2VMName
                CommandId = 'RunPowerShellScript'
                ScriptString = "(Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain"
                ErrorAction = 'Stop'
            }
            $domainName = (Invoke-AzVMRunCommand @paramInvokeAzVmRunCommand).Value[0].Message
        } else {
            $messageTxt = "Gen2 VM $gen2VMName is not domain joined."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
        }
    
        If ($domainName) {
            [string]$validateTrust = $null
            $messageTxt = "Validating trust status for $gen2VMName with domain $domainName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
            $paramInvokeAzVmRunCommand = @{
                ResourceGroupName = $resourceGroup
                VMName = $gen2VMName
                CommandId = 'RunPowerShellScript'
                ScriptString = "Test-ComputerSecureChannel"
                ErrorAction = 'Stop'
            }
            $validateTrust = (Invoke-AzVMRunCommand @paramInvokeAzVmRunCommand).Value[0].Message
    
            If ($validateTrust -eq "True") {
                $messageTxt = "Machine $gen2VMName trust with domain $domainName not impacted"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
            } else {
                $messageTxt = "Domain trust for machine $gen2VMName with $domainName broken."
                Write-Warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Validate-DomainHealth"
                $messageTxt = "VM $gen2VMName is joined to domain $domainName. Post conversion Reset-ComputerMachinePassword is required for healthy Trust between VM and domain."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
                $title    = 'Confirm'
                $question = 'Execute Reset-ComputerMachinePassword?'
                $choices  = '&Yes', '&No'
                $decision = $Host.UI.PromptForChoice($title, $question, $choices, -1)
    
                if ($decision -eq 0) {
                    $messageTxt = "Provide domain credentials for $domainName to reset computer machine password."
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
                    $domainCred = Get-Credential
                    $domainController = Read-Host -Prompt "Enter domain controller fqdn which will be contacted for reset computer machine password operation"
                    $messageTxt = "Resetting Computer Machine password using $($domainCred.UserName) and $domainController"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
                    $paramInvokeAzVmRunCommand = @{
                        ResourceGroupName = $resourceGroup
                        VMName = $gen2VMName
                        CommandId = 'RunPowerShellScript'
                        ScriptString = "Reset-ComputerMachinePassword -Server $domainController -Credential $domainCred"
                        ErrorAction = 'Stop'
                    }
                    Invoke-AzVMRunCommand @paramInvokeAzVmRunCommand | Out-Null
                    
                    [string]$validateTrust = $null
                    $messageTxt = "Re-Validating trust status for $gen2VMName"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
                    $paramInvokeAzVmRunCommand = @{
                        ResourceGroupName = $resourceGroup
                        VMName = $gen2VMName
                        CommandId = 'RunPowerShellScript'
                        ScriptString = "Test-ComputerSecureChannel"
                        ErrorAction = 'Stop'
                    }
                    $validateTrust = (Invoke-AzVMRunCommand @paramInvokeAzVmRunCommand).Value[0].Message
                    If ($validateTrust -eq "True") {
                        $messageTxt = "Machine $gen2VMName trust with domain $domainName re-established."
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
                    } else {
                        $messageTxt = "Domain trust for machine $gen2VMName with $domainName could not be re-established."
                        Write-Warning $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Validate-DomainHealth"
                    }
                }
            }        
        }
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Validate-DomainHealth"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Enable SQL VM
if ($ERRORLEVEL -eq 0 -and $CurrentVMConfig.sqlVm -eq $true -and !($downloadAndConvertOnly)) {
    try {
        $messageTxt = "Registering Gen2 VM $gen2vmname as SQL VM with AHUB license and LightWeight Management type"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Register-SQLVM"

        $paramNewSqlVm = @{
            Name    = $gen2VMName
            ResourceGroupName = $resourceGroup
            Location          = $CurrentVMConfig.location
            LicenseType       = 'AHUB'
            SqlManagementType = 'LightWeight'
            ErrorAction       = 'Stop'
        }
        if ($sqlTags.Count -gt 0) {
            $paramNewSqlVm.Add('Tag', $sqlTags)
        }
        New-AzSqlVM @paramNewSqlVm | Out-Null
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Register-SQLVM"
        Set-ErrorLevel -1
    }
}
#endregion

#region - Closure
if ($ERRORLEVEL -eq 0) {
    if ($downloadAndConvertOnly) {
        $messageTxt = "Gen1 VM $vmName OS Disk downloaded and converted successfully. Please re-run script with uploadAndDeployOnly parameter to complete conversion."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Conversion-Complete"
    } else {
        $messageTxt = "Gen1 VM $vmName under resource group $vmResourceGroupName successfully converted to Gen2 $gen2VMName under resource group $resourceGroup."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Conversion-Complete"
    }
}
#endregion

#region - Rollback
If ($ERRORLEVEL -eq -1 -and $rollBackRequired -eq $true) {
    try {
        if ($removeVm -eq $true) {
            $messageTxt = "Re-Create Gen1 VM using Snapshot $([system.string]::concat($vmName, "-gen1-os-disk-snapshot"))"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"

            $snapshot = Get-AzSnapshot -ResourceGroupName $vmResourceGroupName -SnapshotName $([system.string]::concat($vmName, "-gen1-os-disk-snapshot")) -ErrorAction 'Stop'

            $messageTxt = "Setting up restore disk config"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
            $newDiskConfigParam = @{
                Location            = $CurrentVMConfig.location
                SkuName             = $currentOsDiskConfig.sku
                OsType              = $CurrentVMConfig.osdisk.OsType
                CreateOption        = 'Copy'
                SourceResourceId    = $snapshot.Id
                DiskSizeGB          = $currentOsDisk.DiskSizeGB
                HyperVGeneration    = 'v1'
                EncryptionType      = $currentOsDiskConfig.encryption.Type
                ErrorAction         = 'Stop'
            }
            if ($CurrentVMConfig.zone) {
                $newDiskConfigParam.Add('Zone', $CurrentVMConfig.zone)
            }
            If ($currentOsDisk.Tags.Count -gt 0) {
                $newDiskConfigParam.Add('Tag', $currentOsDisk.Tags)
            }
            if ($currentOsDiskConfig.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($currentOsDiskConfig.encryption.DiskEncryptionSetId)) {
                $newDiskConfigParam.Add('DiskEncryptionSetId', $currentOsDiskConfig.encryption.DiskEncryptionSetId)
            }
            $restoreGen1DiskConfig = New-AzDiskConfig @newDiskConfigParam

            $messageTxt = "Restoring disk $($currentOsDisk.Name) under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
            $paramNewAzDisk = @{
                ResourceGroupName = $vmResourceGroupName
                DiskName = $currentOsDisk.Name
                Disk = $restoreGen1DiskConfig
                ErrorAction = 'Stop'
            }
            New-AzDisk @paramNewAzDisk | Out-Null

            $messageTxt = "Restoring Gen1 VM $vmName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
            $newAzVmConfigParam = @{
                VMName  = $vmName
                VMSize  = $CurrentVMConfig.vmsize
                ErrorAction = 'Stop'
            }
            if ($CurrentVMConfig.zone) {
                $newAzVmConfigParam.Add('Zone', $CurrentVMConfig.zone)
            }
            elseif ($CurrentVMConfig.avSetId) {
                $newAzVmConfigParam.Add('AvailabilitySetId', $CurrentVMConfig.avSetId)
            }
            else {
                $messageTxt = "Gen1 VM $vmName is not using any high availability configuration using Availability Set or Zone."
                Write-Warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Restore-Gen1VM"
            }
            if ($CurrentVMConfig.ultraSSD -eq $true) {
                $newAzVmConfigParam.Add('EnableUltraSSD', $true)
            }
            if ($CurrentVMConfig.hibernationEnabled -eq $true) {
                $newAzVmConfigParam.Add('HibernationEnabled', $true)
            }
            if ($CurrentVMConfig.proxPlacementGrp) {
                $newAzVmConfigParam.Add('ProximityPlacementGroupId', $CurrentVMConfig.proxPlacementGrp)
            }
            $restoreVm = New-AzVMConfig @newAzVmConfigParam
            If ($CurrentVMConfig.nicCardList.Count -eq 1) {
                $restoreVm = Add-AzVMNetworkInterface -VM $restoreVm -Id $CurrentVMConfig.nicCardList -ErrorAction 'Stop'
            }
            else {
                foreach ($existingNic in $CurrentVMConfig.nicCardList) {
                    $restoreVm = Add-AzVMNetworkInterface -VM $restoreVm -Id $existingNic -ErrorAction 'Stop'
                }
            }

            $messageTxt = "Restoring $vmName using OS disk $($currentOsDisk.Name)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
            $restoreGen1Disk = Get-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $($currentOsDisk.Name) -ErrorAction 'Stop'
            $setOsDiskParam = @{
                VM              = $restoreVm
                Name            = $($currentOsDisk.Name)
                CreateOption    = 'Attach'
                ManagedDiskId   = $restoreGen1Disk.Id
                Caching         = 'ReadWrite'
                ErrorAction     = 'Stop'
            }
            switch ($currentOsDiskConfig.osType) {
                "Linux" {
                    $setOsDiskParam.Add('Linux', $true)
                }
                "Windows" {
                    $setOsDiskParam.Add('Windows', $true)
                }
                default {
                    $setOsDiskParam.Add('Windows', $true)
                }
            }
            if ($currentOsDiskConfig.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($currentOsDiskConfig.encryption.DiskEncryptionSetId)) {
                $setOsDiskParam.Add('DiskEncryptionSetId', $currentOsDiskConfig.encryption.DiskEncryptionSetId)
            }
            $restoreVm = Set-AzVMOSDisk @setOsDiskParam

            foreach ($disk in $CurrentVMConfig.dataDisk) {
                $dataDisk = $null
                $dataDisk = Get-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $disk.Name -ErrorAction 'SilentlyContinue'
                $messageTxt = "Adding $($disk.Name) at LUN $($disk.Lun)"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
                $paramAddAzVmDataDisk = @{
                    VM = $restoreVm
                    Name = $disk.Name
                    CreateOption = 'Attach'
                    LUN = $disk.Lun
                    Caching = $disk.Caching
                    ManagedDiskId = $dataDisk.Id
                    ErrorAction = 'SilentlyContinue'
                }
                if ($dataDisk.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($dataDisk.encryption.DiskEncryptionSetId)) {
                    $paramAddAzVmDataDisk.Add('DiskEncryptionSetId', $dataDisk.encryption.DiskEncryptionSetId)
                }
                $restoreVm = Add-AzVMDataDisk @paramAddAzVmDataDisk
            }
    
            If ($CurrentVMConfig.bootDiagnostic.Enabled -eq $true) {
                If ($CurrentVMConfig.bootDiagnostic.StorageUri) {
                    $bootDiagSaName = $CurrentVMConfig.bootDiagnostic.StorageUri.Replace('https://','').Replace('.blob.core.windows.net','').Replace('/','')
                    $bootDiagSaRg = (Get-AzStorageAccount | Where-Object {$psitem.StorageAccountName -eq $bootDiagSaName}).ResourceGroupName
                    if ($bootDiagSaRg) {
                        $messageTxt = "Setting up Un-Managed Boot Diagnostics for $vmName using storage account $bootDiagSaName under resource group $bootDiagSaRg"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
                        Set-AzVMBootDiagnostic -VM $restoreVm -Enable -ResourceGroupName $bootDiagSaRg -StorageAccountName $bootDiagSaName | Out-Null
                    } else {
                        $messageTxt = "Setting up Managed Boot Diagnostics for $vmName"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
                        Set-AzVMBootDiagnostic -VM $restoreVm -Enable | Out-Null
                    }
                }
                else {
                    $messageTxt = "Setting up Managed Boot Diagnostics for $vmName"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
                    Set-AzVMBootDiagnostic -VM $restoreVm -Enable | Out-Null
                }
            }
            else {
                $message = "Boot diagnostics for Gen1 VM $vmName is disabled. Boot diagnostics will be disabled for Gen2 VM $vmName as well."
                Write-Warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Restore-Gen1VM"
            }
    
            $messageTxt = "Setting restored $vmName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
            $paramNewAzVm = @{
                ResourceGroupName = $vmResourceGroupName
                VM = $restoreVm
                Location = $CurrentVMConfig.location
                ErrorAction = 'Stop'
            }
            if ($currentvm.Tags.count -gt 0) {
                $paramNewAzVm.Add('Tag', $currentVm.Tags)
            }
            New-AzVM @paramNewAzVm | Out-Null
        } else {
            $messageTxt = "Restore Gen1 VM $vmName configuration including Data disks, NIC."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"

            $paramGetAzVm = @{
                ResourceGroupName = $vmResourceGroupName
                Name              = $vmName
                ErrorAction       = 'Stop'
            }
            $restoreVm = Get-AzVM @paramGetAzVm
            $restoreVmConfig = @{
                nicCardList     = $restoreVm.NetworkProfile.NetworkInterfaces.Id
            }
            If ($CurrentVMConfig.nicCardList.Count -eq 1) {
                $restoreVm = Add-AzVMNetworkInterface -VM $restoreVm -Id $CurrentVMConfig.nicCardList -Primary -ErrorAction 'Stop'
            }
            else {
                foreach ($existingNic in $CurrentVMConfig.nicCardList) {
                    $restoreVm = Add-AzVMNetworkInterface -VM $restoreVm -Id $existingNic -ErrorAction 'Stop'
                }
            }
            $messageTxt = "Remove existing Temp NIC cards"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
            $restoreVm = Remove-AzVMNetworkInterface -VM $restoreVm -NetworkInterfaceIDs $restoreVmConfig.nicCardList -ErrorAction 'Stop'

            foreach ($disk in $CurrentVMConfig.dataDisk) {
                $dataDisk = $null
                $dataDisk = Get-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $disk.Name -ErrorAction 'SilentlyContinue'
                $messageTxt = "Adding $($disk.Name) at LUN $($disk.Lun)"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
                $paramAddAzVmDataDisk = @{
                    VM = $restoreVm
                    Name = $disk.Name
                    CreateOption = 'Attach'
                    LUN = $disk.Lun
                    Caching = $disk.Caching
                    ManagedDiskId = $dataDisk.Id
                    ErrorAction = 'SilentlyContinue'
                }
                if ($dataDisk.encryption.Type -eq "EncryptionAtRestWithCustomerKey" -and ($dataDisk.encryption.DiskEncryptionSetId)) {
                    $paramAddAzVmDataDisk.Add('DiskEncryptionSetId', $dataDisk.encryption.DiskEncryptionSetId)
                }
                $restoreVm = Add-AzVMDataDisk @paramAddAzVmDataDisk

                $messageTxt = "Updating VM Configuration for Gen1 $vmName"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Restore-Gen1VM"
                Update-AzVM -VM $restoreVm -ResourceGroupName $vmResourceGroupName -ErrorAction 'Stop' | Out-Null
            }
        }
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Restore-Gen1VM"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion