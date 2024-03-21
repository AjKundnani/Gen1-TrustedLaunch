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
        8. Swap OS disk for Gen1 VM
        9. Updates Gen1 VM to Trusted launch.

.PARAMETER subscriptionId
Subscription ID for Gen1 VM & target Gen2 VM.

.PARAMETER tenantDomain
Primary AAD Domain Name for authentication. (For example, contoso.onmicrosoft.com)

.PARAMETER vmName
Gen1 VM Resource Name.

.PARAMETER vmResourceGroupName
Resource Group for Gen1 VM & target Gen2 VM.

.PARAMETER targetOsDiskName
Name of Gen2-Trusted launch converted target OS disk.

.PARAMETER disableSecureBoot
(Optional) If target Trusted Launch VM should be deployed with Secure Boot disabled. This option would be needed if VM is hosting custom or unsigned boot drivers which cannot be attested.

.PARAMETER workingDirectory
Local directory used to download OS Disk on Windows 10/11 machine where MBR2GPT Utility will be executed.

.PARAMETER downloadAndConvertOnly
(Optional) Download and Convert OS disk only. Script will not upload or deploy converted VM. This can be used to control the stages of script. Script will run end-to-end if both downloadAndConvertOnly and uploadAndDeployOnly parameters are not used.

.PARAMETER uploadAndDeployOnly
(Optional) Upload OS disk and deploy converted VM only. This parameter assumes script has already been executed with downloadAndConvertOnly and required files are in place already. Script will run end-to-end if both downloadAndConvertOnly and uploadAndDeployOnly parameters are not used.

.PARAMETER disableVmEncryption
(Optional) Disable Azure VM encryption at time of execution of script. Encryption will need to be manually re-enabled post deployment. NOTE: This option will not work if any of the VM Disk is configured with Customer-Managed Key encryption.

.PARAMETER enablePremiumDiskTier
(Optional) Change Gen1 OS Disk to Premium SSD for improved download time. Converted disk will be uploaded with original disk tier.

.EXAMPLE
    .\Convert-Gen1ToTLVM.ps1 -subscriptionId $subscriptionId -tenantDomain $tenantDomain -vmName ws2016vm01 -vmResourceGroupName testrg -targetOsDiskName ws2016vm01-osdisk -workingDirectory F:\workingdir\
    
    Convert Gen1 VM to Trusted Launch VM.
    
.EXAMPLE
    .\Convert-Gen1ToTLVM.ps1 -subscriptionId $subscriptionId -tenantDomain $tenantDomain -vmName ws2016vm01 -vmResourceGroupName testrg -targetOsDiskName ws2016vm01-osdisk -workingDirectory F:\workingdir\ -uploadAndDeployOnly
    
    Disk is already converted to GPT locally. Uploads the disk and converts the VM from Gen1 to Trusted launch

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
    [Parameter(Mandatory = $true, HelpMessage = "Name of source Gen1 VM")]
    [string][ValidateNotNullOrEmpty()]$vmName,
    [Parameter(Mandatory = $true, HelpMessage = "Source Gen1 VM resource group")]
    [string][ValidateNotNullOrEmpty()]$vmResourceGroupName,
    [Parameter(Mandatory = $true, HelpMessage = "Name of converted target OS disk.")]
    [string][ValidateNotNullOrEmpty()]$targetOsDiskName,
    [Parameter(Mandatory = $false, HelpMessage = "Disable secure boot for target VM")]
    [switch]$disableSecureBoot,
    [Parameter(Mandatory = $true, HelpMessage = "Working directory for script on local machine for conversion")]
    [string][ValidateNotNullOrEmpty()]$workingDirectory,
    [Parameter(Mandatory = $false, HelpMessage = "Use this switch to execute download and conversion of OS Disk only. Upload and VM deployment will not be executed.")]
    [switch]$downloadAndConvertOnly,
    [Parameter(Mandatory = $false, HelpMessage = "Use this switch to execute Upload OS Disk and VM deployment only. This parameter assumes OS Disk and required files are already in-place. Ensure to execute script with downloadAndConvertOnly first.")]
    [switch]$uploadAndDeployOnly,
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

    $azPsModule = @(@{
        ModuleName = 'Az.Accounts'
        Version    = [version]"2.8.0"
    },
    @{
        ModuleName = 'Az.Compute'
        Version    = [version]"6.0.0"
    },
    @{
        ModuleName = 'Az.Network'
        Version    = [version]"6.0.0"
    },
    @{
        ModuleName = 'Az.Storage'
        Version    = [version]"5.5.0"
    })

    foreach ($azModule in $azPsModule) {
        $module = Get-Module -ListAvailable -Name $azModule.ModuleName

        # Check if the module is available
        if ($module) {
            # Check if the module version is greater than or equal to the minimum version
            if ($module.Version -ge $azModule.Version) {
                $messagetxt = "Module $($azModule.ModuleName) with minimum version $($azModule.Version) is available."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
            } else {
                $messagetxt = "Module $($azModule.ModuleName)  is available, but its version is lower than the minimum version $($azModule.Version). Upgrading module on local machine."
                Write-warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Setup-PreRequisites"
                Update-Module $($azModule.ModuleName) -ErrorAction 'Stop' -Confirm:$false -Force
            }
        } else {
            $messagetxt = "Module $($azModule.ModuleName) is not available, proceeding with Az Module install."
            Write-warning $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Setup-PreRequisites"
            Install-Module -Name $($azModule.ModuleName) -Repository PSGallery -Force -Confirm:$false -ErrorAction 'Stop'
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

        [bool]$gen2Vm = $false
        [bool]$trustedLaunchVM = $false
    
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
            securityType    = $currentVm.SecurityProfile.SecurityType
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
            if ($CurrentVMConfig.securityType) {
                $messagetxt = "VM $vmName under resource group $vmResourceGroupName is already Trusted launch, no further action required."
                [bool]$trustedLaunchVM = $true
                [bool]$gen2Vm = $true
                Write-Error $messagetxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-AzVM"
                Set-ErrorLevel -1
            } else {
                $messageTxt = "VM $vmName under resource group $vmResourceGroupName is already running as Gen2, skipping MBR to GPT conversion."
                [bool]$gen2Vm = $true
                Write-Warning $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Get-AzVM"
            }
        } elseif ($currentOsDiskConfig.osType -eq "Linux") {
            $messageTxt ="OS Type of Source VM is $($currentOsDiskConfig.osType). Assuming disk conversion is completed locally on VM using gdisk before proceeding."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Get-AzVM"
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

        if (($gen2Support.value.Split(",")[-1] -eq "V2") -and !($tlvmSupport)) {
            $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) supported for TLVM. Proceeding to create TLVM."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-SkuFeature"
            $trustedLaunch = $true
        } else {
            $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) not supported for Trusted launch. Update VM Size to Trusted launch Supported SKU. For more details, https://aka.ms/TrustedLaunch"
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
        $existingGen2Disk = $null
        $existingGen2Disk = Get-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $targetOsDiskName -ErrorAction 'SilentlyContinue'

        If ($existingGen2Disk){
            $messageTxt = "$targetOsDiskName already exists under $vmResourceGroupName. Delete the disk or use different target disk naem. Terminating script."
            Write-Error $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "New-AzDisk"
            Set-ErrorLevel -1
        } else {
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
            $messageTxt = "Adding trusted launch disk configuration"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            Set-AzDiskSecurityProfile -Disk $gen2diskConfig -SecurityType "TrustedLaunch" -ErrorAction 'Stop' | Out-Null

            $messageTxt = "Setting up new disk $targetOsDiskName under $vmResourceGroupName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            $paramNewAzDisk = @{
                ResourceGroupName = $vmResourceGroupName
                DiskName = $targetOsDiskName
                Disk = $gen2diskConfig
                ErrorAction = 'Stop'
            }
            $gen2OsDisk = New-AzDisk @paramNewAzDisk
            $gen2OsDisk = Get-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $gen2OsDisk.Name -ErrorAction 'SilentlyContinue'

            while ($gen2OsDisk.DiskState -ne "ReadyToUpload") {
                $messageTxt = "Awaiting Disk State update. DiskState: $($gen2OsDisk.DiskState), ProvisioningState: $($gen2OsDisk.ProvisioningState)"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
                Start-Sleep -Seconds 3
                $gen2OsDisk = Get-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $gen2OsDisk.Name -ErrorAction 'SilentlyContinue'
            }

            $messageTxt = "Generating Upload URL for $targetOsDiskName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            $gen2diskSas = (Grant-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $targetOsDiskName -DurationInSecond 86400 -Access 'Write' -ErrorAction 'Stop').AccessSAS

            $messageTxt = "Uploading converted vhd to $targetOsDiskName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            Set-Location $azCopyDir
            .\azcopy copy "$logDirectory\$vmName-osdisk.vhd" $gen2diskSas
            Set-Location $workingDirectory
            $messageTxt = "Revoking Upload URL"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            Revoke-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $targetOsDiskName -ErrorAction 'Stop' | Out-Null

            if ($enablePremiumDiskTier -and $currentOsDiskConfig.sku -ne 'Premium_LRS') {
                $messageTxt = "Changing $targetOsDiskName under resource group $vmResourceGroupName to $($currentOsDiskConfig.Sku)."
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Download-AzDisk"
                $gen2OsDisk.Sku = [Microsoft.Azure.Management.Compute.Models.DiskSku]::new($($currentOsDiskConfig.Sku))
                Update-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $targetOsDiskName -Disk $gen2OsDisk -ErrorAction 'SilentlyContinue' | Out-Null
            }
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

#region - Swap OS Disk
if ($ERRORLEVEL -eq 0 -and !($downloadAndConvertOnly)) {
    try {
        $messageTxt = "De-allocating VM $vmName"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"

        $paramStopAzVm = @{
            ResourceGroupName   = $vmResourceGroupName
            Name                = $vmName
            Force               = $true
            Confirm             = $false
            ErrorAction         = 'Stop'
        }
        Stop-AzVm @paramStopAzVm | Out-Null

        $messageTxt = "Set the VM configuration to point to the new disk $($gen2OsDisk.Name)"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"

        Set-AzVMOSDisk -VM $currentVm -ManagedDiskId $gen2OsDisk.Id -Name $gen2OsDisk.Name -ErrorAction 'Stop' | Out-Null

        $messageTxt = "Update the VM with the new OS disk and Gen2-Trusted launch configuration"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"

        $paramUpdateAzVm = @{
            ResourceGroupName   = $vmResourceGroupName
            VM                  = $currentVm
            SecurityType        = 'TrustedLaunch'
            EnableVtpm          = $true
            ErrorAction         = 'Stop'
        }
        if ($disableSecureBoot -eq $true) {
            $paramUpdateAzVm.Add('EnableSecureBoot', $false)
        } else {$paramUpdateAzVm.Add('EnableSecureBoot', $true)}
        Update-AzVM @paramUpdateAzVm | Out-Null

        $messageTxt = "Starting $vmname"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"

        $paramStartAzVm = @{
            ResourceGroupName   = $vmResourceGroupName
            Name                = $vmName
            ErrorAction         = 'Stop'
        }
        Start-AzVM @paramStartAzVm | Out-Null
        
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Update-AzVM"
        Set-ErrorLevel -1
        exit $ERRORLEVEL
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
        $messageTxt = "Gen1 VM $vmName under resource group $vmResourceGroupName successfully converted to Trusted launch."
        Write-Output $messageTxt
        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Conversion-Complete"
    }
}
#endregion