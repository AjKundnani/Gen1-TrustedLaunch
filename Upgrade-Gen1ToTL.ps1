<#
.SYNOPSIS
Upgrades Azure VM from Gen1 to Trusted Launch Configuration with OS State preserved.
Script Version - 2.1.0

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

.PARAMETER batchSize
(Optional) Number of machines which should be processed in parallel. Default set to 5.

.PARAMETER useCloudshell
(Optional) Use cloud shell in Azure Portal for script execution.

.PARAMETER useSignedScript
(Optional) Use end to end signed script for upgrade.

.PARAMETER outputStorageAccountName
(Required with useSignedScript) Name of storage account where output and error file will be stored. Storage Blob Data Contributor or Storage Blob Data Owner access required on storage account.

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

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]

param (
    [Parameter(Mandatory = $true, HelpMessage = "Azure Subscription Id or Guid")]
    [string][ValidateNotNullOrEmpty()]$subscriptionId,
    [Parameter(Mandatory = $true, HelpMessage = "Azure Tenant domain")]
    [string][ValidateNotNullOrEmpty()]$tenantDomain,
    [Parameter(Mandatory = $true, HelpMessage = "Location of csv containing Gen1 VM(s) details - vmName, vmResourceGroupName, EnableSecureBoot.")]
    [string][ValidateNotNullOrEmpty()]$csvLocation,
    [Parameter(Mandatory = $false, HelpMessage = "Number of machines which should be processed in parallel. Default set to 5.")]
    [int][ValidateNotNullOrEmpty()]$batchSize,
    [Parameter(Mandatory = $false, HelpMessage = "Use cloud shell in Azure Portal for script execution.")]
    [switch]$useCloudshell,
    [Parameter(Mandatory = $false, HelpMessage = "Use end to end signed script for upgrade.")]
    [switch]$useSignedScript,
    [Parameter(Mandatory = $false, HelpMessage = "Required if useSignedScript is set. Name of storage account where output and error file will be stored. Storage Blob Data Contributor or Storage Data Owner access required on storage account.")]
    [string][ValidateNotNullOrEmpty()]$outputStorageAccountName
)

#region - Validate Pre-Requisites
try {
    New-Variable -Name 'ERRORLEVEL' -Value 0 -Scope Script -Force
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion.Major -gt 7 -or ($PSVersion.Major -eq 7 -and $PSVersion.Minor -gt 2)) {
        $messagetxt = "PowerShell version is greater than 7.2"
        Write-Output $messageTxt
    } else {
        $messagetxt = "PowerShell version is not greater than 7.2 and does not meets requirements."
        Write-Error $messagetxt
        Set-Variable -Name ERRORLEVEL -Value -1 -Scope Script -Force
    }

    if ($useCloudshell) {
        $workingDirectory = [system.string]::concat((Get-Location).Path, "/Gen1-TrustedLaunch-Upgrade")
    } else {$workingDirectory = "$env:UserProfile\Gen1-TrustedLaunch-Upgrade"}
    if ((Test-Path $workingDirectory) -eq $true) {
        $messageTxt = "Working Directory Already Setup $workingDirectory"
        Write-Output $messageTxt
    }
    else {
        $messageTxt = "Setting up working dir $workingDirectory"
        Write-Output $messageTxt
        New-Item -ItemType Directory -Path (Split-Path $workingDirectory -Parent) -Name (Split-Path $workingDirectory -Leaf) -ErrorAction 'Stop' | Out-Null
    }

    If ($useSignedScript -and !($outputStorageAccountName)) {
        $messagetxt = "Output storage account name is required if useSignedScript is set."
        Write-Error $messageTxt
        Set-Variable -Name ERRORLEVEL -Value -1 -Scope Script -Force
    }

    $azPsModule = @(@{
            ModuleName = 'Az.Accounts'
            Version    = [version]"2.8.0"
        },
        @{
            ModuleName = 'Az.Compute'
            Version    = [version]"6.0.0"
        },
        @{
            ModuleName = 'Az.Storage'
            Version    = [version]"5.8.0"
        })

    foreach ($azModule in $azPsModule) {
        $module = Get-Module -ListAvailable -Name $azModule.ModuleName

        # Check if the module is available
        if ($module) {
            # Check if the module version is greater than or equal to the minimum version
            if ($module.Version -ge $azModule.Version) {
                $messagetxt = "Module $($azModule.ModuleName) with minimum version $($azModule.Version) is available."
                Write-Output $messageTxt
            }
            else {
                $messagetxt = "Module $($azModule.ModuleName)  is available, but its version is lower than the minimum version $($azModule.Version). Upgrading module on local machine."
                Write-warning $messageTxt
                Update-Module $($azModule.ModuleName) -ErrorAction 'Stop' -Confirm:$false -Force
            }
        }
        else {
            $messagetxt = "Module $($azModule.ModuleName) is not available, proceeding with $($azModule.ModuleName) install."
            Write-warning $messageTxt
            Install-Module -Name $($azModule.ModuleName) -Repository PSGallery -Force -Confirm:$false -ErrorAction 'Stop'
        }
    }
}
catch [system.exception] {
    $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
    Write-Output $messageTxt
    $ERRORLEVEL = -1
}
#endregion

#region - Connect Azure Subscription
If ($ERRORLEVEL -eq 0) {
    try {
        $messageTxt = "Connecting to Subscription $subscriptionId under $tenantDomain"
        Write-Output $messageTxt
        #region - Enable-AzAccount()
        if ($useCloudshell) {
            Set-AzContext -SubscriptionId $subscriptionId -tenant $tenantDomain -ErrorAction 'Stop'
        } else {
            $azureProfile = "$workingDirectory\AzureProfile-$subscriptionId.json"
            $paramTestPath = @{
                Path        = $($azureProfile)
                ErrorAction = 'Stop'
            }
            if (Test-Path @paramTestPath) {
                $messageTxt = "Clearing previously cached Azure profile JSON"
                Write-Output $messageTxt
                Remove-Item -Path $azureProfile -Force -Confirm:$false -ErrorAction 'Stop' | Out-Null
            }
            $paramTestPath = @{
                Path        = $workingDirectory
                PathType    = 'Container'
                ErrorAction = 'Stop'
            }
            if (-not (Test-Path @paramTestPath)) {
                $paramNewItem = @{
                    Path        = $workingDirectory
                    ItemType    = 'directory'
                    ErrorAction = 'Stop'
                }
                New-Item @paramNewItem | Out-Null
            }

            $paramConnectAzAccount = @{
                subscriptionId = $subscriptionID
                Tenant         = $tenantDomain
                ErrorAction    = 'Stop'
            }
            if ($environment) {
                $paramConnectAzAccount.Add('Environment', $environment)
            }
            Connect-AzAccount @paramConnectAzAccount

            $paramSaveAzContext = @{
                Path        = $($azureProfile)
                Force       = $true
                ErrorAction = 'Stop'
            }
            Save-AzContext @paramSaveAzContext | Out-Null
        }
        #endregion
    }
    catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Set-Variable -Name ERRORLEVEL -Value -1 -Scope Script -Force
    }    
}
#endregion

if ($ERRORLEVEL -eq 0) {
    #region - Main script
    if (-not $batchSize) {
        [int]$batchSize = 5
    }

    $importVmArray = Import-Csv $csvLocation -ErrorAction 'Stop'
    foreach ($element in $importVmArray) {
        $element | Add-Member -MemberType NoteProperty -Name 'subscriptionId' -Value $subscriptionId
        $element | Add-Member -MemberType NoteProperty -Name 'tenantDomain' -Value $tenantDomain
        if ($useCloudshell) {
            $element | Add-Member -MemberType NoteProperty -Name 'useCloudShell' -Value $true
        }
        if ($useSignedScript) {
            $element | Add-Member -MemberType NoteProperty -Name 'useSignedScript' -Value $true
            $element | Add-Member -MemberType NoteProperty -Name 'storageAccountName' -Value $outputStorageAccountName
        }
    }

    $importVmArray | ForEach-Object -ThrottleLimit $batchSize -Parallel  {
        #region - Functions
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
                [string]$logDirectory,
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$vmName
            )
            try {
                $logStamp = (Get-Date -Format yy.MM.dd-HH.mm.ss)
                $script:logFile = "$logDirectory\$($vmName)-Gen1-TL-Upgrade-" + $logStamp + '.log'
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
                $logMessage,
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

        $importVm = $_
        $vmName = $importVm.vmName
        $vmResourceGroupName = $importVm.vmResourceGroupName
        $subscriptionId = $importVm.subscriptionID
        $tenantDomain = $importVm.tenantDomain
        $useCloudshell = $importVm.useCloudShell
        $outputStorageAccountName = $importVm.storageAccountName
        $useSignedScript = $importVm.useSignedScript
        
        if ($importVm.enableSecureBoot) {
            $enableSecureBoot = [system.convert]::ToBoolean($importVm.enableSecureBoot)
        }
        else { $enableSecureBoot = $true }
        [bool]$gen2Vm = $false
        [bool]$tlVm = $false

        #region - Validate Pre-Requisites
        try {
            Set-Errorlevel 0 | Out-Null
            Get-Errorlevel | Out-Null

            if ($useCloudshell) {
                $workingDirectory = [system.string]::concat((Get-Location).Path, "/Gen1-TrustedLaunch-Upgrade")
            } else {$workingDirectory = "$env:UserProfile\Gen1-TrustedLaunch-Upgrade"}

            Write-InitLog -logDirectory $workingDirectory -vmName $vmName
            $messageTxt = "Script Version: 2.1.0"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"

            $inputParam = @{
                'VM name' = $vmName
                'Resource group name' = $vmResourceGroupName
                'Subscription ID' = $subscriptionId
                'Tenant Domain' = $tenantDomain
                'Use Cloud Shell' = $useCloudshell
                'Use Signed Script' = $useSignedScript
                'Output Storage Account Name' = $outputStorageAccountName
                'Enable Secure Boot' = $enableSecureBoot
            }
            $messageTxt = $inputParam.GetEnumerator() | ForEach-Object {"$($PSItem.Key) = $($PSItem.Value)"}
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
            
            $messageTxt = "Processing VM $vmName under resource group $vmResourceGroupName with Secure boot $($importVm.enableSecureBoot)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
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
                $messageTxt = "Connecting to Subscription $subscriptionId under $tenantDomain"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Connect-AzSubscription"
                #region - Enable-AzAccount()
                If ($useCloudshell -eq $true) {
                    Set-AzContext -SubscriptionId $subscriptionId -tenant $tenantDomain -ErrorAction 'Stop'
                } else {
                    $azureProfile = "$workingDirectory\AzureProfile-$subscriptionId.json"
                    $paramTestPath = @{
                        Path        = $($azureProfile)
                        ErrorAction = 'Stop'
                    }
                    if (Test-Path @paramTestPath) {
                        $paramImportAzContext = @{
                            Path        = $($azureProfile)
                            ErrorAction = 'Stop'
                        }
                        Import-AzContext @paramImportAzContext | Out-Null
                    } else {
                        $paramTestPath = @{
                            Path        = $workingDirectory
                            PathType    = 'Container'
                            ErrorAction = 'Stop'
                        }
                        if (-not (Test-Path @paramTestPath)) {
                            $paramNewItem = @{
                                Path        = $workingDirectory
                                ItemType    = 'directory'
                                ErrorAction = 'Stop'
                            }
                            New-Item @paramNewItem | Out-Null
                        }

                        $paramConnectAzAccount = @{
                            subscriptionId = $subscriptionID
                            Tenant         = $tenantDomain
                            ErrorAction    = 'Stop'
                        }
                        if ($environment) {
                            $paramConnectAzAccount.Add('Environment', $environment)
                        }
                        Connect-AzAccount @paramConnectAzAccount

                        $paramSaveAzContext = @{
                            Path        = $($azureProfile)
                            Force       = $true
                            ErrorAction = 'Stop'
                        }
                        Save-AzContext @paramSaveAzContext | Out-Null
                    }
                }
                #endregion
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
        
                $paramGetAzVm = @{
                    ResourceGroupName = $vmResourceGroupName
                    Name              = $vmName
                    ErrorAction       = 'Stop'
                }
                $currentVm = Get-AzVM @paramGetAzVm
        
                $CurrentVMConfig = @{
                    osdisk       = $currentvm.StorageProfile.OsDisk
                    vmsize       = $currentvm.HardwareProfile.VmSize
                    location     = $currentVm.Location
                    securityType = $currentVm.SecurityProfile.SecurityType
                }
                
                $osDiskParam = @{
                    ResourceGroupName = $currentVm.ResourceGroupName
                    Name              = $CurrentVMConfig.osdisk.Name
                    ErrorAction       = 'Stop'
                }
                $currentOsDisk = Get-AzDisk @osDiskParam
        
                $currentOsDiskConfig = @{
                    sku        = $currentOsDisk.sku.Name
                    diskSize   = $currentOsDisk.DiskSizeGB
                    HyperVGen  = $currentOsDisk.HyperVGeneration
                    osType     = $currentOsDisk.OsType
                    encryption = $currentOsDisk.Encryption
                }
        
                if ($currentOsDiskConfig.HyperVGen -eq "V2") {
                    if ($CurrentVMConfig.securityType) {
                        $messagetxt = "VM $vmName under resource group $vmResourceGroupName is already Trusted launch, no further action required."
                        Write-Output $messagetxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
                        [bool]$tlVm = $true
                        [bool]$gen2Vm = $true
                    }
                    else {
                        $messageTxt = "VM $vmName under resource group $vmResourceGroupName is running as Gen2. MBR2GPT conversion will be skipped."
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
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
                    $messageTxt = "OS Type of Source VM is $($currentOsDiskConfig.osType) and OS Name is $($currentOs.OsName)."
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
                }
        
                #region - Validate SKU Support
                If ($tlVm -eq $false) {
                    $messageTxt = "Validating VM SKU $($CurrentVMConfig.vmsize) for $vmname is supported for Trusted launch"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
            
                    $gen2Support = $null
                    $tlvmSupport = $null
            
                    $skuDetail = Get-AzComputeResourceSku -Location $($CurrentVMConfig.location) -ErrorAction 'Stop' | `
                        Where-Object { $psitem.Name -eq $($CurrentVMConfig.vmsize) }
            
                    $gen2Support = $skuDetail | Select-Object -Property Capabilities -ExpandProperty Capabilities | Where-Object { $psitem.Name -eq "HyperVGenerations" }
                    $tlvmSupport = $skuDetail | Select-Object -Property Capabilities -ExpandProperty Capabilities | Where-Object { $psitem.Name -eq "TrustedLaunchDisabled" }
            
                    if (($gen2Support.value.Split(",")[-1] -eq "V2") -and !($tlvmSupport)) {
                        $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) supported for TLVM. Proceeding to create TLVM."
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
                    }
                    else {
                        $messageTxt = "VM SKU $($CurrentVMConfig.vmsize) not supported for Trusted launch. Update VM Size to Trusted launch Supported SKU. For more details, https://aka.ms/TrustedLaunch"
                        Write-Error $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Get-AzVM"
                        Set-ErrorLevel -1
                        exit $ERRORLEVEL
                    }
                }
                #endregion
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

        #region - MBR to GPT Validation
        if ($ERRORLEVEL -eq 0) {
            try {
                if ($gen2Vm -eq $false) {
                    if ($currentOsDiskConfig.osType -ne "Linux") {
                        if ($currentOs.OsName -contains '2016') {
                            $messagetxt = "Windows Server 2016 does not supports native MBR to GPT upgrade. Please follow offline upgrade path available in GitHub repo. Terminating script"
                            Write-Error $messagetxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Validation"
                            Set-ErrorLevel -1
                        }
                        else {
                            $messageTxt = "Validating MBR to GPT conversion support for $vmname"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                            If ($useSignedScript -eq $true) {
                                $messageTxt = "Using signed script for executing MBR to GPT validation"
                                Write-Output $messageTxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
    
                                $messageTxt = "Creating container gen1log in storage account $outputStorageAccountName"
                                Write-Output $messageTxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                                $ctx = New-AzStorageContext -StorageAccountName $outputStorageAccountName -UseConnectedAccount -erroraction 'stop'
                                New-AzStoragecontainer -Name "gen1log" -Context $ctx -ErrorAction 'SilentlyContinue' | Out-Null
    
                                $messageTxt = "Generating SAS URL for output file in storage account $outputStorageAccountName"
                                Write-Output $messageTxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                                $sasToken = New-AzStorageContainerSASToken -Context $ctx -Name "gen1log" -Permission rawl -StartTime $((Get-Date).AddMinutes(-5)) -ExpiryTime $((Get-Date).AddHours(1)) -ErrorAction 'Stop'
                                $outputBlobSasUri = "https://$outputStorageAccountName.blob.core.windows.net/gen1log/$vmName-mbr2gpt-validate-output.log?" + $sasToken
                                $errorBlobSasUri = "https://$outputStorageAccountName.blob.core.windows.net/gen1log/$vmName-mbr2got-validate-error.log?" + $sasToken
    
                                $messageTxt = "Executing MBR to GPT validation for $vmName"
                                Write-Output $messageTxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                                $paramInvokeAzVMRunCommand = @{
                                    ResourceGroupName = $vmResourceGroupName
                                    VMName            = $vmName
                                    Location          = $CurrentVMConfig.location
                                    RunCommandName    = [system.string]::Concat($vmName, "-MBR2GPT-Validate")
                                    SourceScriptUri   = "https://raw.githubusercontent.com/AjKundnani/Gen1-TrustedLaunch/main/artifacts/Validate-MBRToGPT.ps1"
                                    OutputBlobUri     = $outputBlobSasUri
                                    ErrorBlobUri      = $errorBlobSasUri
                                    ErrorAction       = 'Stop'
                                }
                                Set-AzVMRunCommand @paramInvokeAzVMRunCommand | Out-Null

                                $outputLog = (Get-AzStorageBlobContent -Blob "$vmName-mbr2gpt-validate-output.log" -Container "gen1log" -Context $ctx).ICloudBlob.DownloadText()
                                $errorLog = (Get-AzStorageBlobContent -Blob "$vmName-mbr2gpt-validate-error.log" -Container "gen1log" -Context $ctx).ICloudBlob.DownloadText()

                                if ($errorLog.Length -gt 0 -or $outputLog.Length -eq 0) {
                                    $messagetxt = "MBR to GPT support validation for Windows $vmname failed. Terminating script execution."
                                    Write-Error $messagetxt
                                    Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Validation"
                                    Set-ErrorLevel -1    
                                }
                                else {
                                    Remove-Item -Path "$vmName-mbr2gpt-validate-output.log" -Force -Confirm:$false
                                    Remove-Item -Path "$vmName-mbr2gpt-validate-error.log" -Force -Confirm:$false
                                    $messagetxt = "MBR to GPT support validation for Windows $vmname completed successfully."
                                    Write-Output $messagetxt
                                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                                }
                            } else {
                                $commandId = "RunPowerShellScript"
                                $scriptString = "MBR2GPT /validate /allowFullOS"
                                $paramInvokeAzVMRunCommand = @{
                                    ResourceGroupName = $vmResourceGroupName
                                    VMName            = $vmName
                                    CommandId         = $commandId
                                    ScriptString      = $scriptString
                                    ErrorAction       = 'Stop'
                                }
                                $mbrtogptValidate = Invoke-AzVMRunCommand @paramInvokeAzVMRunCommand
                                # Write-Output $mbrtogptValidate
    
                                if ($mbrtogptValidate.Value[-1].Message -or !($mbrtogptValidate.Value[0].Message)) {
                                    $messagetxt = "MBR to GPT support validation for Windows $vmname failed. Terminating script execution."
                                    Write-Error $messagetxt
                                    Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Validation"
                                    Set-ErrorLevel -1    
                                }
                                else {
                                    $messagetxt = "MBR to GPT support validation for Windows $vmname completed successfully."
                                    Write-Output $messagetxt
                                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Validation"
                                }
                            }
                        }
                    }
                }
            }
            catch [System.Exception] {
                $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Validation"
                Set-ErrorLevel -1
                exit $ERRORLEVEL
            }
        }
        #endregion

        #region - MBR to GPT conversion
        if ($ERRORLEVEL -eq 0) {
            try {
                if ($gen2Vm -eq $false) {
                    if ($currentOsDiskConfig.osType -eq "Linux") {
                        $messageTxt = "Assuming MBR to GPT conversion has been completed as per documented pre-requisites. Proceeding with Trusted launch upgrade."
                        Write-Warning $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "MBR-GPT-Execution"
                        # $commandId = "RunShellScript"
                        # switch ($currentOs.OsName) {
                        #     "Ubuntu" {
                        #         $scriptString = "gdisk /dev/sda \
                        #                         partprobe /dev/sda \
                        #                         grub-install /dev/sda"
                        #     }
                        #     default {
                        #         $scriptString = "gdisk /dev/sda \
                        #                         partprobe /dev/sda \
                        #                         grub2-install /dev/sda"
                        #     }
                        # }
                    }
                    else {
                        $messageTxt = "Executing MBR to GPT conversion on $vmname"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                        if ($useSignedScript -eq $true) {
                            $messageTxt = "Using signed script for executing MBR to GPT validation"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"

                            $messageTxt = "Creating container gen1log in storage account $outputStorageAccountName"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                            $ctx = New-AzStorageContext -StorageAccountName $outputStorageAccountName -UseConnectedAccount -erroraction 'stop'
                            New-AzStoragecontainer -Name "gen1log" -Context $ctx -ErrorAction 'SilentlyContinue' | Out-Null

                            $messageTxt = "Generating SAS URL for output file in storage account $outputStorageAccountName"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                            $sasToken = New-AzStorageContainerSASToken -Context $ctx -Name "gen1log" -Permission rawl -StartTime $((Get-Date).AddMinutes(-5)) -ExpiryTime $((Get-Date).AddHours(1)) -ErrorAction 'Stop'
                            $outputBlobSasUri = "https://$outputStorageAccountName.blob.core.windows.net/gen1log/$vmName-mbr2gpt-convert-output.log?" + $sasToken
                            $errorBlobSasUri = "https://$outputStorageAccountName.blob.core.windows.net/gen1log/$vmName-mbr2gpt-convert-error.log?" + $sasToken

                            $messageTxt = "Executing MBR to GPT conversion for $vmName"
                            Write-Output $messageTxt
                            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                            $paramInvokeAzVMRunCommand = @{
                                ResourceGroupName = $vmResourceGroupName
                                VMName            = $vmName
                                Location          = $CurrentVMConfig.location
                                RunCommandName    = [system.string]::Concat($vmName, "-MBR2GPT-Convert")
                                SourceScriptUri   = "https://raw.githubusercontent.com/AjKundnani/Gen1-TrustedLaunch/main/artifacts/Convert-MBRToGPT.ps1"
                                OutputBlobUri     = $outputBlobSasUri
                                ErrorBlobUri      = $errorBlobSasUri
                                ErrorAction       = 'Stop'
                            }
                            Set-AzVMRunCommand @paramInvokeAzVMRunCommand | Out-Null

                            $outputLog = (Get-AzStorageBlobContent -Blob "$vmName-mbr2gpt-convert-output.log" -Container "gen1log" -Context $ctx).ICloudBlob.DownloadText()
                            $errorLog = (Get-AzStorageBlobContent -Blob "$vmName-mbr2gpt-convert-error.log" -Container "gen1log" -Context $ctx).ICloudBlob.DownloadText()

                            if ($errorLog.Length -gt 0 -or $outputLog.Length -eq 0) {
                                $messagetxt = "MBR to GPT support conversion for Windows $vmname failed. Terminating script execution."
                                Write-Error $messagetxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Execution"
                                Set-ErrorLevel -1    
                            }
                            else {
                                Remove-Item -Path "$vmName-mbr2gpt-convert-output.log" -Force -Confirm:$false
                                Remove-Item -Path "$vmName-mbr2gpt-convert-error.log" -Force -Confirm:$false
                                $messagetxt = "MBR to GPT support conversion for Windows $vmname completed successfully."
                                Write-Output $messagetxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                            }
                        } else {
                            $commandId = "RunPowerShellScript"
                            $scriptString = "MBR2GPT /convert /allowFullOS"
                            $paramInvokeAzVMRunCommand = @{
                                ResourceGroupName = $vmResourceGroupName
                                VMName            = $vmName
                                CommandId         = $commandId
                                ScriptString      = $scriptString
                                ErrorAction       = 'Stop'
                            }
                            $mbrtogpt = Invoke-AzVMRunCommand @paramInvokeAzVMRunCommand
                            # Write-Output $mbrtogpt
                            if ($mbrtogpt.Value[-1].Message -or !($mbrtogpt.Value[0].Message)) {
                                $messagetxt = "MBR to GPT conversion for Windows $vmname failed. Terminating script execution."
                                Write-Error $messagetxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Execution"
                                Set-ErrorLevel -1    
                            }
                            else {
                                $messagetxt = "MBR to GPT conversion for Windows $vmname completed successfully."
                                Write-Output $messagetxt
                                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "MBR-GPT-Execution"
                            }
                        }
                    }
                }
            }
            catch [System.Exception] {
                $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "MBR-GPT-Execution"
                Set-ErrorLevel -1
                exit $ERRORLEVEL
            }
        }
        #endregion

        #region - Upgrade VM to Trusted launch
        if ($ERRORLEVEL -eq 0) {
            try {
                if ($tlvm -eq $false) {
                    $messageTxt = "De-allocating $vmname"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Upgrade-AzVM"

                    $paramStopAzVm = @{
                        ResourceGroupName = $vmResourceGroupName
                        Name              = $vmName
                        Force             = $true
                        Confirm           = $false
                        ErrorAction       = 'Stop'
                    }
                    Stop-AzVm @paramStopAzVm | Out-Null

                    $messageTxt = "Updating security type for $vmname to Trusted launch"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Upgrade-AzVM"

                    $paramUpdateAzVm = @{
                        ResourceGroupName = $vmResourceGroupName
                        VM                = $currentVm
                        SecurityType      = 'TrustedLaunch'
                        EnableVtpm        = $true
                        ErrorAction       = 'Stop'
                    }
                    if ($enableSecureBoot -eq $true) {
                        $paramUpdateAzVm.Add('EnableSecureBoot', $true)
                    } 
                    else { $paramUpdateAzVm.Add('EnableSecureBoot', $false) }
                    Update-AzVM @paramUpdateAzVm | Out-Null

                    $messageTxt = "Starting $vmname"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Upgrade-AzVM"

                    $paramStartAzVm = @{
                        ResourceGroupName = $vmResourceGroupName
                        Name              = $vmName
                        ErrorAction       = 'Stop'
                    }
                    Start-AzVM @paramStartAzVm | Out-Null
                }
            }
            catch [System.Exception] {
                $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Upgrade-AzVM"
                Set-ErrorLevel -1
                exit $ERRORLEVEL
            }
        }
        #endregion

        #region - closure
        if ($ERRORLEVEL -eq 0) {
            $messageTxt = "Gen1 to Trusted launch upgrade complete for $vmName."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
        }
        #endregion
    }
    #endregion   
}