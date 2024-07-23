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
        Update-AzConfig -EnableLoginByWam $false -ErrorAction 'Stop'
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

        #region - Check for feature registration
        If ((Get-AzProviderFeature -ProviderNamespace "Microsoft.Compute" -FeatureName "Gen1ToTLMigrationPreview").RegistrationState -ne "Registered") {
            $messageTxt = "Feature Gen1ToTLMigrationPreview is not registered. Registering now."
            Write-Warning $messagetxt
            Register-AzProviderFeature -ProviderNamespace "Microsoft.Compute" -FeatureName "Gen1ToTLMigrationPreview" -ErrorAction 'Stop'

            do {
                $registrationState = (Get-AzProviderFeature -ProviderNamespace "Microsoft.Compute" -FeatureName "Gen1ToTLMigrationPreview").RegistrationState
                $messagetxt = "Registration state: $registrationState"
                Write-Output $messagetxt
                Start-Sleep -Seconds 10
            } while ($registrationState -ne "Registered")
        } else {
            $messagetxt = "Feature Gen1ToTLMigrationPreview is already registered."
            Write-Output $messagetxt
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
                                $errorBlobSasUri = "https://$outputStorageAccountName.blob.core.windows.net/gen1log/$vmName-mbr2gpt-validate-error.log?" + $sasToken
    
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
# SIG # Begin signature block
# MIIoQQYJKoZIhvcNAQcCoIIoMjCCKC4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC2y2ic3DdfE49D
# beLMYjbjDu6H/A04e2Dm65EPC7KHsqCCDYswggYJMIID8aADAgECAhMzAAADhNlo
# fWbMdUuhAAAAAAOEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwNzEzMjM0NTM4WhcNMjQwOTE1MjM0NTM4WjCBiDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IDNyZCBQYXJ0eSBBcHBsaWNhdGlvbiBDb21wb25lbnQwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOcuqjP/XRg6pKFeMaWfpMTgEZTBne4mxd
# XcEiErb/lZ9Yfxgxa8WhOA66XU+usOUDmo6z/WpI3KVFIuf4MrHh76xAL/HypU9b
# H7hvCG40do0YQxmymk+O25zXQ6Z0QKyKhDNU7K79OVWiE/QNRPXDxXj65HTqT2qb
# 5dVzDziesfrFpzzrkHtOzBikEEFl1oZfmZOy3lSeiiaVLwkgaoPpYMDK+WbANGXQ
# LQ6aP5vyWDtknjDP2F9gjp6j+Q67bCBjIs8FpdH2IN6HAvE3X/E4YOIOrZY2JYUz
# 9poFh1rrjkGuM4CT2tzdqhfkB28QOnuhEyJ+AmB3B01oL9ahNSiZAgMBAAGjggFz
# MIIBbzAfBgNVHSUEGDAWBgorBgEEAYI3TBEBBggrBgEFBQcDAzAdBgNVHQ4EFgQU
# HNwWRAxH9Xw4ZX9wXRlFc716vLwwRQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMNMjMxNTIyKzUwMTE0ODAfBgNV
# HSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0Ey
# MDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZF
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQ
# Q0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
# BQADggIBACe+otxvOu3z6TOJ95EbPptRocynVoyom18xquOJSKeqDNItu2pmyVpa
# iZDhPstLyuo0mXyNLPh3TAl+botuUfpFZDOGzgmqWVBrdHQxsu3t++x6Gw0BJfQv
# n/c0/lU/jRTRTAp7S7jAqjqpyMc0yvrrL6xvUNn3rkLkdy2yXDHWpHdEx5JdpJDp
# gn5j1tv3GGdteYdhZlb2HolacViuJSbeMdG5sDDspcw8xY1Ds4FMXq7MYqLYQsr8
# KwXJZ95SboZ09V/5MOwpKGGhle0Bc5nAErdJBNjjaBLBMGDig9OV0Z3ZIfY4jOFl
# eTEsK5LOTQtSaNVD4rbG+QnMsweLag7qVM7z5IeOqE7UY/CfCEksl+hrKc3MBvdc
# yPcJ289x3gRkOH09FIjRIAfFpBDSkPj4HW5LKqNSv3AbFluKx6ZgbNYhwHxQSxDq
# YsTlAjtnbMjYI2RTrSIMjgGYRvfwa57ypyPdlyzm14Q5UNggsWyr1Og+QbQeW6+R
# CG6FuV/nEAYrMgeHlMQBd50aVhTdBeq5CR3Gz6q4aVL7nEdDR6eYuL0U1e4EoL2O
# YBok3y4rBL3r57nLEEZ6xMGAe5eHBPtgcuPw5S/aJDropeu+4BXSi5R/qGktTkbK
# flJMAlfXHL6a64o88h8i8ZZ4HHHM41qxMB52j9bgaCCQFJFlLJPvMIIHejCCBWKg
# AwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYw
# NzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGf
# Qhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRg
# JGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NE
# t13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnn
# Db6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+E
# GvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+t
# GSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxh
# H2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AV
# s70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f
# 7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3D
# KI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9Jaw
# vEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1Ud
# DgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBi
# AEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRy
# LToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3Js
# Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDEx
# XzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDEx
# XzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/
# BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2Nz
# L3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAA
# bwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUA
# A4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+
# vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4H
# Limb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6
# aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiX
# mE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn
# +N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAq
# ZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5h
# YbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/
# RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXm
# r/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMyk
# XcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGgwwghoIAgEB
# MIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNV
# BAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAOE2Wh9Zsx1
# S6EAAAAAA4QwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkE
# MSIEIDIGu9uxv2Nr/m056FbZHgb4HhgTcVRRe25wXGRtB6nvMEQGCisGAQQBgjcC
# AQwxNjA0oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNy
# b3NvZnQuY29tIDANBgkqhkiG9w0BAQEFAASCAQBpjRU3BZGrbtrQBvjAiMeSnnHU
# W6m0Re7QQY+FWakBaG5el/Ti29rw0E5Klg0ldL5KwYBAZrBrv2ZOgLJUu2HYV6EN
# r7za1BgncW72jB/Q2aceygb07BT0DkQg18NEBReWAutVL097kKgqKx5R/khYZxbH
# H4yWjoiARDhYFFYkOC7z0/tsnTvcAtX22GEKsPxz8V9b94oYHoG/fqw5GIqUGY3B
# yDtcQf5OmEbzIM3TkdNko4Jts3oA6U8JCu+1UBiftM9deeCbT4qkdTROKwG1DOpi
# JL00dPWbYKX79/c2N/GMYIMh70HRUQ9QZR/6m0vCJ1z5UCQIKdjq7rKkBFQDoYIX
# lDCCF5AGCisGAQQBgjcDAwExgheAMIIXfAYJKoZIhvcNAQcCoIIXbTCCF2kCAQMx
# DzANBglghkgBZQMEAgEFADCCAVIGCyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEB
# BgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIJnQhgD+qSS1wSULuUMv3qxr
# GZ2l/0qUdCbiuL8sXAQ+AgZmRjONmK0YEzIwMjQwNjA0MDYxNTEyLjUwMVowBIAC
# AfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsT
# Hm5TaGllbGQgVFNTIEVTTjozNzAzLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEeowggcgMIIFCKADAgECAhMzAAAB6pok
# ctVZP2FjAAEAAAHqMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMB4XDTIzMTIwNjE4NDUzMFoXDTI1MDMwNTE4NDUzMFowgcsxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jv
# c29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVT
# TjozNzAzLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALULX/FIPyAH
# 1fsu52ijatZvaSypoXrlC0mRtCmaxzobhuDkw6/pY/+4nhc4m8pf9zW3R6PihYGp
# 0YPpVuNdfhPQp/KVO6WvMq2DGfFmHurW4PQPL/DkbQMkM9vqjFCvPq8xXZnfL1nG
# N9moGcN+oaif/hUMedmF1qzbay9ILkYfLCxDYn3Qwzsvh5xjxOcsjzmRddNURJvT
# 23Eva0cxisH4ocLLTx2zfpqfshw4Z9GaEdsWg9rmib1galUpLzF5PsQDBbtZtcv+
# Wjmn0pFEiMCWwEEcPVN0YG5ysYLdNBdJOn2zsOOS+80W5RrQEqzPpSIIvEkZBJmF
# 3aI4lMR8nV/FiTadjpIIqxX5Wa1XlqI/Nj+xagVjnjb7POsA+vh6Wu+v24HpyL8p
# yL/8Q4RFkRRME9cwT+Jr63yOtPbLe6DXkxIJW6E6w2ua5kXBpEKtEQPTLPhX3CUx
# MYcglbnmI0zcc9UknX285K+sI/2WwRwTBZkhDUULI86eQzV+zvzzR1qEBrlSY+oy
# TlYQrHMM9WnTzVflFDocZVTPpl2BDSNxPn0Qb4IoM9EPqbHyi/MilL+v/AQc8q3m
# Q6FiuPJAddz0ocpNZ9ekBWPVLKq3lfiev4yl65u/438+NAQ+vSJgkONLMmuoguEG
# zmnK1vq/JHwdRUyn6YADiteM7Dja+Qd9AgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQU
# K4FFJaJR5ukXQFTUxMhyiwVuWV4wHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1w
# JTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACiD
# rVZeP37+fFVtfcbfsqC/Kg0Ce67bDcehZmPcfRgJ5Ddv0pJlOFVOFbiIVwesqeEU
# wFtclfi5AjneQ5ZJpYJpXfELOelG3dzj+BKfd287/UY/cwmSkl+CjnoKBL3Ms6I/
# fWR+alR0+p6RlviK8xHoug9vkc2WrRZsGnMVu2xOM2tPJ+qpyoDBzqv30N/ZRBOo
# NrS/PCkDwLGICDYqVs/IzAE49yv2ElPywalf9mEsOHXV1lxtQDNcejVEmitJJ+1V
# r2EtafPEbMQZp89TAuagROKE4YuohCUKm+v3geJqTQarTBjqV25RCOT+XFngTMDD
# 9wYx6TwndB2I1Ly726NiHUHs0uvq3ciCV9JwNXdt1VZ63WK1NSgpVEsiK9EPABPt
# 1EfXcKrfaPYkbkFi79eK1ETxx3NomYNUHNiGU+X1Be8L7qpHwjo0g3/33XhtOr9L
# iDoUXh/V2LFTETiqV9Q8yLEavQW3j9LQ/h/CaGz5YdGfrY8HiPfMIeLEokKxGf0h
# HcTEFApB0yLlq6KoHrFAEANR/4XuFIpl9sDywVIWt4tKqG+P6pRAXzg1zG5rGlsl
# ZWmw7XwgvhBu3jkLP9AxrsSYwY2ftrwwze5NA6VDLS7pz+OrXXWLUmoyNrJNx5Bk
# 0wEwzkQxzkOvmbdPhsOP1ZM0uA/xIV7cSpNpZUw5MIIHcTCCBVmgAwIBAgITMwAA
# ABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAw
# OTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6c
# BwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWN
# E893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8
# OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6O
# U8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6
# BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75x
# qRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrb
# qn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XY
# cz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK
# 12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJR
# XRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnG
# rnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/Bggr
# BgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1Jl
# cG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQM
# HgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud
# IwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0
# dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKG
# Pmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0
# XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEk
# W+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zR
# oZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1
# AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthIS
# EV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4s
# a3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32
# THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMB
# V0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5P
# ndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUx
# UYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi
# 6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6C
# baUFEMFxBmoQtB1VM1izoXBm8qGCA00wggI1AgEBMIH5oYHRpIHOMIHLMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# MzcwMy0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2WiIwoBATAHBgUrDgMCGgMVAInbHtxB+OlGyQnxQYhy04KSYSSPoIGDMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQAC
# BQDqCRSSMCIYDzIwMjQwNjA0MDQyMDM0WhgPMjAyNDA2MDUwNDIwMzRaMHQwOgYK
# KwYBBAGEWQoEATEsMCowCgIFAOoJFJICAQAwBwIBAAICHfMwBwIBAAICE9MwCgIF
# AOoKZhICAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQAC
# AwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEADkBzroFeBUsgf5UD
# 8UOX9ww941iRcjeOeLgjfI9kCnCJpiiprCl3jldKRTTIzD8hCZo3oIPK+HG1RfrF
# 4sw5Hyez1/FZR9m+aW04umNk9WA8ovigTLK5PSSdob693o05gvKfCtXFb/EpIx1L
# wP9tAdKkDPdwYSvv8Dfe+bdZ7qjfpctEpBI1yk/ufafC8ULhLH4OJzTIX24Qj4Se
# TWTn3GLHQvxQhK1gmYGN2O6ASgZBCSNoicekMTcqgVN/WTBBfMIobwfFea/2/yzT
# dAqH1J0n1DCHYL7sc5f8l5dweY7Ui0pbJjXMJ9qoKJ9MD63Kqz9rQdEjCd8sKidi
# jAD+mjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAAB6pokctVZP2FjAAEAAAHqMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIOLqW/O2IE191xQU
# tYWz/xOP1boVZnht3cUkk0YBQoyaMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCB
# vQQgKY+h1eNkNHiLCDSW0sA1cGHkbW4qooi+ryyMp6S4ZngwgZgwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAeqaJHLVWT9hYwABAAAB6jAi
# BCC7WdmDIeLMVqpQuWQj42D5EE3zOQ8yTGATRLIbegXqRDANBgkqhkiG9w0BAQsF
# AASCAgAEChtBsbrMm0f4wBg78Uv4Yf4pTCj/SpcQnVS4GzxSrShNZrzOKo/+XHA9
# bovCyOCKQWNCSUqZ27CWJXXaOJNPCbpg1Fc5Hih8bHjH5g5DYDF8ROXqxZpuiGUE
# WpR0bf/iXoHRtL8AIydOc9BQqjKraUSY6magw1vOXBuDupi1ch4JrUsMFnzTfACI
# 0u2RCxZyPFEn8mSv6Fq2AapPWX7Ld5xyeefwOjy9sEbAPoo2z2uSlkZy0MF7Ylwf
# kUWibxqe+rjs2VEyw6WoXPSJTbdfFNCeH6BgoO7AVCchDCr0Rh7UaJQNkmSc+pkm
# V/PCuEJKn5zGHV/dDZ0eqmBNMH5HUcKDPb6uNWJ7q0JqjfH0AsuPCq3ktYz6NPY6
# QbZBuqkzk/N8aaRKIFxA1JJQIKFhXDT/yJDIPFNOP4pGw9IRVLO/Iu4bFTJqbrky
# 0nhPkk7ek4RDy9s9ZT5t8DKsDRJB8iPQ4VKVh8M2TbhTXwBUwmYdior1n4xFWZTI
# mcvUakyO2GSNwpLp1HeaPgiLr0UXLHs6qJIMD+mV1fAS9E4lt4MEX1/YJcmMf7Y8
# 0hNAFg6FAsDESCeLOCNYOdloq3hZfKRS5h0f+Zsj/3oncsEqs9gWwG5IHGD6UMZE
# /yNkBQwrqX7nqhrnOY8Q9pCmi8bWei1xA5cyYGHP3DYRgm0gVg==
# SIG # End signature block
