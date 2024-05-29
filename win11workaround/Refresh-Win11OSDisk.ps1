<#
.SYNOPSIS
Export and import Windows 11 OS disk to refresh Windows 11 OS Disk boot variables.
Script Version: 2.0.1

.DESCRIPTION
The Windows 11 boot issue post Gen1 to Trusted launch upgrade could be due to boot variable error. Run this script post Windows 11 in-place upgrade to refresh the boot variables for VM.

.PARAMETER subscriptionId
Subscription ID for Windows 11 Trusted launch VM VM.

.PARAMETER tenantDomain
Primary AAD Domain Name for authentication. (For example, contoso.onmicrosoft.com)

.PARAMETER csvLocation
Local file path location of csv containing vmName, vmResourceGroupName, refreshOsDiskName details.

.PARAMETER batchSize
Number of machines which should be processed in parallel. Default set to 5.

.PARAMETER useCloudshell
Use cloud shell in Azure Portal for script execution.

.PARAMETER vmName
(Csv input parameter) Resource Name of Windows 11 Trusted launch VM to be fixed.

.PARAMETER vmResourceGroupName
(Csv input parameter) Resource Group for Windows 11 Trusted launch VM.

.PARAMETER refreshOsDiskName
(Csv input parameter) New OS disk name to be created for Windows 11 Trusted launch VM.

.EXAMPLE
.\Refresh-Win11OSDisk.ps1 -subscriptionId $subscriptionId -tenantDomain contoso.onmicrosoft.com -csvLocation "C:\sample.csv"
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]

param (
    [Parameter(Mandatory = $true, HelpMessage = "Target Azure Subscription Id")]
    [string][ValidateNotNullOrEmpty()]$subscriptionId,
    [Parameter(Mandatory = $true, HelpMessage = "Azure Tenant domain if conversion executed in Azure")]
    [string][ValidateNotNullOrEmpty()]$tenantDomain,
    [Parameter(Mandatory = $true, HelpMessage = "Location of csv containing Gen1 VM(s) details - vmName, vmResourceGroupName, targetOsDiskName.")]
    [string][ValidateNotNullOrEmpty()]$csvLocation,
    [Parameter(Mandatory = $false, HelpMessage = "Number of machines which should be processed in parallel. Default set to 5.")]
    [int][ValidateNotNullOrEmpty()]$batchSize,
    [Parameter(Mandatory = $false, HelpMessage = "Use cloud shell in Azure Portal for script execution.")]
    [switch]$useCloudshell
)

#region - Validate Pre-Requisites
New-Variable -Name 'ERRORLEVEL' -Value 0 -Scope Script -Force
try {
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion.Major -gt 7 -or ($PSVersion.Major -eq 7 -and $PSVersion.Minor -gt 2)) {
        $messagetxt = "PowerShell version is greater than 7.2"
        Write-Output $messageTxt
    } else {
        $messagetxt = "PowerShell version is not greater than 7.2 and does not meets requirements."
        Write-Error $messagetxt
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
        }
    )

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
    If ((Test-Path "$workingDirectory\azCopy.zip") -eq $true -or $useCloudshell) {
        $messageTxt = "azCopy zip already downloaded"
        Write-Output $messageTxt
    }
    else {
        $messageTxt = "Downloading AzCopy"
        Write-Output $messageTxt
        Start-BitsTransfer https://aka.ms/downloadazcopy-v10-windows -Destination "$workingDirectory\azCopy.zip" -Priority High
    }

    if ((Test-Path "$workingDirectory\azCopy.zip") -eq $true -or $useCloudshell) {
        If ((Test-Path "$workingDirectory\azCopy\") -eq $true -or $useCloudshell) {
            $messageTxt = "azCopy already setup"
            Write-Output $messageTxt
        }
        else {
            $messageTxt = "Unzipping AzCopy"
            Write-Output $messageTxt
            Expand-Archive -Path $workingDirectory\azCopy.zip -DestinationPath $workingDirectory\azCopy\ -ErrorAction 'Stop' -Force
        }
        
        if (!($useCloudshell)) {
            $messageTxt = "Setting up location of azcopy to $azCopyDir"
            Write-Output $messageTxt
            $azCopyDir = (Get-ChildItem -Path $workingDirectory\azCopy\ | Where-Object { $psitem.Name -like "azcopy_windows*" }).Name
            $azCopyDir = "$workingDirectory\azCopy\$azCopyDir\"
            $env:AZCOPY_LOG_LOCATION = $azCopyDir
        }
    }
    else {
        $messageTxt = "Error in Downloading AZCOPY to $workingDirectory\azCopy.zip"
        Write-Error $messageTxt
        Set-Variable -Name ERRORLEVEL -Value -1 -Scope Script -Force
    }
}
catch [system.exception] {
    $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
    Write-Output $messageTxt
    [int]$script:ERRORLEVEL = -1
}
#endregion

#region - Connect Azure Subscription
If ($ERRORLEVEL -eq 0) {
    try {
        $messageTxt = "Connecting to Subscription $subscriptionId under $tenantDomain"
        Write-Output $messageTxt
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

#region - Main script
if ($ERRORLEVEL -eq 0) {
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
    }
    $importVmArray | ForEach-Object -ThrottleLimit $batchSize -Parallel  {
        try {
            $importVm = $_
            $vmName = $importVm.vmName
            $vmResourceGroupName = $importVm.vmResourceGroupName
            $targetOsDiskName = $importVm.refreshOsDiskName
            $subscriptionId = $importVm.subscriptionId
            $tenantDomain = $importVm.tenantDomain
            $useCloudshell = $importVm.useCloudShell
            if ($useCloudshell -eq $true) {
                $workingDirectory = [system.string]::concat((Get-Location).Path, "/Gen1-TrustedLaunch-Upgrade")
            } else {
                $workingDirectory = "$env:UserProfile\Gen1-TrustedLaunch-Upgrade"
                $azCopyDir = (Get-ChildItem -Path $workingDirectory\azCopy\ | Where-Object { $psitem.Name -like "azcopy_windows*" }).Name
                $azCopyDir = "$workingDirectory\azCopy\$azCopyDir\"
                $env:AZCOPY_LOG_LOCATION = $azCopyDir
            }
    
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
                    $script:logFile = "$logDirectory\$($vmName)-Refresh-Win11-OSDisk-" + $logStamp + '.log'
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

            Write-InitLog -logDirectory $workingDirectory -vmName $vmName
            $messageTxt = "Script Version: 2.0.1"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"
            Set-Errorlevel 0 | Out-Null
            Get-Errorlevel | Out-Null

            $inputParam = @{
                'VM name' = $vmName
                'Target OS Disk Name' = $targetOsDiskName
                'Resource group name' = $vmResourceGroupName
                'Subscription ID' = $subscriptionId
                'Tenant Domain' = $tenantDomain
                'Use Cloud Shell' = $useCloudshell
            }
            $messageTxt = $inputParam.GetEnumerator() | ForEach-Object {"$($PSItem.Key) = $($PSItem.Value)"}
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Setup-PreRequisites"

            #region - Connect Azure Subscription
            If ($ERRORLEVEL -eq 0) {
                try {
                    $messageTxt = "Connecting to Subscription $subscriptionId under $tenantDomain"
                    Write-Output $messageTxt
                    Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Connect-AzSubscription"
                    #region - Enable-AzAccount()
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
            if ($ERRORLEVEL -eq 0) {
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
                        securityType = $currentVm.SecurityProfile.SecurityType
                        location     = $currentVm.Location
                    }
                    if ($currentvm.Zones.Count -gt 0) {
                        $messageTxt = "Availability zone detected for $vmName under $vmResourceGroupName"
                        Write-Output $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
                        $CurrentVMConfig.Add('zone', $currentVm.Zones[0])
                    }
                    else {
                        $messageTxt = "No availability zone detected for $vmName under $vmResourceGroupName"
                        Write-Warning $messageTxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Get-AzVM"
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
                        disklength = $currentOsDisk.DiskSizeBytes
                    }
    
                    if ($currentOsDiskConfig.HyperVGen -eq "V2" -and $currentOsDiskConfig.osType -eq "Windows") {
                        $messagetxt = "Proceeding with export and import for OS disk of $($vmName)"
                        Write-Output $messagetxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Get-AzVM"
                    }
                    else {
                        $messagetxt = "OS disk is does not seems related to Windows 11 upgrade issue. Proceeding."
                        Write-Warning $messagetxt
                        Write-LogEntry -logMessage $messageTxt -logSeverity 2 -logComponent "Get-AzVM"
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
    
            #region - Setup new Azure OS Disk
            $messageTxt = "De-allocating $vmname"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Stop-AzVM"
    
            $paramStopAzVm = @{
                ResourceGroupName = $vmResourceGroupName
                Name              = $vmName
                Force             = $true
                Confirm           = $false
                ErrorAction       = 'Stop'
            }
            Stop-AzVm @paramStopAzVm | Out-Null
    
            $messageTxt = "Setting up new disk config"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"

            $newDiskConfigParam = @{
                Location          = $CurrentVMConfig.location
                OsType            = $CurrentVMConfig.osdisk.OsType
                CreateOption      = 'Upload'
                UploadSizeInBytes = $($currentOsDiskConfig.disklength + 512)
                HyperVGeneration  = 'v2'
                EncryptionType    = $currentOsDiskConfig.encryption.Type
                SkuName           = $currentOsDiskConfig.sku
                ErrorAction       = 'Stop'
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
                DiskName          = $targetOsDiskName
                Disk              = $gen2diskConfig
                ErrorAction       = 'Stop'
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
            #endregion
            
            #region - Copy OS Disk
            $messageTxt = "Generating Upload URL for $targetOsDiskName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            $gen2diskSas = (Grant-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $targetOsDiskName -DurationInSecond 86400 -Access 'Write' -ErrorAction 'Stop').AccessSAS
    
            $messageTxt = "Generating Download URL of $($currentOsDisk.Name) valid for 12 hours."
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            $downloadDiskSas = (Grant-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -Access 'Read' -DurationInSecond 45000).AccessSAS
    
            $messageTxt = "Copying OS disk $($currentOsDisk.Name) to $targetOsDiskName"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            if ($useCloudshell -eq $true) {azcopy copy $downloadDiskSas $gen2diskSas --blob-type PageBlob}
            else {
                Set-Location $azCopyDir
                .\azcopy copy $downloadDiskSas $gen2diskSas --blob-type PageBlob
            }
    
            $messageTxt = "Revoking Upload URL for $($targetOsDiskName)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            Revoke-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $targetOsDiskName -ErrorAction 'Stop' | Out-Null
    
            $messageTxt = "Revoking download URL for $($CurrentVMConfig.osdisk.Name)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "New-AzDisk"
            Revoke-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -ErrorAction 'Stop' | Out-Null
            #endregion

            #region - Update VM Configuration
            $messageTxt = "Set the VM configuration to point to the new disk $($gen2OsDisk.Name)"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
    
            Set-AzVMOSDisk -VM $currentVm -ManagedDiskId $gen2OsDisk.Id -Name $gen2OsDisk.Name -ErrorAction 'Stop' | Out-Null
    
            $messageTxt = "Update the VM $vmName with the new OS disk and Gen2-Trusted launch configuration"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Update-AzVM"
    
            $paramUpdateAzVm = @{
                ResourceGroupName = $vmResourceGroupName
                VM                = $currentVm
                ErrorAction       = 'Stop'
            }
            Update-AzVM @paramUpdateAzVm | Out-Null
    
            $messageTxt = "Starting $vmname"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Start-AzVM"
    
            $paramStartAzVm = @{
                ResourceGroupName = $vmResourceGroupName
                Name              = $vmName
                ErrorAction       = 'Stop'
            }
            Start-AzVM @paramStartAzVm | Out-Null
            #endregion

            #region - closure
            if ($ERRORLEVEL -eq 0) {
                $messageTxt = "Windows 11 OS disk refresh is complete for $vmName. You can delete the previous OS disk $($currentOsDisk.Name) under resource group $($currentOsDisk.ResourceGroupName)"
                Write-Output $messageTxt
                Write-LogEntry -logMessage $messageTxt -logSeverity 3 -logComponent "Refresh-Win11OSDisk"
            }
            #endregion
        }
        catch [System.Exception] {
            $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
            Write-Output $messageTxt
            Write-LogEntry -logMessage $messageTxt -logSeverity 1 -logComponent "Update-AzVM"
            Set-ErrorLevel -1
            exit $ERRORLEVEL
        }
    }   
}
#endregion