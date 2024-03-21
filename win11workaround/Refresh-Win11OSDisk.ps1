<#
.SYNOPSIS
Export and import Windows 11 OS disk to refresh Windows 11 OS Disk boot variables.

.DESCRIPTION
The Windows 11 boot issue post Gen1 to Trusted launch upgrade could be due to boot variable error. Run this script post Windows 11 in-place upgrade to refresh the boot variables for VM.

.EXAMPLE
.\Refresh-Win11OSDisk.ps1 -subscriptionId $subscriptionId -tenantDomain contoso.com -vmName win11vm03 -vmResourceGroupName $resourceGroupName -targetOsDiskName win11vm03-os-disk
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]

param (
    [Parameter(Mandatory = $true, HelpMessage = "Target Azure Subscription Id")]
    [string][ValidateNotNullOrEmpty()]$subscriptionId,
    [Parameter(Mandatory = $true, HelpMessage = "Azure Tenant domain if conversion executed in Azure")]
    [string][ValidateNotNullOrEmpty()]$tenantDomain,
    [Parameter(Mandatory = $true, HelpMessage = "Name of Windows 11 VM")]
    [string][ValidateNotNullOrEmpty()]$vmName,
    [Parameter(Mandatory = $true, HelpMessage = "Windows 11 VM resource group")]
    [string][ValidateNotNullOrEmpty()]$vmResourceGroupName,
    [Parameter(Mandatory = $true, HelpMessage = "Name of new Windows 11 OS disk.")]
    [string][ValidateNotNullOrEmpty()]$targetOsDiskName
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
            } else {
                $messagetxt = "Module $($azModule.ModuleName)  is available, but its version is lower than the minimum version $($azModule.Version). Upgrading module on local machine."
                Write-warning $messageTxt
                Update-Module $($azModule.ModuleName) -ErrorAction 'Stop' -Confirm:$false -Force
            }
        } else {
            $messagetxt = "Module $($azModule.ModuleName) is not available, proceeding with $($azModule.ModuleName) install."
            Write-warning $messageTxt
            Install-Module -Name $($azModule.ModuleName) -Repository PSGallery -Force -Confirm:$false -ErrorAction 'Stop'
        }
    }

    $workingDirectory = $env:USERPROFILE
    If ((Test-Path "$workingDirectory\azCopy.zip") -eq $true) {
        $messageTxt = "azCopy zip already downloaded"
        Write-Output $messageTxt
    } else {
        $messageTxt = "Downloading AzCopy"
        Write-Output $messageTxt

        Start-BitsTransfer https://aka.ms/downloadazcopy-v10-windows -Destination "$workingDirectory\azCopy.zip" -Priority High
    }

    if ((Test-Path "$workingDirectory\azCopy.zip") -eq $true) {
        If ((Test-Path "$workingDirectory\azCopy\") -eq $true) {
            $messageTxt = "azCopy already setup"
            Write-Output $messageTxt
        } else {
            $messageTxt = "Unzipping AzCopy"
            Write-Output $messageTxt
            Expand-Archive -Path $workingDirectory\azCopy.zip -DestinationPath $workingDirectory\azCopy\ -ErrorAction 'Stop' -Force
        }
        $azCopyDir = (Get-ChildItem -Path $workingDirectory\azCopy\ | Where-Object {$psitem.Name -like "azcopy_windows*"}).Name
        $azCopyDir = "$workingDirectory\azCopy\$azCopyDir\"
        $env:AZCOPY_LOG_LOCATION = $logDirectory
        
        $messageTxt = "Setting up location of azcopy to $azCopyDir"
        Write-Output $messageTxt
    } else {
        $messageTxt = "Error in Downloading AZCOPY to $workingDirectory\azCopy.zip"
        Write-Error $messageTxt
        Set-ErrorLevel -1
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

#region - Current VM Configuration
if ($ERRORLEVEL -eq 0) {
    try {
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
            securityType    = $currentVm.SecurityProfile.SecurityType
            location        = $currentVm.Location
        }
        if ($currentvm.Zones.Count -gt 0) {
            $messageTxt = "Availability zone detected for $vmName under $vmResourceGroupName"
            Write-Output $messageTxt
            $CurrentVMConfig.Add('zone', $currentVm.Zones[0])
        } else {
            $messageTxt = "No availability zone detected for $vmName under $vmResourceGroupName"
            Write-Warning $messageTxt
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
            disklength  = $currentOsDisk.DiskSizeBytes
        }

        if ($currentOsDiskConfig.HyperVGen -eq "V2" -and $currentOsDiskConfig.osType -eq "Windows") {
            $messagetxt = "Proceeding with export and import for OS disk of $($vmName)"
            Write-Output $messagetxt
        } else {
            $messagetxt = "OS disk is does not seems related to Windows 11 upgrade issue. Proceeding."
            Write-Warning $messagetxt
        }
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - Main script
if ($ERRORLEVEL -eq 0) {
    try {
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

        $messageTxt = "Setting up new disk config"
        Write-Output $messageTxt
        $newDiskConfigParam = @{
            Location            = $CurrentVMConfig.location
            OsType              = $CurrentVMConfig.osdisk.OsType
            CreateOption        = 'Upload'
            UploadSizeInBytes   = $($currentOsDiskConfig.disklength+512)
            HyperVGeneration    = 'v2'
            EncryptionType      = $currentOsDiskConfig.encryption.Type
            SkuName             = $currentOsDiskConfig.sku
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
    
        $gen2diskConfig = New-AzDiskConfig @newDiskConfigParam
        $messageTxt = "Adding trusted launch disk configuration"
        Write-Output $messageTxt
        Set-AzDiskSecurityProfile -Disk $gen2diskConfig -SecurityType "TrustedLaunch" -ErrorAction 'Stop' | Out-Null

        $messageTxt = "Setting up new disk $targetOsDiskName under $vmResourceGroupName"
        Write-Output $messageTxt
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
            Start-Sleep -Seconds 3
            $gen2OsDisk = Get-AzDisk -ResourceGroupName $vmResourceGroupName -DiskName $gen2OsDisk.Name -ErrorAction 'SilentlyContinue'
        }

        $messageTxt = "Generating Upload URL for $targetOsDiskName"
        Write-Output $messageTxt
        $gen2diskSas = (Grant-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $targetOsDiskName -DurationInSecond 86400 -Access 'Write' -ErrorAction 'Stop').AccessSAS

        $messageTxt = "Generating Download URL of $($currentOsDisk.Name) valid for 12 hours."
        Write-Output $messageTxt
        $downloadDiskSas = (Grant-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -Access 'Read' -DurationInSecond 45000).AccessSAS

        $messageTxt = "Copying OS disk $($currentOsDisk.Name) to $targetOsDiskName"
        Write-Output $messageTxt
        Set-Location $azCopyDir
        .\azcopy copy $downloadDiskSas $gen2diskSas --blob-type PageBlob

        $messageTxt = "Revoking Upload URL"
        Write-Output $messageTxt
        Revoke-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $targetOsDiskName -ErrorAction 'Stop' | Out-Null

        $messageTxt = "Revoking download URL"
        Write-Output $messageTxt
        Revoke-AzDiskAccess -ResourceGroupName $vmResourceGroupName -DiskName $($CurrentVMConfig.osdisk.Name) -ErrorAction 'Stop' | Out-Null

        $messageTxt = "Set the VM configuration to point to the new disk $($gen2OsDisk.Name)"
        Write-Output $messageTxt

        Set-AzVMOSDisk -VM $currentVm -ManagedDiskId $gen2OsDisk.Id -Name $gen2OsDisk.Name -ErrorAction 'Stop' | Out-Null

        $messageTxt = "Update the VM with the new OS disk and Gen2-Trusted launch configuration"
        Write-Output $messageTxt

        $paramUpdateAzVm = @{
            ResourceGroupName   = $vmResourceGroupName
            VM                  = $currentVm
            ErrorAction         = 'Stop'
        }
        Update-AzVM @paramUpdateAzVm | Out-Null

        $messageTxt = "Starting $vmname"
        Write-Output $messageTxt

        $paramStartAzVm = @{
            ResourceGroupName   = $vmResourceGroupName
            Name                = $vmName
            ErrorAction         = 'Stop'
        }
        Start-AzVM @paramStartAzVm | Out-Null
    } catch [System.Exception] {
        $messageTxt = 'Error Exception Occurred' + "`n$($psitem.Exception.Message)" + "`nError Caused By: $(($psitem.InvocationInfo.Line).Trim())"
        Write-Output $messageTxt
        Set-ErrorLevel -1
        exit $ERRORLEVEL
    }
}
#endregion

#region - closure
if ($ERRORLEVEL -eq 0) {
    $messageTxt = "Windows 11 OS disk refresh is complete. You can delete the previous OS disk $($currentOsDisk.Name) under resource group $($currentOsDisk.ResourceGroupName)"
    Write-Output $messageTxt
}
#endregion