# (PREVIEW) Gen1 to Trusted launch upgrade | Windows 11 boot issue.

Post upgrade of Windows 10 Gen1 to Windows 11 Trusted launch, the VM goes into bad boot state potentially due to incorrect boot variables. The script [Refresh-Win11OSDisk](./Refresh-Win11OSDisk.ps1) can be executed to setup new Azure OS disk with content of existing Windows 11 OS disk to fix the required boot variables.

## Pre-Requisites

- PowerShell client 7.2 or above.
- Az Modules - Az.Accounts, Az.Compute, Az.Storage
- Windows 10 Gen1 to Windows 11 Trusted launch upgrade is complete and Windows 11 VM is in bad boot state.
- OS disk is NOT [restricted for import/export](https://learn.microsoft.com/azure/virtual-machines/disks-restrict-import-export-overview).

## High-Level Script Workflow

Id    |    Step    |    Description
-|-|-
1    |    Validate Pre-Requisites    |    Validate pre-requisites for executing script:<ul><li>Az.Account, Az.Compute PowerShell modules<li>AzCopy for Windows 10</li></ul>
2    |    Connect Azure Subscription and read Windows 11 VM Configuration    |    Store Windows 11 VM Configuration required for OS disk refresh:<ul><li>OS Disk Metadata<li>VM Location<li>Availability Zone</li></ul>
3    |    De-Allocate Windows 11 VM and copy OS disk to new Azure OS disk    |    Script will setup new Azure OS disk using existing OS disk configuration and copy the existing Windows 11 OS disk content to new disk using `azcopy` cmdlet. This operation can take 15-20 minutes to complete.
4    |    Swap OS Disk and start Windows 11 VM    |    OS Disk is swapped with new copied OS disk. VM is started.

## Script execution

Parameter Name    |    Description    |    Mandatory
-|-|-
subscriptionId    |    Subscription ID for Windows VM to be updated.    |    True
tenantDomain    |    Primary AAD Domain Name for authentication. (For example, contoso.onmicrosoft.com)    |    True
csvLocation    |    Local file path location of csv containing vmName, vmResourceGroupName, refreshOsDiskName details. (Refer to [sampleCsv](../artifacts/sampleCsv.csv) for schema details.)    |    True
batchSize      |    Number of machines which should be processed in parallel. Default set to 5.    |    False
useCloudShell    |    Use cloud shell in Azure Portal for script execution.    |    False

Csv column Name    |    Description    |    Mandatory
-|-|-
vmName    |    Resource Name of Windows 11 VM to be updated.    |    True
vmResourceGroupName    |    Resource Group for Windows 11 VM to be updated.   |    True
refreshOsDiskName    |    New OS disk name to be created for Windows 11 Trusted launch VM.  |    True

**Example**

```azurepowershell
.\Refresh-Win11OSDisk.ps1 -subscriptionId $subscriptionId -tenantDomain contoso.onmicrosoft.com -csvLocation "C:\sample.csv"
```

## Post-VM Start Activities

After successful boot of Windows 11 VM. You can delete the original OS disk which was in bad boot state.

## Troubleshooting

Share the log files available under folder `Gen1-Trustedlaunch-Upgrade` at `%userprofile%` with feature team to troubleshoot Gen1 to Trusted launch upgrade.
