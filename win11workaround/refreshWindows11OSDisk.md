# (PREVIEW) Gen1 to Trusted launch upgrade | Windows 11 boot issue.

Post upgrade of Windows 10 Gen1 to Windows 11 Trusted launch, the VM goes into bad boot state potentially due to incorrect boot variables. The script [Refresh-Win11OSDisk](./Refresh-Win11OSDisk.ps1) can be executed to setup new Azure OS disk with content of existing Windows 11 OS disk to fix the required boot variables.

## Pre-Requisites

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
vmName    |    Resource Name of Windows 11 VM in boot error state    |    True
vmResourceGroupName    |    Resource Group for Windows 11 VM to be updated.    |    True
targetOsDiskName    |    Resource name of Windows 11 OS disk.    |    True

**Example**

```azurepowershell
.\Refresh-Win11OSDisk.ps1 -subscriptionId $subscriptionId -tenantDomain contoso.com -vmName win11vm03 -vmResourceGroupName $resourceGroupName -targetOsDiskName win11vm03-os-disk
```

## Post-VM Start Activities

After successful boot of Windows 11 VM. You can delete the original OS disk which was in bad boot state.