# (PREVIEW) Azure Gen1 to Gen2 Trusted Launch VM Conversion Script

[Azure Generation 2 (Gen2) VM](https://learn.microsoft.com/en-us/azure/virtual-machines/generation-2) is based on UEFI-based boot architecture which enables key scenarios including [Trusted Launch (TLVM)](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch). Gen2 TLVM provides customers with secure compute solutions with security capabilities like:

Feature Name    |    Description
-|-
Secure Boot    |    Protects OS against rootkits and boot kits.
vTPM    |    It serves as a dedicated secure vault for keys and measurements, enabling attestation by measuring the entire boot chain of your VM
Guest VM Attestation    |    Guest attestation extension enables proactive attestation and monitoring the boot integrity of your VMs.

Newer OS like Windows Server 2022 Azure Edition require UEFI, Windows 11 requires UEFI & vTPM as pre-requisite for installation. Additionally, for enabling [Azure Compute security benchmark](https://learn.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows#secured-core) (like Secure Boot), UEFI support in OS is mandatory.

This repository provides end users with PowerShell script-based guidance which they can self-execute & convert existing Gen1 (BIOS) Windows VMs to Gen2 (UEFI) Windows VMs.

## Pre-Requisites

Pre-Requisite    |    Description
-|-
Windows 10 Virtual Machine in same region & zone (if applicable) as target Gen1 VM.<br/>**Note** Windows 10 VM should be up-to date (v22H2) with [KB4023057](https://support.microsoft.com/en-us/topic/kb4023057-update-for-windows-update-service-components-fccad0ca-dc10-2e46-9ed1-7e392450fb3a) installed.   |    This VM will be used to download -> convert -> upload the target Gen1 VM OS Disk.<br/> Placing the VM in same region & zone will reduce network latency.
[MBR2GPT](https://learn.microsoft.com/en-us/windows/deployment/mbr-to-gpt)    |    In-Built utility available with Windows 10/11 OS.
[Az PowerShell Module 8.0.0+](https://learn.microsoft.com/en-us/powershell/azure/what-is-azure-powershell?view=azps-8.3.0)    |    Required cmdlets for Azure Platform.
[AzCopy](https://learn.microsoft.com/en-us/azure/storage/common/storage-ref-azcopy)    |    Download & Upload target Gen1 VM OS Disk.
VM Contributor rights on Gen1 VM resource group.    |    Required RBAC permissions to modify and re-deploy Gen1 VM.
Gen1 VM is in allocated / Running state.    |    Required to read current state and configuration of Gen1 VM.
Gen1 Operating System    |    The following Operating Systems are supported for conversion:<ul><li>Windows Server 2012 R2<li>Windows Server 2016<li>Windows Server 2019<li>Windows 8.1<li>Windows 10</ul>
**Backup** Gen1 VM    |    As a best practice, ensure you have full backup taken for Gen1 VM before executing conversion which can be used to roll-back if needed.
Storage (premium recommended) on Windows 10 Virtual Machine    |    OS Disk of Gen1 VM will be downloaded locally on Windows 10 workstation, adequate disk storage should be available to support download & conversion of OS disk. (Ideally >1.5 * Gen1 OS Disk Size). <br/> Premium Disk will provide better IOPS for higher download / upload speed.

## High-Level Conversion Workflow

Id    |    Step    |    Description
-|-|-
1    |    Validate Pre-Requisites    |    Validate pre-requisites for executing script:<ul><li>Az.Account, Az.Compute PowerShell modules<li>MBR2GPT Utility<li>AzCopy for Windows 10</li></uk>
2    |    Connect Azure Subscription and read Gen1 VM Configuration    |    Store Gen1 VM Configuration required for conversion:<ul><li>OS Disk Metadata<li>VM Size<li>Image Reference<li>Data Disk(s) Metadata<li>VM Location<li>NIC(s) Resource ID<li>Availability Zone</li></ul>
3    |    Validate VM SKU Gen2 Support and local disk to support OS Disk download.    |    Validate if current VM Size assigned to Gen1 VM supports Gen2. If not, VM Size for Gen1 VM will need to be updated with [Gen2 support](https://learn.microsoft.com/en-us/azure/virtual-machines/generation-2).<br/>For steps of changing VM Size, please refer to [Change the size of a Virtual Machine](https://learn.microsoft.com/en-us/azure/virtual-machines/resize-vm?tabs=portal).
4    |    De-Allocate Gen1 VM and download OS Disk VHD locally.    |    Downloaded OS disk boot partition will be converted from MBR to GPT using MBR2GPT Utility.<br/>Time taken for download is dependent on disk size and network throughput.<br/>Assuming script is executed in same region as Gen1 VM, and OS Disk size of 128GB, download can take ~35-40 minutes to complete.<br/>**NOTE**: If Public IP is set to type `Dynamic`, the IP will get released with de-allocation of VM. If workload has dependency on Public IP, change the IP Type to `Static` before executing script.
5    |    Mount VHD and convert boot partition from MBR to GPT.    |    This step is applicable for Windows OS only.<br/> For Linux, disk should be converted using `gdisk`, refer to steps listed under heading [MBR to GPT Conversion - Azure Linux](#mbr-to-gpt-conversion---azure-linux).
6    |    Upload converted VHD and create new Azure disk.    |    GPT converted Azure disk will be used to create new Gen2 VM using existing OS disk.<br/>Time taken for upload is dependent on disk size and network throughput.<br/>Assuming script is executed in same region as Gen2 TLVM, and OS Disk size of 128GB, upload can take ~20-30 minutes to complete.
7    |    Swap OS Disk and upgrades Gen1 VM to Trusted launch.    |    OS Disk is swapped with converted and uploaded disk. VM is updated to Trusted launch VM and started.

## MBR to GPT Conversion - Azure Linux

Execute these steps on Azure Linux Gen1 VM to complete MBR to GPT conversion before executing Gen1 -> Trusted Launch upgrade script.

**Note**: These steps are applicable for Azure Linux VMs only, i.e., Linux VMs created in Azure cloud. These do not apply if the Linux VM has been created outside Azure (like on-premises).

Id    |    Step    |    Description
-|-|-
1    |    Query the OS Disk using below command<br/> `lsblk -o NAME,HCTL,SIZE,MOUNTPOINT \| grep -i "sd"` | Identify the boot partition and associated disk
2    |    Backup MBR partition:<br/>`dd if=/dev/sda of=backup.mbr bs=512 count=1`    |    Backup should be taken on drive other than Boot drive.
3    |    Execute gdisk command `gdisk /dev/sda`to create new partition with following values:<br/><ul><li>Command: **n**<li>Partition Number: `default`<li>First Sector: **34**<li>Last Sector: **2047**<li>partition type **ef02**<li>Command: **w** to write the changes</ul>    |    ![Gdisk Execution](./.attachments/gdisk.png)
4    |    Update partition table changes:`partprobe /dev/sda`    |    
5    |    Install Bootloader in re-partitioned boot disk:<ul><li>**For Ubuntu**: `grub-install /dev/sda`<li>**For RHEL & SLES** `grub2-install /dev/sda`</ul>    |    ![grub execute](./.attachments/grubinstall.png)
6    |    Execute `ConvertGen1ToTLVM.ps1` script to complete Gen1 -> Trusted Launch upgrade.<br/>**Note**: M-Series VMs currently do not support Trusted Launch, use parameter `-DisableTrustedLaunch` to skip TL configuration.    |    
7    |    Validate bootloader: `if test -d /sys/firmware/efi; then echo efi; else echo bios; fi`    |    Expected Response: **efi**


## Post-Conversion Activities

After successful conversion of Gen1 to Trusted Launch VM, user needs to perform required steps for applicable scenarios from below list:

1. Validate health of Virtual Machine OS and workload hosted on converted Gen2 TLVM.

## Roll-Back

Script will make best efforts to roll-back and restore the Gen1 VM configuration.

In case script-based roll-back does not work as expected, please restore VM using the full backup taken as part of pre-requisites.

## Known Issues

### Cannot find OS partition(s) for disk n

This error is generated by `MBR2GPT` utility. Error is majorly caused by corrupt `BCD` store of OS partition.

More details on resolution of this error will be published.

### Current selected volume will not support download of OS VHD. Please change the working directory location

This error is caused when working directory is the root drive volume. To resolve this issue, please create a folder under the drive and use the folder path as working directory.

### Cannot find room for the EFI system partition

This error occurs for one of following reason:

- If you execute MBR2GPT utility from OS other than Windows 10.
- There is no free space available on the system volume.
- System volume is corrupted. You can validate by trying to **Shrink Volume** by few MBs under Disk Management console. Use command `chkdsk C:/v/f` to repair system volume.

### FatalError [0x090001] PANTHR Exception (code 0x80000003: BREAKPOINT) occurred

This error is caused on Windows 10 VM due to absence of [KB4023057](https://support.microsoft.com/en-us/topic/kb4023057-update-for-windows-update-service-components-fccad0ca-dc10-2e46-9ed1-7e392450fb3a).
To resolve this error, install all available updates on Windows 10 machine.

### D Drive assigned to System Reserved Post conversion

Temporary storage Drive letter assignment 'D' is changed to 'E' with previous letter assigned to System Reserved post-conversion.
The issue is being troubleshooted. execute below steps manually post-conversion to workaround the issue:

After the conversion check the disks on the server, if `system reserved` partition has the letter D:, do the following actions:

1. reconfigure pagefile from D: to C:
2. reboot the server
3. remove letter D: from the partition
4. reboot the server to show the temporary storage disk with D: letter

### FindOSPartitions: Cannot get volume name for the default boot entry

MBR2GPT utility reports above error when it's unable to locate EFI boot data on Gen1 OS Disk VHD. To resolve this issue, run below command on mounted VHD to copy EFI boot data before executing conversion.
`.\bcdboot.exe G:\Windows\ /f bios /s G:`

You can set the breakpoint before below line in script to pause conversion:
`$mbr2gpt = .\MBR2GPT.exe /disk:$($mountDisk.Number) /convert /allowFullOS /logs:$logDirectory`