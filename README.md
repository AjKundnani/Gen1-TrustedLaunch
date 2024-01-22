# (PREVIEW) Azure Gen1 to Gen2 Trusted Launch VM Upgrade

[Azure Generation 2 (Gen2) VM](https://learn.microsoft.com/azure/virtual-machines/generation-2) is based on UEFI-based boot architecture which enables key scenarios including [Trusted Launch (TLVM)](https://learn.microsoft.com/azure/virtual-machines/trusted-launch). Gen2 TLVM provides customers with secure compute solutions with security capabilities like:

Feature Name    |    Description
-|-
Secure Boot    |    Protects OS against rootkits and boot kits.
vTPM    |    It serves as a dedicated secure vault for keys and measurements, enabling attestation by measuring the entire boot chain of your VM
Guest VM Attestation    |    Guest attestation extension enables proactive attestation and monitoring the boot integrity of your VMs.

Newer OS like Windows Server 2022 Azure Edition require UEFI, Windows 11 requires UEFI & vTPM as pre-requisite for installation. Additionally, for enabling [Azure Compute security benchmark](https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows#secured-core) (like Secure Boot), UEFI support in OS is mandatory.

This repository provides end users with PowerShell script-based guidance which they can self-execute & upgrade existing Gen1 (BIOS) VMs to Gen2 (UEFI) VMs.

## Pre-Requisites

Pre-Requisite    |    Description
-|-
[Az PowerShell Module](https://learn.microsoft.com/powershell/azure/what-is-azure-powershell)    |    Required cmdlets for Azure Platform.
VM Contributor rights on Gen1 VM resource group.    |    Required RBAC permissions to modify and re-deploy Gen1 VM.
VM is in allocated / Running state.    |    Required to read current state and configuration of Gen1 VM and execute MBR to GPT conversion.
Operating System    |    Operating system should be [Trusted launch supported.](https://aka.ms/TrustedLaunch)
Azure IaaS VM Agent    |    [Azure IaaS Windows VM Agent](https://learn.microsoft.com/azure/virtual-machines/extensions/agent-windows) OR [Azure IaaS Linux VM Agent](https://learn.microsoft.com/azure/virtual-machines/extensions/agent-linux) should be installed and healthy.
Disk Encryption    |    If enabled, Disable any OS disk encryption including Bitlocker, CRYPT, [Server side encryption with customer managed keys](https://learn.microsoft.com/azure/virtual-machines/disk-encryption) prior to upgrade. All disk encryptions should be re-enabled post successful upgrade.
VM Backup    |    Azure Backup if enabled for VM(s) should be configured with Enhanced Backup Policy. Trusted launch security type cannot be enabled for Generation 2 VM(s) configured with Standard Policy backup protection.<br/>Existing Azure VM backup can be migrated from Standard to Enhanced policy using private preview migration feature. Submit on-boarding request to preview using link https://aka.ms/formBackupPolicyMigration.
VM Disaster Recovery    |    Trusted launch VMs currently do not support Azure Site Recovery (ASR). If enabled, ASR should be disabled prior to upgrade.

## Best Practices

Best Practice    |    Description
-|-
Validate in lower environment    |    Enable Trusted launch on a test Generation 2 VM and ensure if any changes are required to meet the prerequisites before enabling Trusted launch on Generation 2 VMs associated with production workloads.
**Backup** Gen1 VM    |    Create restore point for Azure Generation 1 VM(s) associated with production workloads before enabling Trusted launch security type. You can use the Restore Point to re-create the disks and Generation 1 VM with the previous well-known state.

## High-Level Upgrade Workflow

Id    |    Step    |    Description
-|-|-
1    |    Validate Pre-Requisites    |    Validate pre-requisites for executing script:<ul><li>Az.Account, Az.Compute PowerShell modules<li>Csv location (Refer to [sampleCsv](./artifacts/sampleCsv.csv) for schema details.)</ul>
2    |    Connect Azure Subscription and read Gen1 VM Configuration    |    Store Gen1 VM Configuration required for conversion:<ul><li>OS Disk Metadata<li>VM Size</li></ul>
3    |    Validate VM SKU Trusted launch Support   |    Validate if current VM Size assigned to Gen1 VM supports Trusted launch. If not, VM Size for Gen1 VM will need to be updated with [Trusted launch support](https://aka.ms/TrustedLaunch).<br/>For steps of changing VM Size, please refer to [Change the size of a Virtual Machine](https://learn.microsoft.com/azure/virtual-machines/resize-vm?tabs=portal).
4    |    Execute MBR to GPT conversion    |    Script will execute online MBR to GPT conversion of OS disk boot partition.<br/>**Note**: For Linux VMs following assumptions are made:<ul><li>OS disk boot partition is mounted on `/dev/sda`.<li>VM is created using Azure marketplace image and not migrated from outside Azure cloud.</li></ul>
5    |    De-allocate and upgrade VM properties    |    Script will update the VM attributes from Gen1 to Gen2 and security type to Trusted launch.
6    |    Start VM    |    Post successful upgrade, VM will be started.

## Post-Conversion Activities

After successful conversion of Gen1 to Trusted Launch VM, user needs to perform required steps for applicable scenarios from below list:

1. Validate health of Virtual Machine OS and workload hosted on converted Gen2 TLVM.
2. Re-enable all disk encryptions on Trusted launch virtual machine post successful upgrade.
3. Re-enable backup with Enhanced Policy post successful upgrade to Trusted launch virtual machine.
