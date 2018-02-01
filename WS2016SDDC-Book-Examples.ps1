# Author : Gilson Banin
# E-mail : gbanin@outlook.com
# Description: Examples of commands / scripts used in the Windows Server 2016 Software Defined Datacenter Book
# Date : 02/01/2018
# Version : 1.0

#region Chapter 01 - Installing

# How to Import Module for Nano Server Creation
Import-Module C:\Temp\NanoServer\NanoServerImageGenerator\NanoServerImageGenerator.psm1 -Verbose

# How to create a Nano Server Base
New-NanoServerImage -Edition Datacenter -DeploymentType Guest -MediaPath E:\ -BasePath .\Base -TargetPath .\NANO.vhdx -ComputerName NANO

# How to Extract VMWare Tool drivers to a folder
D:\Setup64.exe /a /p C:\Temp\Nano\VMTools

# How join Nano Server to a AD doamin
C:\djoin /provision /domain domainname /machine NANONAME /savefile C:\nanojoin.djoin

# How to create a Nano Server complete image
New-NanoServerImage -MediaPath 'E:\' -Edition 'Datacenter' -DeploymentType Guest -TargetPath 'C:\Temp\NANOSERVER.vhd' -MaxSize 8589934592 -DomainBlobPath 'C:\Users\gbanin\Desktop\nanojoin.djoin' -EnableRemoteManagementPort -InterfaceNameOrIndex '1' -Ipv4Address '192.168.194.115' -Ipv4Dns '192.168.194.100' -Ipv4SubnetMask '255.255.255.0' -Ipv4Gateway '192.168.194.2' -SetupUI ('NanoServer.DNS', 'NanoServer.Defender') -DriverPath ('F:\Program Files\VMware\VMware Tools\Drivers\pvscsi\Win8\amd64\pvscsi.inf') -SetupCompleteCommand ('tzutil.exe /s "E. South America Standard Time"') -LogPath 'C:\ Temp\NanoServerImageBuilder\Logs'

# How to convert Azure VM from Pay as you go to HUB
$vm = Get-AzureRMVM -ResourceGroup “RGName” -Name “VMName”
$vm.LicenseType = “Windows_Server”
Update-AzureRMVM -ResourceGroup “RGName” -VM $vm

# How to generalize a VM for cloning
sysprep.exe /oobe /generalize /shutdown /mode:vm

# How to list instalation options of Windows Server
Get-WindowsImage -ImagePath C:\Install.wim

# How to remove a edition from windows image by index
Remove-WindowsImage -ImagePath C:\Install.wim -Index 1

# How to mount a windows image to a folder
Mount-WindowsImage -Image-Path C:\Install.wim -Index 1 -Path C:\Mount

# How to include a hotfix to a windows image
Add-WindowsPackage -Path C:\hotfixes C:\Mount

# How to include a driver to a windows image
Add-WindowsDriver -Path C:\Mount -Driver C:\Drivers -Recurse

# How to include a Hyper-V role to a windows image
Enable-WindowsOptionalFeature -Path C:\Mount -FeatureName Microsoft-hyper-V -all

# How to dismount a windows image and save all instructions
Dismount-WindowsImage -Path C:\Mount -Save

# Example of Desired State Configuration
Configuration WebsiteTest {

    # Importar o modulo dos recursos que estamos usando
    Import-DscResource -ModuleName PsDesiredStateConfiguration

    # Especifica o nome da máquina que será aplicada
    Node 'localhost' {

        # Especifica que o feature do IIS estará presente
        WindowsFeature WebServer {
            Ensure = "Present"
            Name   = "Web-Server"
        }

        # Garantirá que o conteúdo do site estará na pasta wwwroot
        File WebsiteContent {
            Ensure = 'Present'
            SourcePath = 'c:\test\index.htm'
            DestinationPath = 'c:\inetpub\wwwroot'
        }
    }
}

# How to Start DSC
Start-DscConfiguration .\WebSiteTest


#endregion

#region Chapter 02 - Storage

# How to enable Remote Disk Management
Enable-NetFirewallRule -DisplayName 'Remote Event Log Management (RPC)'   
   
Enable-NetFirewallRule -DisplayName 'Remote Event Log Management (NP-In)'    

Enable-NetFirewallRule -DisplayName 'Remote Event Log Management (RPC-EPMAP)'

Enable-NetFirewallRule -DisplayName 'Remote Volume Management - Virtual Disk Service (RPC)'      

Enable-NetFirewallRule -DisplayName 'Remote Volume Management - Virtual Disk Service Loader (RPC)'

Enable-NetFirewallRule -DisplayName 'Remote Volume Management (RPC-EPMAP)'

# How to manage disk from prompt command with Diskpart
Diskpart
Select disk 1
Convert dynamic
Create volume simples size=1000000 disk=1
Assign letter=w
Format fs=ntfs label=”data disk” quick

# How to manage disk from PowerShell
Get-Disk | 
    Where-Object PartitionStyle -eq 'raw' |
        Initialize-Disk -PassThru |
            New-Partition -UseMaximumSize -AssignDriveLetter |
                Format-Volume -FileSystem ReFS  

# How to create a VHDX from PowerShell
New-VHD -Path C:\mydata.vhdx -Dynamic -SizeBytes 10Gb | 
    Mount-VHD -Passthru |
        Initialize-Disk -Passthru |
            New-Partition -AssignDriveLetter -UseMaximumSize |
                Format-Volume -FileSystem NTFS  

# How to create a Storage Pool and vDisks
$disks = Get-StoragePool -IsPrimordial $true | 
    Get-PhysicalDisk | Where-Object CanPool -eq $True

$storageSubsystem = Get-StorageSubSystem

New-StoragePool –FriendlyName MyStoragePool `
–StorageSubsystemFriendlyName $storageSubsystem.FriendlyName `
–PhysicalDisks $disks

New-VirtualDisk –FriendlyName MyVirtualDisk `
-StoragePoolFriendlyName MyStoragePool `
-ResiliencySettingName Mirror `
-ProvisioningType Fixed `
-NumberOfDataCopies 2 `
-UseMaximumSize

Get-VirtualDisk –FriendlyName MyVirtualDisk | 
    Get-Disk | Initialize-Disk –Passthru | 
        New-Partition –AssignDriveLetter –UseMaximumSize | 
            Format-Volume -FileSystem NTFS

# How to create a Storage QoS Policy
$desktopVmPolicy = New-StorageQosPolicy -Name Desktop -PolicyType Dedicated -MinimumIops 100 -MaximumIops 200

# How to see Storage QoS PolicyID
$desktopVmPolicy.PolicyId

# How to apply Storage QoS to a VM
Get-VM -Name VMName | Get-VMHardDiskDrive | Set-VMHardDiskDrive -QoSPolicyID cd6e6b87-fb13-492b-9103-41c6f631f8e0

# How to monitor Storage QoS
Get-StorageQoSflow | Sort-Object InitiatorName | FT InitiatorName, Status, MinimumIOPs, MaximumIOPs, StorageNodeIOPs, Status

# How to see Storage QoS in a VM
Get-VM -Name VMName | Get-VMHardDiskDrive | Format-List   

# How to install Storage Replica in multiple servers
Invoke-Command -ScriptBlock {

Install-WindowsFeature -Name Storage-Replica,FS-FileServer -IncludeManagementTools -Restart

} -ComputerName server1, server2

# How to create a Storage Replica Partnership
New-SRPartnership -SourceComputerName server1 `
-SourceRGName RG1 `
-SourceVolumeName d: `
-SourceLogVolumeName e: `
-DestinationComputerName server2 `
-DestinationRGName RG2 `
-DestinationVolumeName d: `
-DestinationLogVolumeName e:

# How to monitor Storage Replica
(Get-SRGroup).replicas
Get-SRPartnership

# How revert replication of Storage Replica
Set-SRPartnership -NewSourceComputerName server2 `
-SourceRGName RG2 `
-DestinationComputerName server1 `
-DestinationRGName RG1

# How to remove a existing Storage Replica partnership
Get-SRPartnership | Remove-SRPartnership
Get-SRGroup | Remove-SRGroup

# How to Measure VHDX creation in a ReFS volume
Measure-Command {New-VHD -Fixed -Path "C:\ClusterStorage\Volume1-NTFS\LargeSectorBlockSize.vhdx" -BlockSizeBytes 128MB -LogicalSectorSize 4KB -SizeBytes 100GB}

Measure-Command {New-VHD -Fixed -Path "C:\ClusterStorage\Volume2-REFS\LargeSectorBlockSize.vhdx" -BlockSizeBytes 128MB -LogicalSectorSize 4KB -SizeBytes 100GB}

# How to install Data Deduplication in a Nano Server
dism /online /enable-feature /featurename:dedup-core /all

# How to install Data Deduplication on Core and Full Servers
Install-WindowsFeature FS-Data-Deduplication -IncludeAllSubFeature

# How to enable Data Deduplication in a volume
Enable-DedupVolume -Volume D: -UsageType Default

# How to change existing Data Dedup configuration
Set-DedupVolume -Volume D: -MinimumFileAgeDays 0

# How to start a new job of Data Deduplication
Start-DedupJob –Volume D: -Type Optimization -Memory 50

# How to test jumbo frames
ping -f -l 9000 [destination ip]

# How to install MultiPath-IO
Install-WindowsFeature Multipath-IO

#endregion 

#region Chapter 03 - Hyper-V

# How to install Hyper-V feature in multiple servers
$computers = Get-Content C:\Users\LocalAdmin\HyperVServers.txt
Invoke-Command -ScriptBlock {Add-WindowsFeature Hyper-V -Restart} -ComputerName $computers

# How to install Failover Cluster feature in multiple servers
$computers = Get-Content C:\Users\LocalAdmin\HyperVServers.txt
Invoke-Command -ScriptBlock {Add-WindowsFeature Failover-Clustering} -ComputerName $computers

# How to configure IP, Mask and Gateway of TCP/IP stack of Server Core with Hyper-V
New-NetIPAddress -interfacealias ethernet0 -IPAddress 192.168.3.200 -Prefixlength 24 -defaultgateway 192.168.3.2

# How to configure Dns address of Server Core with Hyper-V
Set-DNSClientServerAddress -interfacealias ethernet0 -ServerAddress 192.168.3.10

# How to enable all firewall rules in all directions
New-NetFirewallRule -displayname "Allow All Traffic" -direction outbound -action allow

New-NetFirewallRule -displayname "Allow All Traffic" -direction inbound -action allow

# How to rename computer and join it to AD domain
Add-Computer -newname HYPERV01 -domainname banin.com -restart

# How to allow remote connection management
Set-Item WSMan:\localhost\Client\TrustedHosts -value * -force 
Enable-WSManCredSSP -Role client -DelegateComputer *

# How to enable Nested Virtualization
Set-VMProcessor -VMName Name -ExposeVirtualizationExtension $true
Get-VMNetworkAdapter -VMName Name | Set-VMNetworkAdapter -MacAddressSpoofing On

# How to create a NAT vSwitch
New-VMSwitch -Name VmNAT -SwitchType Internal
New-NetNat –Name LocalNAT –InternalIPInterfaceAddressPrefix “192.168.100.0/24”
Get-NetAdapter "vEthernet (VmNAT)" | New-NetIPAddress -IPAddress 192.168.100.1 -AddressFamily IPv4 -PrefixLength 24

# How to configure TCP/IP inside of nested VM
Get-NetAdapter "Ethernet" | New-NetIPAddress -IPAddress 192.168.100.2 -DefaultGateway 192.168.100.1 -AddressFamily IPv4 -PrefixLength 24
Netsh interface ip add dnsserver “Ethernet” address=<DNS server>

# How to discover a integration services version
REG QUERY "HKLM\Software\Microsoft\Virtual Machine\Auto" /v IntegrationServicesVersion
Get-ItemProperty “HKLM:Software\Microsoft\Virtual machine\Auto”
Get-VMIntegrationService -ComputerName HYPERVName -VMName VMName

# How create a VHDX fixed size
New-VHD -ComputerName HVName -Path C:\VHD\MyFirstDisk.VHDx -SizeBytes 40GB -Fixed

# How to create a VHDX dynamic size
New-VHD -Computername HVName -Path C:\VHD\MyFirstDisk.VHDx -SizeBytes 100GB -Dynamic

# How to add a VHDX in a VM
Add-VMHardDiskDrive -ComputerName HVName -VMname VMName -Path C:\VHD\MyFirstDisk.vhdx

# Explore *-VHD comands
Convert-VHD
Dismount-VHD
Get-VHD
Get-VHDSet
Get-VHDSnapshot
Merge-VHD
Mount-VHD
New-VHD
Optimize-VHD
Optimize-VHDSet
Remote-VHDSnapshot
Resize-VHD
Set-VHD
Test-VHD

# How to create a Pass through disk
New-VHD -Path C:\VHD\Passthru.vhdx -Dynamic -SizeBytes 60GB | Mount-VHD -Passthru | Initialize-Disk -Passthru | set-disk -isoffline $true

# How to add a Pass through disk to a VM
Get-Disk 1 | Add-VMHardDiskDrive -VMName VMName

# How to create a External vSwitch
New-VMSwitch -ComputerName HVServer -Name ExternalSwitch -SwitchType External

# How to create a Internal vSwitch
New-VMSwitch -ComputerName HVServer -Name InternalSwitch -SwitchType Internal

# How to create a Private vSwitch
New-VMSwitch -ComputerName HVServer -Name PrivateSwitch -SwitchType Private

# How to enable vNIC Teaming Mode
Set-VMNetworkAdapter -VMName VMName -MacAddressSpoofing On -AllowTeaming On
New-NetLbfoTeam -Name vNICTeaming -TeamMembers NIC1, NIC2 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm IPAddresses

# How to enable DVMQ
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\VMSMP\Parameters\BelowTenGigVmqEnabled = 1
Set-NetAdapterVmq -Name NIC -BaseProcessorGroup 0 - BaseProcessorNumber 2 -MaxProcessors 4 -MaxProcessorsNumber 8 - Enabled

# How to enable / disable DHCP guard
Set-VMNetworkAdapter -VMName VMname -DhcpGuard On/Off

# How to enable / disable Router guard
Set-VMVMNetworkAdapter -VMName VMName -RouterGuard On/Off

# How to enable / disable Port mirroring
Set-VMVMNetworkAdapter -VMName VMName -PortMirroring Source/Destination/None

# Explore Discrete Device Assignment
Get-PnpDevice -PresentOnly
Get-PnpDevice -PresentOnly | Where-Object {$_.Class -eq "Net"}
$pnpdevs = Get-PnpDevice -PresentOnly | Where-Object {$_.Class -eq "Net"} | Where-Object {$_.FriendlyName -eq "Intel(R) Dual Band Wireless-AC 7265"}
Disable-PnpDevice -InstanceId $pnpdevs.InstanceId -Confirm:$false
$locationpath = ($pnpdevs | get-pnpdeviceproperty DEVPKEY_Device_LocationPaths).data[0]
Dismount-VMHostAssignableDevice -LocationPath $locationpath -Force
Get-VMHostAssignableDevice 
Set-VM -Name VMName -AutomaticStopAction Shutdown
Add-VMAssignableDevice -LocationPath "$locationpath" -VMName VMName

# How to install Bitlocker in a VM Gen1
Install-WindowsFeature -Name Bitlocker -IncludeAllSubFeature - IncludeManagementTools -Restart

# How to enable Bitlocker
C:\manage-bde.exe -On -StartupKey B:\ -UsedSpaceOnly -SkipHardwareTest

# How to enable cryptography traffic live migration
Set-VMSecurity -VMName W10GEN1 -EncryptStateAndVmMigrationTraffic $true

# How to enable and monitor Resource Metering
Enable-VMResourceMetering -ComputerName HVName -VMName VMName
Measure-VM -ComputerName HVName -VMName VMName | FL
Measure-VM -ComputerName HVName -VMName VMName | select -expand harddiskmetrics
Measure-VM -ComputerName HVName -VMName VMName | select -expand networkmeteredtrafficreport

# How to enable Host Resource Protection
Set-VMProcessor -VMName VMName -EnableHostResourceProtection $true

# How to add hot virtual network adapter
Add-VMNetworkAdapter -ComputerName HVServer -VMName VMName -SwitchName SwitchName -Name Management -DeviceNaming On

# How to add hot virtual memory and monitoring
Get-VMMemory -ComputerName HVName -VMName Name
C:\while ($true) {get-counter “\memory\available mbytes”; start-sleep -s .5}
Set-VMMemory -ComputerName HVName -VMName Name -StartupBytes 4096MB

# How to configure Secure Boot on Linux VM
Set-VMFirmware VMName -SecureBootTemplate MicrosoftUEFICertificateAuthority

# How to upgrade VM Version
Update-VMVersion -VM VMName

# How to configure Nested Virtualizaiton on VMWare Workstation 12
hypervisor.cpuid.v0 = “FALSE”
mce.enable = “TRUE”
vhu.enable = “TRUE”

#endregion 

#region Chapter 04 - Container

# How to create a Hyper-V Container
docker run -d --name hvcontainer --isolation=hyperv microsoft/windowsservercore

# How to determine container version
docker inspect -f “{{.HostConfig.Isolation}}” ContainerName

# How to install Container feature
Install-WindowsFeature Containers -Restart

# How to install Docker on Windows Server
Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
Install-Package -Name Docker -Providername DockerMsftProvider -Verbose
Restart-Computer -Force

# How to install Docker on Nano Server
Set-Item WSMan:\localhost\Client\Trustedosts 10.10.10.10 -Force
Enter-PSSession -ComputerName 10.10.10.10 -Credential (Get-Credential)
$sess = New-CimInstance -NameSpace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperationsSession
Invoke-CimMethod -InputObject $sess -MethodName ApplyApplicableUpdates
Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
Install-Package -Name Docker -Providername DockerMsftProvider -Verbose
Start-Service Docker

# Creation of Daemon.json
%ProgramData%\Docker\Config\Daemon.json
Stop-Service Docker

# How to see remotely docker version
docker -H 10.10.10.10:2375 version

# How to download docker images from docker hub
docker pull microsoft/windowsservercore
docker pull microsoft/nanoserver:10.0.14393.576

# How to remove docker image
docker rmi 168f41dd231f

# How to create a container network transparent mode
docker network create -d transparent --subnet=192.168.100.0/24 --gateway 192.168.100.1 transparent-vnet

# How to list container network
docker network ls

# How to create and attached a existing container network
docker run -d --network=transparent-vnet microsoft/iis

# How to interact to a existing container
docker exec -it container_name cmd

# How to configure a static ip in a container
docker run -d --network=transparent-vnet --ip 192.168.100.90 microsoft/iis

# How create a container with 1 gb of meomry and 20% of CPU
docker run -d --name mycontainer --memory 1g --cpu-percent 20 --network=transparente-vnet --ip 192.168.100.90 microsoft/iis
 
# How to see what is happening inside of container
docker logs container_id

# How to remove a container network
Get-ContainerNetwork | Remove-ContainerNetwork

# How to create a NAT container network
docker network create -d nat --subnet=192.168.100.0/24 --gateway=192.168.100.1 NATCustomNetwork

# How to list containers for a specific network name
docker network inspect network_name

# How to map a port from host to container
docker run -d -p 80:8080 --name mycontainer microsoft/windowsservercore

# How to interact to a container with PowerShell
docker run -it microsoft/windowsservercore powershell.exe

# How to start / stop a container
docker start / stop container_id

# How to remove a container
docker rm container_id

# How to open a firewall for SMB connection on Server Core
netsh advfirewall firewall add rule name="Open Port 445" dir=in action=allow protocol=TCP localport=445

# How to export a docker image to another container host
docker save newjavaimage -o \conthost\c$\images\newjavaimage.tar

# How to import a docker image
docker load -i C:\NewImages\new_java_image.tar

# How to map a local folder to a container
docker run -d -v D:\ContainerData:C:\ContainerData gbanin/my_fist_image

# How to work with a volumes
docker run -d -v volume01:C:\ContainerData

# How to list volumes
docker volume ls

# How to create a file inside a container
New-Item -itemType file -Name Teste.txt -Value WidowsServer2016

# How to create a new custom image
docker commit container_name new_image_name

# How to download and install a newest version of Java in a container image

wget -Uri http://javadl.sun.com/webapps/download/AutoDL?BundleId=107944 -outfile javaInstall.exe -UseBasicParsing

REG ADD HKLM\Software\Policies\Microsoft\Windows\Installer /v DisableRollback /t REG_DWORD /d 1 | Out-Null

./javaInstall.exe /s INSTALLDIR=C:\Java REBOOT=Disable | Out-Null

# How to list docker images
docker images

# How to see dependencies
docker history image_name

# How to compile a new image using dockerfile
docker build -t my_first_image Dockerfile
docker build -t my_first_image:v2 Dockerfile

# How to tag a docker image
docker tag my_first_image:v2 gbanin/my_first_image:latest

# How to upload your docker image
docker login
docker push gbanin/my_first_image:latest

# How to download and install Docker Compose
Invoke-WebRequest https://github.com/docker/compose/releases/download/1.18.0/docker-compose-windows-x86_64.exe -UseBasicParsing -OutFile $env:ProgramFiles\docker\docker-compose.exe

# How to compose a docker solution
docker-compose up -f meucompose.yml

# How to destoy a docker solution 
docker-compose down -f meucompose.yml

# How to create a gMSA for containers
New-ADServiceAccount -Name gMSAContainers -DNSHostName gMSAcontainers.banin.com -PrincipalsAllowedToRetrieveManagedPassword "Container Hosts"

# How to install ADDS PowerShell module
Add-WindowsFeature AD-RSAT-Powershell
Import-Module ActiveDirectory

# How to install gMSA in a container host
Get-ADServiceAcccount -Identity gMSAContainers
Install-ADServiceAccount -Identity gMSAContainers
Test-ADServiceAccount -Identity gMSAContainers

# How to clone Credential Spec from Github
Invoke-WebRequest "https://raw.githubusercontent.com/Microsoft/Virtualization-Documentation/live/windows-server-container-tools/ServiceAccounts/CredentialSpec.psm1" -UseBasicParsing -OutFile $env: TEMP\cred.psm1
Import-Module $env:TEMP\cred.psm1
New-CredentialSpec -Name gMSAContainers -AccountName gMSAContainers

# How to attach .json security file to AD interaction
docker run -d microsoft/iis --security-opt=gMSAContainers.json --network=transparent-vnet

# How to delete all containers
docker container prune

# How to stop all containers without remove them
docker stop -t 0 $(docker ps -q)

# 

#endregion 

#region Chapter 05 - High Availability

# How to install Failover Cluster service
Install-WindowsFeature -Name FailoverClustering -IncludeManagementTools

# How to force quorum
net start clussvc /fq

# How to avoid cluster split brain
net start clussvc /pq

# How to configure Site AAwareness
New-ClusterFaultDomain –Name SaoPaulo –Type Site –Description “Primary” –Location “Sao Paulo Datacenter”

New-ClusterFaultDomain –Name RioJaneiro –Type Site –Description “Secondary” –Location “Rio de Janeiro Datacenter”

Set-ClusterFaultDomain –Name Node1 –Parent SaoPaulo
Set-ClusterFaultDomain –Name Node2 –Parent SaoPaulo
Set-ClusterFaultDomain –Name Node3 –Parent RioJaneiro
Set-ClusterFaultDomain –Name Node4 –Parent RioJaneiro

(Get-Cluster). PreferredSite = SaoPaulo

# How to configure preferred site
(Get-Cluster). PreferredSite = SaoPaulo
(Get-ClusterGroup -Name GroupName). PreferredSite = SaoPaulo

# How to setup compute resiliency
(Get-Cluster). ResiliencyLevel=2
(Get-Cluster). ResiliencyDefaultPeriod=240
(Get-ClusterGroup “VMName”).ResiliencyPeriod=120

# How to configure start order priority
New-ClusterGroupSet
Get-ClusterGroupSet
Add-ClusterGroupSetDependency

# How to create a failover cluster without AD
New-Cluster -AdministrativeAccessPoint DNS

# How to enable MAC spoofing in a guest clutering
Set-VMNetworkAdapter -VMName <Name> -MacAddressSpoofing On

# How to install NLB service
Install-WindowsFeature NLB

# How to create a NLB in a first node
New-NLBCluster -InterfaceName Etherner -ClusterPrimaryIP 10.10.10.10 -Clustername ClusterNLB

# How to add new replication disk without remove replication
Set-VMReplication -VMName VMName -ReplicatedDisks (Get-VMHardDiskDrive VMName)

# How to test a cluster creation for S2D
Test-Cluster -Node Node1, Node2 -Include “Storage Space Direct”, “Inventory”, “Network”, “System Configuration”

# How to create cluster
New-Cluster -Name Clustername -Node Node1, Node2 -NoStorage

# How to enable storage space direct
Enable-ClusterS2D
Enable-ClusterStorageSpaceDirect -cimSession ClusterName

# How to create a new volume ReFS in a cluster S2D
New-Volume -Friendlyname “Volume1” -FileSystem CSVFS_ReFS -StoragePoolFriendlyname S2D* Size 1TB

# How to create a mirroring volume
New-Volume -FriendlyName "Volume2" -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size 1TB -ResiliencySettingName Mirror

# How to create a mirroring volume with parity
New-Volume -FriendlyName "Volume3" -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -Size 1TB -ResiliencySettingName Parity

# How to list storage tiers
Get-StorageTier | Select FriendlyName, ResiliencySettingName, PhysicalDiskRedundancy

# How create storage tier
New-Volume -FriendlyName "Volume4" -FileSystem CSVFS_ReFS -StoragePoolFriendlyName S2D* -StorageTierFriendlyNames Performance, Capacity -StorageTierSizes 300GB, 700GB

#endregion 

#region Chapter 06 - Monitoring

# WSUS GPO Path
Computer Configuration \ Policies \ Administrative Templates \ Windows Components \ Windows Update

# How to install Windows Server Backup
Install-WindowsFeature Windows-Server-Backup

# How to execute Windows Server Backup from PowerShell
$policy = New-WBPolicy
$filespec = New-WBFileSpec -FileSpec C:\Temp\Book.docx
Add-WBFileSpec -Policy $policy -FileSpec $filespec
$backuplocation = New0WBBackupTarget -NetworkPath “\\server\backup\backups”
Add-WBBackupTarget -Policy $policy -Target $backuplocation
Set-WBVssBackupOptions -Policy $policy -VssCopyBackup
Start-WBBackup -Policy $policy -Async

# How to backup IIS metadata
Backup-WebConfiguration -Name IISBackup

# How to list event log
Get-EventLog -LogName Application -Newest

# How to create a new event on event viewer for custom app
Net-EventLog -LogName Application -Source MyCustomApp

Write-EventLog -LogName Application -Source MyCustomApp -EvnetID 911 -EntryType Error -Message ‘Falha na conexão ao servidor entre em contato com o administrador’

# PowerShell Direct
Enter-PSSession -VMName -Credential $credential

# How to enable Remote Desktop
Set-ItemProperty – Path “HKLM:\System\CurrentControlSet\Control\Terminal Server” -Name “fDenyTSConnections” -Value 0

# How to enable RDP on Windows Firewall
Enable-NetFirewallRule -DisplayGroup “Remote Desktop”

# How to see listening port
C:\netstat -an | find “:3389”

#endregion 

#region Chapter 07 - Networking

# How to install Network Controller
Install-WindowsFeature NetworkController

# How to configure IPSec from GPO
# Requer IPSec entre os servidores para sessões do Remote PowerShell FILE1 and FILE2
$admincred = Get-Credential -UserName "DOMAIN\administrator" -Message "Enter the domain admin password"
Enter-PSSession -ComputerName DC -Credential $admincred

$name = "Require IPSec for PowerShell"
$gpo = "banin.com\Firewall"
$mode = "Transport"
New-NetIPsecRule -DisplayName $name -Mode $mode -InboundSecurity Require -Protocol TCP -LocalPort 5985 -PolicyStore $gpo -Enabled True
$rule = Get-NetIPsecRule -PolicyStore $gpo
$rule | ft
Get-NetFirewallPortFilter -AssociatedNetIPsecRule $rule
Get-NetFirewallAddressFilter -AssociatedNetIPsecRule $rule
Restart-Computer FILE1,FILE2

#Testar conectividade com o servidor FILE1
$testipsec = {Get-NetIPsecMainModeSA | ft}
Invoke-Command -ComputerName FILE1 -ScriptBlock $testipsec

#Criar regra para obrigrar o IPSec
$name = "Request outbound IPSec for PowerShell"
New-NetIPsecRule -DisplayName $name -OutboundSecurity Request -InboundSecurity Request -RemotePort 5985 -Protocol TCP

#Como deveria funcionar
Invoke-Command -ComputerName FILE1 -ScriptBlock $testipsec
$testipsec
Invoke-Command -ComputerName FILE2 -ScriptBlock $testipsec
Remove-NetIPsecRule -DisplayName $name

#Remove "Require IPSec for PowerShell" pela GPO Firewall
$name = "Require IPSec for PowerShell"
$gpo = "banin.com\Firewall"
Remove-NetIPsecRule -DisplayName $name -PolicyStore $gpo

#Cria uma GPO para forçar a comunicação por IPSec para todos os computadores do domínio
New-GPO -Name IPSec
New-GPLink -Name IPsec -Target "DC=Company,DC=Pri"
$name = "Require IPSec for PowerShell"
$gpo = "banin.com\IPSec"
New-NetIPsecRule -DisplayName $name -InboundSecurity Require -OutboundSecurity Require -RemotePort 5985 -Protocol TCP -PolicyStore $gpo
Exit-PSSession

#A partir do seu desktop
gpupdate /force
Get-NetIPsecRule -PolicyStore ActiveStore | Select-Object DisplayName,Enabled,Mode,SecIn,SecOut,PolicyStoreSourceType

#Conectar em um Domain Controller e verificar as associações de segurança
Enter-PSSession -ComputerName DC -Credential $admincred
Get-NetIPsecMainModeSA | ft
Get-NetIPsecQuickModeSA | ft
Exit-PSSession

# How to create a Switch Embedded Teaming
New-VMSwitch –Name SETSwitch –NetAdapterName "Ethernet0", "Ethernet1" –EnableEmbeddedTeaming $true

# How to see Trust Anchor
Get-DnsServerTrustAnchor -Name banin.com

# Resolve DNS Name
ResolveDNSName www.secure.banin.com -type A -Server adds01.banin.com
Resolve-DnsName www.secure.banin.com -type A -server adds01.banin.com -dnssecok

# DNS Split Brain
Add-DnsServerZoneScope -ZoneName "banin.com" -Name "internal" 
Add-DnsServerResourceRecord -ZoneName "banin.com" -A -Name "adfs" -IPv4Address "10.10.10.10” -ZoneScope "internal"
Add-DnsServerResourceRecord -ZoneName "banin.com" -A -Name "adfs" -IPv4Address "200.200.200.200"
Add-DnsServerQueryResolutionPolicy -Name "SplitBrainZonePolicy" -Action ALLOW -ServerInterface "eq,10.10.10.5" -ZoneScope "internal,1" -ZoneName banin.com

# DNS Policy Filters
Add-DnsServerQueryResolutionPolicy -Name "BlockListPolicy" -Action IGNORE -FQDN "EQ,*.dominiomalicioso.com" -PassThru
Add-DnsServerQueryResolutionPolicy -Name "BlockListPolicyMalicious06" -Action IGNORE -ClientSubnet "EQ,MaliciousSubnet06" –FQDN “EQ,*.dominiomalicioso.com” -PassThru
Add-DnsServerQueryResolutionPolicy -Name "BlockListPolicyQType" -Action IGNORE -QType "EQ,ANY" -PassThru
Add-DnsServerClientSubnet -Name "AllowedSubnet" -IPv4Subnet 172.0.0.0/16 -PassThru
Add-DnsServerQueryResolutionPolicy -Name "AllowListPolicySubnet” -Action IGNORE -ClientSubnet "NE, AllowedSubnet" -PassThru


# DNS Policy - Recursive Control
Set-DnsServerRecursionScope -Name . -EnableRecursion $False
Add-DnsServerRecursionScope -Name "InternalClients" -EnableRecursion $True
Add-DnsServerQueryResolutionPolicy -Name "SplitBrainRecursionPolicy" -Action ALLOW -ApplyOnRecursion -RecursionScope "InternalClients" -ServerInterfaceIP  "EQ,10.0.0.5"

#endregion 

#region Chapter 08 - Identity

# How to list domain and forest functional levels
Get-ADForest | FT Name, ForestMode
Get-ADDomain | FT Name, DomainMode

# How to list schema version
DSQuery * “cn=schema, cn=configuration, dc=banin, dc=com” -scope base -attr objectVersion  
Get-ADObject “cn=schema, cn=configuration, dc=banin, dc=com” -Properties objectVersion

# How to extend schema
Adprep.exe / ForestPrep (para preparar a Floresta)
Adprep.exe /DomainPrep (para preparar o Domínio)
Adprep.exe /GpoPrep (para preparar as políticas de grupo)
Adprep.exe /RodcPrep (para preparar os controladores de domínio somente leitura)

# How to install ADDS and automate DC promotion
Install-WindowsFeature AD-Domain-Services
Import-Module ADDSDeployment
Install-ADDSForest -CreateDnsDelegation: $false -DatabasePath “N:\NTDS” -DomainMode “Win2012R2” -DomainName “labpfe.com” -DomainNetbiosName “LABPFE” -ForestMode “Win2012R2” -InstallDns: $true -LogPath “N:\NTDS” -NoRebootOnCompletion: $false -SysvolPath “N:\SYSVOL” -Force: $true

# How to activate KDS
Add-KdsRootKey -EffectiveImmediately

# How to create a gMSA
New-ADServiceAccount -Name MyFirstGMSA -DNSHostName MyFirsGMSA.banin.com -PrincipalsAlloedToRetrievemanagedPassword “Domain Computers”
Add-ADComputerServiceAccount -Identity ServerName -ServiceAccount MyFirstGMSA
Install-ADServiceAccount  -Identity MyFirstGMSA
Test-ADServiceAccount -Identity MyFirstGMSA

# How to create a test service for gMSA
New-Service -Name “ServiceLABMSA” -BinaryPathname “C:\Windows\System32\svchost.exe -k netsvcs”

# SPN
setspn -L DOMAIN\Account
setspn -a HTTP/www.banin.com BANIN\WebAppAccount

# Backup of AD - Prepair Disk
Set-Disk -number number_disk -IsOffline $false
Initialize-Disk -Number number_disk -PartitionStyle GPT
New-Partition -DiskNumber number_disk -UseMaximumSize -AssignDriverLetter
Format-Volume -DriverLettrer E -FileSystem NTFS

# Backup of AD - Automation
Install-WindowsFeature Windows-Server-Backup
$policy = New-WBPolicy
Add-WBSystemState -Policy $policy
# Get-WBVolume -AllVolumes
$volume = Get-WBVolume -AllVolumes | Where MountPath -eq "C:"
Add-WBVolume -Policy $policy -Volume $volume
$backupvolume = Get-WBVolume -AllVolumes | Where MountPath -eq "B:"
$backuptarget = New-WBBackupTarget -Volume $backupvolume
Add-WBBackupTarget -Policy $policy -Target $backuptarget
Set-WBSchedule -Policy $policy -Schedule 02:00
Set-WBPolicy -Policy $policy
Start-WBBackup -Policy $policy

# Restore Mode
bcdedit /set /safeboot dsrepair

# How to list backup list
$backup = Get-WBBackupSet | where versionid -eq “version-id”

# Non authoritative restore
Start-WBSystemStateRecovery -BackupSet $backup -Force -RestartComputer

# Authoritative restore
Start-WBSystemStateRecovery -BackupSet $backup -Force -AuthoritativeSysvolRecovery
ntdsutil
activate instance ntds
authoritative restore
restore object “cn=gbanin,ou=usuarios,dc=banin,dc=com” (para um usuário individual)
restore subtree “ou=usuarios,dc=banin,dc=com” (para a OU usuários e todos objetos que estão dentro dela)

# Boot in normal mode
bcdedit /deletevalue /safeboot

# How to enable recycle bin
EnableADOptionalFeature -Identity “CN=Recycle Bin Feature,CN=Optional Feature,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=banin,DC=com” -Scope ForestOrConfiguraitonSet -Target “banin.com”

# Restore deledted users from recycle bin
GetADObject -Filter {displayname -eq “Gilson Banin”} -IncludeDeletedObjects | Restore-AdObject

# AD Snapshot
ntdsutil
activate instance ntds
snapshot
create
list all
mount {GUID}
dsamain -dbpath C:\$SNAP_DATE_VOLUMEC$\ntds\ntds.dit -ldapport 5000

# AD offline
Stop-Service NTDS -Force

# AD defrag
stop-service ntds -force
ntdsutil
active instance ntds
files
info
compact to D:\newntds

# DFSRMIG
dfsrmig /SetGlobalState stage_number 

# How to enable ADFS login page
Set-ADFSProperties -EnableIdpInitiatedSignonPage $true

# Publish RDG from WAP
Get-WebApplicationProxyApplication applicationname | Set-WebApplicationProxyApplication -DisableTranslateUrlInRequestHeaders:$false
Get-WebApplicationProxyApplication applicationname | Set-WebApplicationProxyApplication -DisableHttpOnlyCookieProtection:$true
Set-RDSessionCollectionConfiguration -CollectionName "<nome-da-sua-colleciton>" -CustomRdpProperty "pre-authentication server address:s: <https://externalfqdn/rdweb/>`nrequire pre-authentication:i:1"


#endregion 

#region Chapter 09 - Security

# How to remove SMB v1
Remove-WindowsFeature FS-SMB1

# How to install Host Guardian Service
Install-WindowsFeature HostGuardianServiceRole -IncludeAllSubFeature

# Device Guard VM
Set-VMSecurity -VMName Name -VirtualizationBasedSecurityOptOut $true

# Create CI Policy
New-CIPolicy -Level FilePublisher -Fallback Hash -UserPEs -FilePath C: \CI\FilePublisher.xml

# Set Rule Option
Set-RuleOptions -FilePath C: \CI\FilePublisher.xml -Option 3 -delete

# Convert CIPolicy
ConvertFrom-CIPolicy C:\CI\ FilePublisher.xml C:\CI\FilePublisher.bin

# Copy .bin to CodeIntegrity folder
Copy-Item C:\CI\FilePublisher.bin C:\Windows\System32\CodeIntegrity\SiPolicy.p7b

# Enable PSRemoting
Enable-PSRemoting

# Create RoleCapabilityFile (JEA)
New-PSRoleCapabilityFile -Path C:\Temp\Minha-Primeira-JEA-Role.psrc

# Create new PSSessionConfigurationFile
New-PSSessionConfigurationFile -SessionType RestrictedRemoteServer -Path C:\Temp\Meu-Primeiro-JEA-Endpoint.pssc

# Register PSSession
Register-PSSessionConfiguration -Path C:\Temp\Meu-Primeiro-JEA-Endpoint.pssc -Name 'JEA-Manutencao' -Force

# Connect to from JEA
$nonAdminCred = Get-Credential
Enter-PSSession -ComputerName localhost -ConfigurationName JEA-Manutencao -Credential $nonAdminCred

# Protect User Group
Remove-ADGroupMember -Identity "Domain Admins" -Members LocalAdmin
$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins"

Add-ADGroupMember -Identity "Protected Users" -Members $DomainAdmins

# 

#endregion 

#region Chapter 10 - Azure Stack

# Azure Stack PowerShell
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Install-Module -Name AzureRM.BootStrapper
Use-AzureRMProfile -Profile 2017-03-09-profile -Force
Install-Module -Name AzureStack -RequiredVersion 1.2.11
Get-Module -ListAvailable | where-Object {$_. Name -like “Azure*”}

# Register
Add-AzureRmAccount -EnvironmentName "AzureCloud"
Register-AzureRmResourceProvider -ProviderNamespace Microsoft.AzureStack
Import-Module .\RegisterWithAzure.psm1
Add-AzsRegistration -CloudAdminCredential $CloudAdminCred -AzureSubscriptionId $AzureContext.Subscription. SubscriptionId -AzureDirectoryTenantName $AzureContext.Tenant. TenantId -PrivilegedEndpoint AzS-ERCS01 -BillingModel Development

# Import module Connect and Compute
Set-ExecutionPolicy RemoteSigned
Import-Module .\Connect\AzureStack.Connect.psm1
Import-Module .\ComputeAdmin\AzureStack.ComputeAdmin.psm1

# Login via Azure AD
$ArmEndpoint = "https://adminmanagement.local.azurestack.external"
$GraphAudience = "https://graph.windows.net/"
Add-AzureRMEnvironment `
 -Name "AzureStackAdmin" `
 -ArmEndpoint $ArmEndpoint

Set-AzureRmEnvironment `
 -Name "AzureStackAdmin" `
 -GraphAudience $GraphAudience

$TenantID = Get-AzsDirectoryTenantId `
 -AADTenantName "<DirectoryTenantName>.onmicrosoft.com" `
 -EnvironmentName AzureStackAdmin

Login-AzureRmAccount `
 -EnvironmentName "AzureStackAdmin" `
 -TenantId $TenantID

# Login via ADFS
$ArmEndpoint = "https://adminmanagement.local.azurestack.external"
$GraphAudience = "https://graph.local.azurestack.external"

Add-AzureRMEnvironment `
 -Name "AzureStackAdmin" `
 -ArmEndpoint $ArmEndpoint

Set-AzureRmEnvironment `
 -Name "AzureStackAdmin" `
 -GraphAudience $GraphAudience `
 -EnableAdfsAuthentication: $true 

$TenantID = Get-AzsDirectoryTenantId -ADFS -EnvironmentName "AzureStackAdmin"
Login-AzureRmAccount -EnvironmentName "AzureStackAdmin" -TenantId $TenantID

# Create a VM Image
$ISOPath = "caminho_da_midia_windows_server_2016.iso"
New-AzsServer2016VMImage -ISOPath $ISOPath

#endregion 
