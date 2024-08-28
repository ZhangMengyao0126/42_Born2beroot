# 42_Born2beroot
## Virtual Machine
### What is a Virtual Machine?
<img width="897" alt="image" src="https://github.com/user-attachments/assets/258ff23b-ec7a-445d-822d-1042a48de7cb"><br>
*Virtual machines are completely isolated. This means, that if something breaks inside the VM, it doesn't affect the host machine.

### Different types of Virtual Machine
<img width="900" alt="image" src="https://github.com/user-attachments/assets/a3178ba6-ada5-4a57-9172-22effdc82176">

### Why do we need a Virtual Machine?
#### For personal use
<img width="828" alt="image" src="https://github.com/user-attachments/assets/5c527335-09f0-47b6-97c9-75f37f25af33">

#### For companies
<img width="873" alt="image" src="https://github.com/user-attachments/assets/40ee75f3-b8f1-4018-a9f0-41b0d2cd5f7d">

<img width="916" alt="image" src="https://github.com/user-attachments/assets/68957fb5-718b-427a-b099-1d7993f7960c">

## Hardware
1. CPU(Central Processing Unit):CPU是工人，负责执行计算机程序中的指令，进行数据处理和计算。<br>
注：现代计算机通常有多个CPU，设置CPU count就是设置分配给虚拟机的CPU数量。<br>
2. RAM(Random Access Memory)(内存):内存是CPU的工作区，用于暂时存储当前正在使用的操作系统、应用程序和数据。当程序结束或设备断电时，内存将会被清空。<br>
注：在创建虚拟机时，设置RAM就是设置Base Memory。<br>
3. HDD（Hard Disk Drive）（硬盘）：硬盘是CPU的档案库，用于长期存储操作系统、应用程序和数据。<br>
*Hard Disk File: 虚拟硬盘文件，用于模拟一个物理硬盘的功能，用于长期存储操作系统、应用程序和数据。不同的类型只是因为适用于不同的Hypervisor平台：<br>
(1)VDI (VirtualBox Disk Image) - Oracle VirtualBox
(2)VHD (Virtual Hard Disk) - Microsoft Hyper-V
(3)VMDK (Virtual Machine Disk) - Virtual Machine Disk

## Debian
一款以稳定著称的Linux发行版。Linux发行版，指在Linux内核的基础上构建，添加了各种应用程序、工具和管理工具，形成完整操作系统环境的操作系统版本。<br>

## Locale
一组用于配置计算机系统语言、文化习惯和格式设置的参数。en_US.UTF-8：en：语言（英语）；US：地区（美国）；UTF-8：字符编码<br>

## URL & Domain name
1. 网址（URL）:是用于指定互联网上某一资源的位置的完整地址。<br>
2. Domain name(域名)：是互联网上用于标识网站的易记名称，它与 IP 地址关联，帮助用户通过人类友好的方式（而不是IP地址的一大串数字）访问特定网站。<br>
3. Domain name(域名)是URL(Uniform Resource Locator)(网址)的一部分。<br>
Eg. https://www.example.com/about?lang=en 是一个完整的 URL，其中：https:// 是协议，www.example.com 是域名，/about 是路径，?lang=en 是查询参数。

## encrypted LVM
1. encrypted: 启用加密后，只有使用正确的密码或密钥才能读取硬盘上的数据。<br>
2. LVM（Logical Volume Manager，逻辑卷管理器）:LVM 是一种磁盘管理方法，允许灵活地分配硬盘空间。它将物理硬盘分区抽象成逻辑卷，用户可以更轻松地调整卷的大小或添加新的卷（没搞懂具体含义，但核心是逻辑卷可以动态调整大小）

## GRUB
GRUB（GRand Unified Bootloader）: 是一个广泛使用的启动加载程序。它负责在计算机启动时引导操作系统。GRUB 允许用户选择不同的操作系统或内核版本来启动。

## Sodu
### sodu(Superuser do)
允许普通用户临时以超级用户（root 用户）的身份执行命令。超级用户通常拥有系统上的所有权限，包括对系统文件和设置进行更改的能力。
### su
切换到 root 用户（超级用户），从而获得系统管理员权限。

## Shell
### What is Shell
Shell:是一种电脑系统与用户交互的命令行界面（CIL：Command-Line Interface），在图形用户界面（GUI：Graphical User Interface）出现前，它是我们操作电脑的主要方式。
### Bash Shell
1. Bash Shell:是一种广泛应用于Unix/Linux操作系统的shell。
2. Bash Prompt:在使用Bash时的提示符。<br>
Eg. user@hostname:~$<br>
user：当前登录的用户名。<br>
hostname：计算机的主机名。<br>
~：当前工作目录（在用户的主目录时显示为 ~，否则会显示为相对路径）。<br>
$：表示普通用户（如果是 #，则表示超级用户 root）。<br>

## Shell Command
### Basic
#### apt install *toolsname(sudo/vim/nano)*
apt: Advanced Package Tool，是Debian及其衍生版（Ubuntu）所使用的高级管理工具包。<br>
install: apt的子命令。<br>
sudo: superuser do工具，用于允许普通用户临时以超级用户（root 用户）的身份执行命令。<br>
#### sudo apt update
update the apt list（will not download any of them until the user asking to）
#### sudo reboot
sudo：允许普通用户临时以超级用户（root 用户）的身份执行命令。<br>
reboot: 重启计算机。<br>
#### sudo -V
-V: equals to “sudo --version”,检查当前sudo工具的版本。
#### sudo adduser *username*
adduser: add an new user
#### sudo addgroup *groupname*
addgroup: add a new group.
*GID: group identifier， in short, group ID
#### sudo adduser *username* *groupname* 
add the user *username* to the group *groupname*<br>
*sudo is also a group.

### SSH
#### What is SSH?
SSH: Secure Shell. The SSH protocol was designed as a secure alternative to unsecured remote shell protocols. It utilizes a client-server paradigm, in which clients and servers communicate via a secure channel.
#### sudo apt install openssh-server
To install the specific server for SSH.
#### sudo service ssh status
To check the current status of the SSH service.
#### vim /etc/ssh/sshd_config
sshd_config:sshdaemon_configuration,是 SSH 服务器的核心配置文件，控制着 SSH 服务器的各种行为。<br>
d：daemon，守护进程，是一个在后台运行的计算机程序，通常不直接与用户交互，而是提供某种服务。例如，sshd 是一个负责处理所有传入 SSH 连接请求的守护进程。<br>
#### About sshd_config
1. Remove #: 启用配置项。在配置文件中，以 # 开头的行通常是注释行。这些行可能包含解释说明、默认配置的提示或被临时禁用的配置项。注释行不会对程序产生任何影响，因为它们不会被解析或执行。<br>
2. Port：<br>
(1)作用：在网络通信中，IP 地址用于标识一台设备（如计算机、服务器或路由器），而端口号用于标识设备上运行的特定应用程序或服务。端口通常对应某种特定的系统协议或服务。每个端口号与一种特定的网络服务或协议相关联，这使得计算机能够在同一个 IP 地址下区分不同的通信请求。<br>
*修改了ssh的端口号就像我们把加密房间的门牌号改了，当黑客攻击的时候，其实他们攻击错了房间（ssh的默认端口号为22）。<br>
*所有协议的端口号理论上都可以修改，只是为了方便和标准化，大家通常使用默认的端口号。<br>
(2)端口转发：Port Forwarding Rules.在NAT（Network Address Translation）模式下，虚拟机的内部端口4242对宿主机（原计算机及其系统）及外部网络不可见，必须要设置端口转发规则，以便外部网络通过宿主机的端口（如 8080）访问虚拟机中的服务。<br>
3. PermitRootLogin<br>
(1)作用：指是否允许使用 SSH 协议安全地远程连接到另一台计算机，进行系统管理和文件操作。它通过加密和身份验证机制保护数据传输安全，是远程管理服务器和网络设备的标准工具。<br>
(2)类型：<br>
PermitRootLogin prohibit-password：允许 root 用户通过 SSH 登录，但禁止使用密码认证。这种设置是提高安全性的推荐配置，因为它允许使用更安全的密钥认证方式，同时防止了密码暴力破解攻击。<br>
PermitRootLogin no：完全禁止 root 用户通过 SSH 登录，提供最高的安全性。<br>
PermitRootLogin yes：允许 root 用户通过 SSH 登录，适合对安全要求较低的环境，但风险较高。<br>
