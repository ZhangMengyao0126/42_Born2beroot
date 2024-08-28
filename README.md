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
#### sudo service ssh restart
To restart the SSH service.
#### vim /etc/ssh/sshd_config    vim /etc/ssh/ssh_Config
sshd_config:sshdaemon_configuration,是 SSH 服务器的核心配置文件，控制着 SSH 服务器的各种行为。<br>
ssh_config:ssh_configuration,是 SSH 客户端的核心配置文件，控制着 SSH 客户端的各种行为。<br>
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

### UFW
#### What is UFW
UFW(Uncomplicated Firewall)，用于简化和管理 Linux 防火墙规则的工具，它通过简单命令配置和管理基于 iptables 的防火墙规则。
#### sudo apt install ufw
To install the ufw.
#### sudo ufw enable
To active the ufw.
#### sudo ufw allow 4242
To allow all traffic through port 4242 in the firewall.
#### sudo ufw status
To check the current status of the ufw.

### Sudo polocy
#### soduers.d  touch /etc/sudoers.d/sudo_config
soduers.d:soduers.directory，存储 sudo 权限的附加配置文件。这些文件可以独立于主配置文件 /etc/sudoers 进行管理。
#### log mkdir /var/log/sudo
log: 创建 /var/log/sudo 目录并不是强制性的要求，而是一种良好的习惯，主要用于组织和管理日志文件，方便纠错。
#### Defaults passwd_tries=3
解释：设置用户在输入密码时允许的最大尝试次数。如果用户在尝试次数用尽之前没有输入正确的密码，sudo 将会拒绝执行命令。<br>
用途：防止暴力破解攻击，限制密码尝试次数可以增强安全性。<br>
#### Defaults badpass_message='Customized error message'
解释：定制当用户输入错误密码时显示的错误消息。此处的 "Customized error message" 可以被替换为任何希望显示的具体消息。<br>
用途：提供用户友好的错误提示信息，帮助用户理解为什么登录失败。<br>
#### Defaults logfile="/var/log/sudo/sudo_config"
解释：指定 sudo 的日志文件位置。在此例中，日志文件将被记录在 /var/log/sudo/sudo_config 中。<br>
用途：将 sudo 的活动和错误记录到指定的日志文件中，以便进行审计和排查问题。<br>
#### Defaults log_input, log_output
解释：启用对 sudo 命令的输入和输出进行日志记录。log_input 记录命令输入的内容，log_output 记录命令输出的内容。<br>
用途：记录所有 sudo 命令的输入和输出，有助于审计和监控系统的活动。<br>
#### Defaults iolog_dir="/var/log/sudo"
解释：指定日志目录的位置，用于存放 sudo 命令的输入和输出日志。在此例中，日志文件将存储在 /var/log/sudo 目录中。<br>
用途：组织和存储 sudo 的输入和输出日志，以便于管理和查找日志文件。<br>
#### Defaults requiretty
解释：要求 sudo 命令在一个实际的终端（tty:teletypewriter)上运行。这意味着 sudo 需要一个终端环境来执行命令，不能在后台脚本或无终端环境中运行。<br>
用途：增强安全性，防止 sudo 命令在非交互式环境（不涉及用户直接交互的环境）中被滥用。<br>
#### Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
解释：定义 sudo 命令的安全路径。这个路径是在 sudo 执行命令时查找可执行文件的目录。路径中的目录由冒号分隔。<br>
用途：确保 sudo 执行命令时只能访问指定的目录中的可执行文件，防止路径劫持攻击。<br>
*路径劫持攻击的工作原理<br>
1. 搜索路径：操作系统在执行程序时，会根据预定义的搜索路径查找可执行文件或库文件。路径通常由环境变量如 PATH、LD_LIBRARY_PATH、PYTHONPATH 等控制。
2. 路径优先级：在这些路径中，操作系统通常会按顺序查找文件。攻击者可以利用路径优先级，将恶意文件放置在优先级较高的路径中，从而使系统在搜索时先找到恶意文件。
3. 恶意文件：攻击者创建一个与合法文件同名的恶意文件，将其放在路径中优先被查找的位置。当程序试图执行或加载文件时，它实际上执行了恶意文件，从而导致安全漏洞。

### Password
#### login.defs  vim /etc/login.defs
login.defs: 是一个配置文件，在类 Unix 操作系统（如 Linux）中用于设置与用户账户相关的全局默认值。这个文件通常用于定义系统级的账户管理策略，包括用户创建、密码管理以及账户的安全策略。
#### PASS_MAX_DAYS
设置密码的最大有效天数。超过这个天数后，用户需要更改密码。
#### PASS_MIN_DAYS
设置密码的最小使用天数。在这个时间段内，用户不能更改密码。
#### PASS_WARN_AGE
设置在密码过期之前，系统向用户发出警告的天数。


#### libpam-pwquality    sudo apt install libpam-pwquality
是一个用于 PAM（可插拔认证模块）系统的库，提供密码质量检查功能。


#### common-password    vim /etc/pam.d/common-password
common-password 文件包含 PAM 密码管理模块的设置。在这个文件中，管理员可以配置密码策略和检查，例如密码的复杂性、长度要求以及使用密码质量检查模块。
#### minlen=10
设置密码的最小长度为 10 个字符。密码必须至少包含 10 个字符才能被接受。
#### ucredit=-1：
要求密码必须至少包含 1 个大写字母（u 表示 uppercase character）。负值表示要求至少包含这么多的字符。
#### dcredit=-1：
要求密码必须至少包含 1 个数字（d 表示 digit）。负值表示要求至少包含这么多的字符。
#### lcredit=-1：
要求密码必须至少包含 1 个小写字母（l 表示 lowercase character）。负值表示要求至少包含这么多的字符。
#### maxrepeat=3：
设置密码中允许的同一字符连续出现的最大次数为 3 次。
#### reject_username：
不允许密码包含用户名。也就是说，密码不能与用户名相同或包含用户名的部分。
#### difok=7：
要求新密码与旧密码相比，必须有至少 7 个字符不同。
#### enforce_for_root：
强制对 root 用户也应用密码质量检查。


#### sudo chage -l <username>
chage: 是一个用于管理用户密码过期设置的工具。它允许系统管理员设置或查看用户账户的密码过期和有效期信息。
-l: --list, show account aging information
#### sudo chage -m <time> <username>    sudo chage -m 2 root
-m: --minimum, set minimum number of days before password change to MIN_DAYS
#### sudo chage -M <time> <username>    sudo chage -M 30 root
-M: --maximum, set maximum number of days before password change to MAX_DAYS

### Script
#### What is Script?
是一个自动执行的shell命令集合文件。

#### 获取架构信息  arch=$(uname -a)
使用 uname -a 命令获取系统的架构信息，包括内核版本、主机名等。
*语法：
1. arch= 是将 arch 变量赋值的操作。
2. $(uname -a) 是命令替换的语法，表示将 uname -a 命令的输出结果作为 arch 变量的值。


#### 获取物理和虚拟CPU 核心数量  cpuf=$(grep "physical id" /proc/cpuinfo | wc -l)    cpuv=$(grep "processor" /proc/cpuinfo | wc -l)
1. grep "physical id" /proc/cpuinfo:
grep 是一个用于搜索文本的工具。
"physical id" 是我们要搜索的模式，它是 grep 要在 /proc/cpuinfo 文件中查找的字符串。
/proc/cpuinfo 是一个虚拟文件，包含了关于 CPU 的各种信息。每个物理 CPU 核心的信息通常包含 "physical id"。
2. | (管道符)
管道符将前一个命令的输出传递给下一个命令。
在这里，grep 命令的输出（即所有包含 "physical id" 的行）被传递给 wc -l 命令。
3. wc -l
wc 是一个用于计算文本文件中行数、字数和字符数的工具。
-l 选项表示计算行数。
因此，wc -l 会计算 grep 命令输出的行数，即包含 "physical id" 的行数。
4. cpuf=$(...)
$(...) 是命令替换的语法，用于执行括号中的命令并将其输出结果赋值给变量 cpuf。
**实际效果**
grep "physical id" /proc/cpuinfo 会输出所有包含 "physical id" 的行。这些行代表了每个物理 CPU 核心的一个条目。
wc -l 会计算这些行的总数，这个数量表示物理 CPU 核心的数量。
获取内存使用情况：

bash
复制代码
ram_total=$(free --mega | awk '$1 == "Mem:" {print $2}')
ram_use=$(free --mega | awk '$1 == "Mem:" {print $3}')
ram_percent=$(free --mega | awk '$1 == "Mem:" {printf("%.2f"), $3/$2*100}')
总内存 (ram_total) 和已用内存 (ram_use)，单位为 MB。
内存使用百分比 (ram_percent)。
获取磁盘使用情况：

bash
复制代码
disk_total=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_t += $2} END {printf ("%.1fGb\n"), disk_t/1024}')
disk_use=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_u += $3} END {print disk_u}')
disk_percent=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_u += $3} {disk_t+= $2} END {printf("%d"), disk_u/disk_t*100}')
总磁盘空间 (disk_total)，排除 /boot 分区。
已用磁盘空间 (disk_use)。
磁盘使用百分比 (disk_percent)。
获取 CPU 负载：

bash
复制代码
cpul=$(vmstat 1 2 | tail -1 | awk '{printf $15}')
cpu_op=$(expr 100 - $cpul)
cpu_fin=$(printf "%.1f" $cpu_op)
使用 vmstat 命令获取 CPU 空闲百分比 (cpul)。
计算 CPU 负载 (cpu_fin)。
获取系统最后启动时间：

bash
复制代码
lb=$(who -b | awk '$1 == "system" {print $3 " " $4}')
使用 who -b 获取系统最后启动的日期和时间。
检查是否使用 LVM：

bash
复制代码
lvmu=$(if [ $(lsblk | grep "lvm" | wc -l) -gt 0 ]; then echo yes; else echo no; fi)
使用 lsblk 检查是否存在 LVM (逻辑卷管理器) 设备。
获取 TCP 连接数：

bash
复制代码
tcpc=$(ss -ta | grep ESTAB | wc -l)
使用 ss 命令获取 ESTABLISHED 状态的 TCP 连接数。
获取当前登录用户数：

bash
复制代码
ulog=$(users | wc -w)
使用 users 命令获取当前登录的用户数。
获取网络信息：

bash
复制代码
ip=$(hostname -I)
mac=$(ip link | grep "link/ether" | awk '{print $2}')
使用 hostname -I 获取 IP 地址。
使用 ip link 获取 MAC 地址。
获取 sudo 命令使用次数：

bash
复制代码
cmnd=$(journalctl _COMM=sudo | grep COMMAND | wc -l)
使用 journalctl 命令统计 sudo 命令的执行次数。
显示系统信息：

bash
复制代码
wall "	Architecture: $arch
CPU physical: $cpuf
vCPU: $cpuv
Memory Usage: $ram_use/${ram_total}MB ($ram_percent%)
Disk Usage: $disk_use/${disk_total} ($disk_percent%)
CPU load: $cpu_fin%
Last boot: $lb
LVM use: $lvmu
Connections TCP: $tcpc ESTABLISHED
User log: $ulog
Network: IP $ip ($mac)
Sudo: $cmnd cmd"
使用 wall 命令将所有收集的信息显示在所有登录用户的终端上。
