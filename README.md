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
1. CPU (Central Processing Unit)
The CPU is the worker, responsible for executing instructions in computer programs and performing data processing and calculations.<br>
Note: Modern computers usually have multiple CPUs, and setting the CPU count determines the number of CPUs allocated to the virtual machine.<br>

3. RAM (Random Access Memory)
RAM is the CPU's working area, which is used to temporarily store the operating system, applications, and data currently in use. When a program ends or the device loses power, the RAM will be cleared.<br>
Note: When creating a virtual machine, setting RAM is equivalent to setting Base Memory.<br>

RAM Hardware:<br>
RAM Modules: RAM is typically packaged in modules known as DIMMs (Dual Inline Memory Modules) for desktops and SO-DIMMs (Small Outline DIMMs) for laptops. These modules contain multiple RAM chips mounted on a circuit board.<br>

RAM Chips:<br>
Each RAM module contains several chips, often made of silicon. These chips are the actual memory cells that store data. Common types include:<br>
DRAM (Dynamic RAM): Requires periodic refreshing to maintain data.<br>
SRAM (Static RAM): Faster and more reliable but more expensive; used in cache memory.<br>


HDD (Hard Disk Drive): The hard disk is the archive for the CPU, used for long-term storage of the operating system, applications, and data.
*Hard Disk File: A virtual hard disk file that simulates the function of a physical hard drive for long-term storage of the operating system, applications, and data. Different types are simply due to their suitability for different hypervisor platforms:
(1) VDI (VirtualBox Disk Image) - Oracle VirtualBox
(2) VHD (Virtual Hard Disk) - Microsoft Hyper-V
(3) VMDK (Virtual Machine Disk) - Virtual Machine Disk



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
解释：I/O Log Data Recorder，指定日志目录的位置，用于存放 sudo 命令的输入和输出日志。在此例中，日志文件将存储在 /var/log/sudo 目录中。<br>
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
是一个自动执行的shell命令集合文件。<br>

#### #！/bin/bash
#!： 这是一个特殊的字符序列，称为 shebang。它告诉操作系统使用指定的解释器来执行脚本文件中的内容。<br>
/bin/bash： 这是解释器的路径。在这个例子中，/bin/bash 指定了脚本应由 Bash 解释器来执行。<br>

#### 获取架构信息  arch=$(uname -a)
1. uname -a
uname：UNIX name， 用于显示操作系统的名称、版本和其他系统信息。它通常用于获取有关系统的一些基本信息。
-a：all， 用于请求 uname 命令显示所有可用的信息。包括操作系统名称、内核版本、主机名、处理器架构等。
uname -a 的输出信息.

1. arch= 是将 arch 变量赋值的操作。<br>
2. $(uname -a) 是命令替换的语法，表示将 uname -a 命令的输出结果作为 arch 变量的值。<br>


#### 获取物理和虚拟CPU 核心数量
#### cpuf=$(grep "physical id" /proc/cpuinfo | wc -l)
#### cpuv=$(grep "processor" /proc/cpuinfo | wc -l)
1. grep "physical id" /proc/cpuinfo
grep: globally search a regular expression and print, 是一个用于搜索文本的工具。<br>
"physical id" 是我们要搜索的模式，它是 grep 要在 /proc/cpuinfo 文件中查找的字符串。每个物理 CPU 核心的信息通常包含 "physical id"。<br>
/proc/cpuinfo 是一个虚拟文件，包含了关于 CPU 的各种信息。<br>
2. grep "processor" /proc/cpuinfo 
processor："processor" 是我们要搜索的模式，它是 grep 要在 /proc/cpuinfo 文件中查找的字符串。processor条目反映了操作系统看到的逻辑 CPU 数量。每个条目代表一个系统可以调度的逻辑处理单元，不管它是物理 CPU 核心还是通过超线程技术（一个物理cpu跑两个线程）创建的虚拟 CPU。<br>
3. | (管道符)
管道符将前一个命令的输出传递给下一个命令。<br>
在这里，grep 命令的输出（即所有包含 "physical id" 的行）被传递给 wc -l 命令。<br>
4. wc -l
wc：wordcount，是一个用于计算文本文件中行数、字数和字符数的工具。<br>
-l: --lines，选项表示计算行数。<br>
因此，wc -l 会计算 grep 命令输出的行数，即包含 "physical id" 的行数。<br>
5. cpuf=$(...)
$(...) 是命令替换的语法，用于执行括号中的命令并将其输出结果赋值给变量 cpuf。<br>
**实际效果**
grep "physical id" /proc/cpuinfo 会输出所有包含 "physical id" 的行。这些行代表了每个物理 CPU 核心的一个条目。<br>
wc -l 会计算这些行的总数，这个数量表示物理 CPU 核心的数量。<br>

#### 获取内存使用情况
#### ram_total=$(free --mega | awk '$1 == "Mem:" {print $2}')
#### ram_use=$(free --mega | awk '$1 == "Mem:" {print $3}')
#### ram_percent=$(free --mega | awk '$1 == "Mem:" {printf("%.2f%%"), $3/$2*100}')
1. free --mega
free: 是一个命令行工具，用于显示系统的内存使用情况。
--mega: 表示输出的内存信息以 MB（兆字节）为单位显示。
2. |（管道符）
将 free --mega 命令的输出传递给 awk 命令。
3. awk '$1 == "Mem:" {print $2}':
awk: Aho, Weinberger, 和 Kernighan（三个创始人的名字），是一个强大的文本处理工具，用于对文本中的数据进行模式匹配和操作。
$1 == "Mem:" 表示匹配第一列（字段）为 "Mem:" 的行。
{print $2} 表示输出该行的第二列的值，也就是总内存(ram_total)的大小。
{print $3} 表示输出该行的第三列的值，也就是已用内存(ram_use)的大小。
4. {printf("%.2f%%"), $3/$2*100}<br>
printf：这是 awk 中的格式化输出函数，类似于 C 语言中的 printf。<br>


"%.2f%%"：
%：标识符，表示这个地方将插入一个变量的值。<br>
.2f：格式说明符，表示输出一个浮点数，保留两位小数。<br>
%%：表示输出一个百分号 %。在格式字符串中，%% 是转义字符，用来表示实际的百分号。<br>


$3/$2*100：<br>
$2：在 awk 中，$2 表示当前行的第二列。对于 free 命令输出的内存信息，第二列通常代表 总内存（Total Memory）。<br>
$3：$3 表示当前行的第三列，通常代表 已用内存（Used Memory）。<br>
$3/$2：表示已用内存占总内存的比例。<br>
$3/$2*100：将上一步的比例乘以 100，以得到一个百分比值，表示已用**内存占总内存的百分比**。<br>

5. ram_total=$(...)
$(...) 是命令替换的语法，将 awk 命令的输出结果赋值给变量 ram_total。

#### 获取磁盘使用情况
####  disk_total=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_t += $2} END {printf ("%.1fGb\n"), disk_t/1024}')
####  disk_use=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_u += $3} END {print disk_u}')
####  disk_percent=$(df -m | grep "/dev/" | grep -v "/boot" | awk '{disk_u += $3} {disk_t+= $2} END {printf("%d"), disk_u/disk_t*100}')
1. df -m<br>
df: disk free, 是显示文件系统磁盘空间使用情况的命令。<br>
-m: --mega, 表示以 MB 为单位显示。<br>
2. grep "/dev/"<br>
grep: 用于在 df 的输出中筛选出包含 /dev/ 的行，这些行通常表示挂载的磁盘分区。<br>
grep -v "/boot"：<br>
grep -v : --invert-match, 用于排除包含 /boot 的行，确保不包含 /boot 分区的统计。<br>
*排除 /boot 分区通常是因为 /boot 分区是系统专用的、较小的独立分区，主要用于存放引导加载程序（如 GRUB）和内核映像。它在系统启动过程中发挥关键作用，但对日常使用来说，其磁盘空间使用情况通常不太重要，且容量很小，不会对整体磁盘使用统计产生显著影响。<br>
3. awk '{disk_t += $2} END {printf ("%.1fGb\n"), disk_t/1024}'<br>
awk: 是一个强大的文本处理工具。<br>
disk_t += $2: 累积每个匹配行的第二列（即分区的总大小）。<br>
END {printf ("%.1fGb\n"), disk_t/1024}: 表示在所有行处理完毕后，将累积的磁盘总大小（disk_t）除以 1024（将 MB 转换为 GB），并格式化为小数点后一位的数字后加上 "Gb" 输出。<br>
最终结果：disk_total 保存的是系统中 /dev/ 下所有磁盘分区的总大小（不包括 /boot），以 GB 为单位。<br>
4.awk '{disk_u += $3} END {print disk_u}')：
disk_u += $3: 累积每个匹配行的第三列（即已用空间的总大小）。<br>
最终结果：disk_use 保存的是系统中 /dev/ 下所有磁盘分区的已用空间，以 MB 为单位。<br>
5.awk '{disk_u += $3} {disk_t+= $2} END {printf("%d"), disk_u/disk_t*100}')<br>
最终结果：disk_percent 保存的是系统中 /dev/ 下所有磁盘分区的使用百分比。<br>

#### 获取 CPU 负载
#### cpul=$(vmstat 1 2 | tail -1 | awk '{printf $15}')
#### cpu_op=$(expr 100 - $cpul)
#### cpu_fin=$(printf "%.1f" $cpu_op)
1. vmstat 1 2：<br>
vmstat: 是一个显示系统内存、进程、CPU 活动等的工具。<br>
1 2: 表示 vmstat 将每秒输出一次数据，总共输出两次。第二次输出包含了完整的统计数据。<br>
*为什么我们需要输出两次：当你运行 vmstat 时，第一次输出通常是初始的统计信息，不一定能反映系统当前的实时状态。这是因为在采集和报告系统性能数据时，数据需要一定的时间来稳定。<br>
tail -1： 从 vmstat 的输出中取最后一行。这一行包含了最新的统计数据。<br>
2. awk '{printf $15}'：<br>
awk : 用于从最后一行中提取第 15 列数据，通常这列代表 CPU 空闲时间的百分比（在不同的 vmstat 版本中，列的位置可能有所不同）。<br>
printf:  用于格式化输出，实际上在这里 printf 只是将 $15 的值直接输出，没有格式化作用。<br>
3. expr 100 - $cpul：<br>
expr：expression, 是一个用于计算表达式的工具。<br>
100 - $cpul： 计算 CPU 的空闲时间百分比与 100 的差值，得到 CPU 的使用率。<br>
4. printf "%.1f"：<br>
printf: 用于格式化输出。<br>
"%.1f": 表示将 $cpu_op 格式化为保留一位小数的浮点数。<br>

#### 获取系统最后启动时间    lb=$(who -b | awk '$1 == "system" {print $3 " " $4}')
1. who -b<br>
who -b： --boot, 输出系统的最后启动时间信息。<br>
2. awk '$1 == "system" {print $3 " " $4}'<br>
$1 == "system"： 表示匹配第一列（字段）为 "system" 的行。<br>
{print $3 " " $4}： 如果条件满足，打印第三列和第四列的内容（“ ”表示中间插入一个空格），即启动日期和时间。<br>

#### 检查系统中是否存在lvm设备
#### if [ $(lsblk | grep "lvm" | wc -l) -gt 0 ]; then
####    echo yes
#### else
####    echo no
#### fi
1. lsblk<br>
列出系统中所有的块设备（如硬盘、分区等）。它显示设备的名称、大小、类型等信息。<br>
2. grep "lvm"<br>
grep "lvm"：在 lsblk 的输出中查找包含 "lvm" 的行。LVM 相关的设备通常在 lsblk 输出中标记为 "lvm"。<br>
3. wc -l<br>
wc -l：计算行数。这里，它用于计算 grep "lvm" 命令找到的行数。即，计算系统中 LVM 设备的数量。<br>
4. -gt 0：--greater-than，测试lsblk 输出中包含 "lvm" 的行数是否大于 0。<br>
5. then：如果条件为真（即 LVM 设备的数量大于 0），则执行 then 后面的命令。<br>
6. else：如果条件为假，则执行 else 后面的命令。<br>
7. f获取网络状态和统计信息i：结束 if 语句块的标记。<br>

#### 获取当前处于 ESTABLISHED 状态的 TCP 连接数    tcpc=$(ss -ta | grep ESTAB | wc -l)
1. TCP链接<br>
TCP：Transmission Control Protocol。是两个网络端点（如计算机或服务器）之间建立的一种连接，用于数据的双向传输。每个连接都有一个唯一的标识符，由源 IP 地址、源端口号、目标 IP 地址和目标端口号共同组成。<br>
2. ss -ta<br>
ss：显示套接字（socket）统计信息。<br>
-t：显示 TCP 套接字的信息。<br>
-a：显示所有的套接字，包括监听和非监听状态。<br>
3. grep ESTAB<br>
grep ESTAB：在 ss -ta 的输出中查找包含 "ESTAB" 的行,即 "ESTABLISHED"（已建立）。这是一个 TCP 连接状态，表示连接已成功建立并处于活动状态。<br>
4. wc -l<br>
wc -l：计算行数。这里，它用于计算grep ESTAB命令找到的行数。即，当前处于 ESTABLISHED 状态的 TCP 连接数。<br>

#### 获取当前登录用户数    ulog=$(users | wc -w)
1.  users<br>
users: 显示当前登录系统的所有用户的用户名。它以空格分隔用户名，表示每个登录的用户。<br>
Eg. alice bob charlie<br>
2. wc -w<br>
wc -w：word count --words， 统计输入中的单词数量。<br>

#### 获取网络信息
#### ip=$(hostname -I)
#### mac=$(ip link | grep "link/ether" | awk '{print $2}')
1. hostname -I<br>
hostname： 这是一个用于显示系统的主机名的命令。<br>
-I： 这是 hostname 命令的一个选项，用于显示所有网络接口的 IP 地址，多个地址用空格分隔。如果系统有多个网络接口，这个选项会列出所有分配给接口的 IP 地址。<br>
2. ip link<br>
ip link：是 ip 命令的一部分，用于显示网络接口的详细信息，包括接口的名称、状态、MAC 地址等。<br>
3. grep "link/ether"<br>
grep "link/ether"：从 ip link 命令的输出中筛选出包含 "link/ether" 的行。这个字段表示网络接口的 MAC 地址。<br>
4. awk '{print $2}'<br>
'{print $2}'：指定 awk 从每行的第二个字段打印内容。在这个上下文中，第二个字段是 MAC 地址。<br>
*IP Adress: Internet Protocol Address， 是一个数字标签，用于在网络上唯一标识每一个设备。它有两个主要版本：IPv4 和 IPv6。IPv4：由四个十进制数（每个数在0到255之间）组成，如 192.168.1.1。IPv6：由八组十六进制数（每组由四个十六进制数字组成）和冒号分隔符组成，如 2001:0db8:85a3:0000:0000:8a2e:0370:7334。<br>
*MAC Adress: Media Access Control Address， MAC 地址 是网络接口卡（NIC）或网络适配器的唯一硬件地址。它通常由制造商在硬件中预设，用于网络层上的唯一标识。它的格式为六组两位十六进制数字（例如 00:1A:2B:3C:4D:5E）。<br>

#### 获取 sudo 命令使用次数    cmnd=$(journalctl _COMM=sudo | grep COMMAND | wc -l)
1. journalctl _COMM=sudo<br>
journalctl：journal control, 用于查看和查询系统日志的命令，通常用于访问 systemd 日志。<br>
_COMM=sudo：command=sudo，这是 journalctl 的一个过滤器，表示只显示 sudo 命令产生的日志条目。_COMM 是一个字段，表示命令名称。<br>

#### 将所有收集的信息显示在所有登录用户的终端上
wall“……”： 这个命令用于向所有登录用户发送广播消息（如果同时登陆了三个用户，就会在终端上看到三条消息）。它通常用于在系统上向所有用户显示一条消息。<br>

## Crontab
### What is Crontab?
crontab: cron table，它定义了由 cron 守护进程执行的任务和时间表。是 Linux 和 Unix 系统中的一个用于定时执行任务的工具。它可以通过设置特定的时间计划（即所谓的 "cron 表达式"）来定期执行脚本、命令或程序。<br>
### sudo crontab -u root -e
1. -u: user, 选项指定了你要操作哪个用户的 crontab 文件。这里的 root 指的是系统的超级用户（管理员）。通常，系统级的计划任务需要由 root 用户管理。<br>
2. -e: edit, 用于编辑指定用户的 crontab 文件。当你运行 crontab -e 时，系统会打开一个文本编辑器（通常是 vi 或 nano），让你编辑 crontab 文件中的任务。<br>
### */10 * * * * sh /home/mzhang/monitoring.sh
1. 时间表达式部分：*/10 * * * *<br>
*/10：表示每10分钟运行一次。在 60 分钟的一个小时内，*/10 的步长会按 10 分钟为间隔，分别触发在以下时间：0, 10, 20, 30, 40, 50分钟。<br>
*：其他的星号表示小时、日期、月份和星期几的字段，因为这里都设置为 *，所以表示无论小时、日期、月份、星期几如何，都执行任务。<br>
2. 命令部分：sh /home/mzhang/monitoring.sh<br>
sh：这是调用 sh 命令解释器来执行脚本。sh 是一个常用的 Unix shell（通常是 Bourne Shell 或其兼容版本），用于解释和执行脚本文件中的命令。<br>

## SHA    shasum Born2beroot.vdi
### What is SHA?
1. 文件内容：SHA （Secure Hash Algorithm）算法将整个文件的内容作为输入，逐字节地进行处理。<br>
2. 生成哈希值：通过一系列复杂的数学运算，SHA 算法将这些字节数据压缩并转换成一个固定长度的哈希值。<br>
### Why do we choose SHA?
1. 内容敏感：任何对文件内容的改变（即使是一个字节的不同）都会导致生成的 SHA 值完全不同。<br>
2. 唯一性：理论上，不同内容的文件会生成不同的 SHA 值，这使得 SHA 值可以唯一地代表文件内容。<br>
3. 完整性验证：因为 SHA 值直接反映了文件内容，所以你可以用它来验证文件是否被修改或损坏。例如，如果你下载了一个文件，你可以将它的 SHA 值与原始的 SHA 值（通常由文件提供者给出）进行比较。如果两者相同，就说明文件在传输过程中没有被篡改。<br>
