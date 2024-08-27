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
