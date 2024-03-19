### 信息收集
sudo arp-scan 扫描开放主机
nmap扫描开放端口，得到开放端口较多，筛选取出

```
ports=$(grep open nmapscan/ports/my_file_server.nmap | awk -F '/' '{print $1}' | paste -sd ',') 
将端口取出存放在ports变量中

21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
445/tcp  open  microsoft-ds
2049/tcp open  nfs
2121/tcp open  ccproxy-ftp

默认脚本漏洞扫描无多余信息

按照优先级先访问ftp，smb web nfs ssh
```
### FTP渗透
```
FTP 允许匿名登录，看看有无可用信息

anonymous 无密码匿名登录成功
Binary 切换至二进制传输模式
prompt 关闭交互

在/pub/log/下存在目录及文件，将可读文件下载本地，读取信息
mget *.*

读取无可用信息
```

### Samba渗透
```
1.使用smbmap 扫描samba下的目录

2.开放了smbdata可匿名登录目录
和smbuser 不允许访问的目录

3.smbclient登录
smbclient //192.168.1.9/smbdata
lcd 可切换本地目录
mget 将所有可读文件下载

4.看到了secure文件，文件提到了关于用户组的操作，
信息中显示有smbuser的用户操作

sshd_config中暴露出ssh存放路径
AuthorizedKeysFile      .ssh/authorized_keys
```

### nfs渗透
```
Export list for 192.168.1.9:
/smbdata 192.168.56.0/24

显示共享目录也是smbdata，但是只允许ip为56网段的用户
优先级排后
```

### web
```
源码无信息，
dirsearch 目录爆破，显示存在readme.txt,访问直接告诉我们密码为:rootroot1
```

### 用户登录
```
ftp 192.168.1.9 
用户为smbuser 密码为rootroot1登录成功，pwd在smbuser home目录下

尝试用此账户密码ssh登录，发现，拒绝登录，要有ssh密钥文件
ssh-keygen 生成公私钥，将私钥上传在smbuser/.ssh/ 下改为authorized_keys文件
私钥存在本地.ssh/下
ssh -i 可以指定本地私钥目录，登录成功
```

### 提权
```
s位和可写文件无有用文件，无自动任务

尝试内核提权
Linux fileserver 3.10.0-229.el7.x86_64 #1 SMP Fri Mar 6 11:36:42 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

CentOS Linux release 7.7.1908 (Core)
版本3.1在dirty cow 版本内，搜索有无可利用文件

40616有个关于suid的提权.c文件，在靶机本地编译执行

gcc 40616.c -o exp 
显示错误，要指定-pthread，警告，但是exp已经生成

运行提权成功


```


