# Grandpa Writeup w/ Metasploit

![](https://miro.medium.com/max/591/1*wourt1uR7Cu9Q-cp-eIo1w.png)

## Reconnaissance <a id="4e50"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.14 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.14Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:29 EST
Nmap scan report for 10.10.10.14
Host is up (0.043s latency).
Not shown: 999 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 7.19 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:29 EST
Nmap scan report for 10.10.10.14
Host is up (0.037s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Error
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Mon, 17 Feb 2020 20:31:32 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  WebDAV type: Unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.32 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:29 EST
Nmap scan report for 10.10.10.14
Host is up.                                                                                                                                            
All 1000 scanned ports on 10.10.10.14 are open|filtered                                                                                                
                                                                                                                                                       
Nmap done: 1 IP address (1 host up) scanned in 201.72 seconds                                                                                          
                                                                                                                                                       
                                                                                                                                                       
                                                                                                                                                       
---------------------Starting Nmap Full Scan----------------------                                                                                     
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:32 EST                                                                                        
Initiating Parallel DNS resolution of 1 host. at 15:32                                                                                                 
Completed Parallel DNS resolution of 1 host. at 15:32, 0.43s elapsed                                                                                   
Initiating SYN Stealth Scan at 15:32
Scanning 10.10.10.14 [65535 ports]
Discovered open port 80/tcp on 10.10.10.14
....
Nmap scan report for 10.10.10.14
Host is up (0.039s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  httpRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 263.21 seconds
           Raw packets sent: 131268 (5.776MB) | Rcvd: 214 (10.752KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                       
Running CVE scan on basic ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:37 EST
/usr/local/bin/nmapAutomator.sh: line 226:  2251 Segmentation fault      $nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"$1".nmap "$1"Running Vuln scan on basic ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:37 EST
/usr/local/bin/nmapAutomator.sh: line 226:  2253 Segmentation fault      $nmapType -sV --script vuln -p$(echo "${ports}") -oN nmap/Vulns_"$1".nmap "$1"---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                       
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.asp,.php -u http://10.10.10.14:80 -o recon/gobuster_10.10.10.14_80.txt
nikto -host 10.10.10.14:80 | tee recon/nikto_10.10.10.14_80.txtWhich commands would you like to run?                                                                                                                  
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                       
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.14:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,asp,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/17 15:38:11 Starting gobuster
===============================================================
http://10.10.10.14:80/_vti_bin (Status: 301) [Size: 158]
http://10.10.10.14:80/_vti_bin/_vti_aut/author.dll (Status: 200) [Size: 195]
http://10.10.10.14:80/_vti_bin/_vti_adm/admin.dll (Status: 200) [Size: 195]
http://10.10.10.14:80/_vti_bin/shtml.dll (Status: 200) [Size: 96]
===============================================================
2020/02/17 15:39:06 Finished
===============================================================Finished gobuster scan
                                                                                                                                                       
=========================
                                                                                                                                                       
Starting nikto scan
                                                                                                                                                       
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2020-02-17 15:39:07 (GMT-5)
--------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPPATCH COPY LOCK PROPFIND MKCOL UNLOCK SEARCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ Retrieved x-aspnet-version header: 1.1.4322
+ 8014 requests: 0 error(s) and 22 item(s) reported on remote host
+ End Time:           2020-02-17 15:45:00 (GMT-5) (353 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                       
=========================
                                                                                                                                                       
                                                                                                                                                       
                                                                                                                                                       
---------------------Finished all Nmap scans---------------------Completed in 15 minute(s) and 46 second(s)
```

We have one port open.

* **Port 80:** running Microsoft IIS httpd 6.0

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The only port that is open is port 80 so this will definitely be our point of entry. The port is running an outdated version of Microsoft IIS and is using the WebDAV protocol. One thing that pops out right away is the number of allowed HTTP methods. As mentioned in the scan results, these methods could potentially allow you to add, delete and move files on the web server.

## Enumeration <a id="063c"></a>

Visit the web application in the browser.

![](https://miro.medium.com/max/565/1*gV1XwZQATrEYcYyVhT2Q7g.png)

Look into the directories/files that gobuster found. We don’t find anything useful. Next, let’s test the allowed HTTP methods.

The scan shows that the HTTP PUT method is allowed. This could potentially give us the ability to save files on the web server. Since this is an IIS Microsoft web server, the type of files it executes are ASP and ASPX. So let’s check if we’re allowed to upload these file extensions.

```text
davtest --url http://10.10.10.14
```

We get back the following result.

![](https://miro.medium.com/max/826/1*o7yQ8L1djScSYbMvs2bZSg.png)

Unlike the [Granny box](https://medium.com/@ranakhalil101/hack-the-box-granny-writeup-w-o-and-w-metasploit-f7a1c11363bb), there are restrictions put in place that don’t allow us to upload files, so this won’t be the way we gain initial access to the box. Next, let’s run searchsploit on the web server version.

![](https://miro.medium.com/max/1382/1*EWgvfAf1pdhGGXt_GPlIUg.png)

Microsoft IIS 6.0 is vulnerable to a remote buffer overflow.

**Note**: Several people I know have tried to solve this box without using Metasploit and have failed to because the shell you get back is too unstable. Therefore, I’ll be solving this box using Metasploit.

## Initial Foothold <a id="03d0"></a>

Start up Metasploit.

```text
msfconsole
```

Viewing the exploit on [exploitdb](https://www.exploit-db.com/exploits/41738) we get a CVE \# [2017–7269](https://nvd.nist.gov/vuln/detail/CVE-2017-7269). Let’s see if Metasploit has an exploit for it.

![](https://miro.medium.com/max/1416/1*YSeviXOxwO4jvqqEELLxtQ.png)

It does. Let’s switch to that exploit and configure the RHOST to the Grandpa IP address.

![](https://miro.medium.com/max/1424/1*gcPLwfg5k7yYp-us-t_RJg.png)

Then run the exploit.

![](https://miro.medium.com/max/1231/1*dogBmAWzkg1mkambZ6GFHw.png)

We get a shell! However, when we run the “_getuid_” command, we get an operation failed error. This is because we’re running in an unstable process. To fix that, let’s see which processes are running on the box and migrate to one that is running with the same privileges that the meterpreter session is running with.

![](https://miro.medium.com/max/1411/1*_dxjVa8Pcoi_1SxbhViQcw.png)

Let’s migrate to process \# 2172 and try running the “_getuid_” command again.

![](https://miro.medium.com/max/873/1*d0cLgfl2DsWaizomawPdZQ.png)

Perfect! We have a stable working meterpreter session. We’re running with low privileges, so we’ll need to escalate our privileges to SYSTEM.

## Privilege Escalation <a id="580f"></a>

Background the meterpreter session.

![](https://miro.medium.com/max/682/1*uMOV4-rYPWbv1RBMqOW_IQ.png)

We’ll use the Local Exploit Suggester module to check the box for local vulnerabilities.

![](https://miro.medium.com/max/1418/1*4NEdHnwrClCg9Ic-pJ7LHQ.png)

Run the Local Exploit Suggester.

![](https://miro.medium.com/max/1418/1*McLipzNT4p9QlBHrW-bOrw.png)

We’ll use MS14–070 to escalate privileges.

![](https://miro.medium.com/max/1414/1*SAuuUM8WBkbEuQqw_Kn3Hw.png)

The exploit was successful! Let’s go back and enter our meterpreter session and view our privilege level.

![](https://miro.medium.com/max/1251/1*Dek6r7bgOFKEtAAabaQ5ew.png)

We’re SYSTEM! Grab the _user.txt_ and _root.txt_ flags.

![](https://miro.medium.com/max/1335/1*tThZ91D2TDVHxdqInHbLXQ.png)

## Lessons Learned <a id="a815"></a>

We gained initial access to the machine and escalated privileges by exploiting known vulnerabilities that had patches available. So it goes without saying, you should always update your software!

