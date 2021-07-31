---
title: TheNoteboook Writeup [HTB]
tags: [HackTheBox, Docker, Json Web Token]
image: /assets/images/thenotebook/thenotebook.png
published: true
banner: true
---

The Notebook is a Linux based that was active since March 6th of 2021 to July 1st, on this machine we will get to a webpage that uses Json Web Tokens, testing it we see that it set the link of the key of tokens on the token itself, so we will generate a pair of keys, sign our own token and point the key to us so it gets validated, with that we will get access to a file upload function that will allow us to upload arbitrary files, so we upload a php reverse shell file, after that we will find a backup file containing the ssh key of a user, this uses have the privileges to run commands on a specific container, we will see that the machine runs an old version of docker, which is vulnerable to CVE 2019-5736, so using a poc that we got on Github we will get access as root on the machine.

# [](#header-1)Enumeration

We start using masscan to find all the available ports and then use nmap to get more information about them.

```
masscan -e tun0 --rate=500 -p 0-65535 10.10.10.230
nmap -sC -sV -p 80,22, -Pn -o scan.txt 10.10.10.230

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are only two port open, ssh and a webpage on port 80, let's see what is there.

![](/assets/images/thenotebook/webpage.png)

The page is a site where we can store notes, we register an account an see what we can do on it. Checking the requests with burp we notice that the site uses Json Web Tokens, so we go to [jwt.io](https://jwt.io/) to see what information is using the site.

![](/assets/images/thenotebook/jwt.png)

# [](#header-1)Gaining Access

There are two things that quickly call our attention, first the key ID, it retrieves a private key file from a webserver that isn't exposed on the machine, and second the value "admin_cap" is set to 0. Json Web Tokens are really flexible, so we can think that the server is retrieving the private key that signed the token and uses it to verify it, so first we generate a pair of key for RS256.

```
ssh-keygen -t rsa -b 4096 -m PEM -f privKey.key
openssl rsa -in privKey.key -pubout -outform PEM -out privKey.key.pub
```

Now that we have a private key let's generate a token that points to our http server and sets "admin_cap" to 1.

![](/assets/images/thenotebook/generate.png)

As we expected the private key is retrieved from the server for every request that we make, and now we have access to some admin functions, first some notes and an upload file function.
Along the notes we find two interesting ones, first: `Finally! Regular backups are necessary. Thank god it's all easy on server.`, so there are backups, we should check for them as soon as we can, and second: `Have to fix this issue where PHP files are being executed :/. This can be a potential security issue for the server.`, PHP files are executed, we where going to test for it anyways, but it saves us some minutes, so we prepare a PHP reverse shell file, upload it through the upload file function, and get a shell to the machine.

![](/assets/images/thenotebook/shell1.png)

# [](#header-1)Lateral Movement

As we saw on another note, there is potencially backup file, so we check /var/backups, and see a file called, home.tar.gz.

![](/assets/images/thenotebook/backups.png)

After decompressing the file we find out that it it's the whole /home, directory, containing the home directory of noah user, including his ssh keys, so now we can connect through ssh to the machine and retrieve user.txt.

![](/assets/images/thenotebook/shell2.png)

# [](#header-1)Privilege Escalation

Now that we have a new user we check if we can run anything with sudo.

![](/assets/images/thenotebook/sudo.png)

We can execute commands on the container "webapp-dev01", or anyone that starts with the same name, since it's just executing on an existing container we can't go with the common privilege escalation technique of creating a container and mapping the whole system on it, on this case we most likely will have to escape from that container, if we check the version of docker we get, `Docker version 18.06.0-ce, build 0ffa825`, so try our luck with searchsploit.

![](/assets/images/thenotebook/searchsploit.png)

We find some PoCs to breakout of the container if the version is lower to 18.09.2, this vulnerabily is identified by CVE 2019-5736, we find a more reliable PoC on [github](https://github.com/Frichetten/CVE-2019-5736-PoC) written in go. We modify the 16th line with our payload, in our case we will host a reverse bash shell, get it with curl and pipe it to bash.

![](/assets/images/thenotebook/payload.png)

So now we just have to compile it running `go build main.go`, access to a container, upload the file and execute it.

![](/assets/images/thenotebook/runpay.png)

And when we try to access to a container and run sh, `sudo docker exec -it webapp-dev01 /bin/sh`, our payload will be executed and we will get access as root.

![](/assets/images/thenotebook/root.png)