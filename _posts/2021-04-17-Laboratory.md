---
title: Laboratory Writeup [HTB]
tags: [HackTheBox, gitlab]
image: /assets/images/laboratory/laboratory.png
published: true
banner: true
---

Laboratory is an easy rated Linux based machine that was active since November 14th of 2020 to April 17th of 2021, on this machine we will get access to the machine through a vulnerability on an old version of gitlab, reset the password of a gitlab user though gitlab-rails console, and privilege escalate by path hijacking on a suid file.

# [](#header-1)Enumeration

We start using masscan to find all the available ports and then use nmap to get more information about them.

```
masscan -e tun0 --rate=500 -p 0-65535 10.10.10.216
nmap -sC -sV -p 80,443, -Pn -o scan.txt 10.10.10.216

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Service Info: Host: laboratory.htb
```

There is only two ports open, ssh and a webpage on port 443, if we visit the webpage we get redirected to "laboratory.htb", so we add it to our hosts file and visit the webpage.

![](/assets/images/laboratory/webpage.png)

Checking the certificate file we see a subdomain, `git.laboratory.htb`.

![](/assets/images/laboratory/certificate.png)

There we find a gitlab instance, so we register an account to get access to it.

![](/assets/images/laboratory/register.png)

Exploring the available projects we find one project made by "dexter" user, SecureWebsite.

![](/assets/images/laboratory/securewebsite.png)

There isn't anything interestin on it, so we move on, if we go to `https://git.laboratory.htb/help`, we can find the version of gitlab.

![](/assets/images/laboratory/version.png)

# [](#header-1)Gaining Access

Searching for vulnerabilities for that gitlab version we find a [Hackerone report](https://hackerone.com/reports/827052) that explains a vulnerability for arbitrary file read, and RCE on gitlab, to perform the file read we have to create two projects, create an issue with a path traversal description and move the issue to the second project, then the file that we pointed to is appended on the issue, the RCE is got by a cookie deserialization, to do that we have to get the secrets.yml file of gitlab, run a local gitlab instance (the easiest way is using docker container of the exact same version), and set the values of secrets.yml to be the same that we got from the other evironment, if you want to avoid doing all that set up there is an exploit written for metasploit on [packectstorm](https://packetstormsecurity.com/files/160441/GitLab-File-Read-Remote-Code-Execution.html), to be able to use it we have to add it inside a directory on, `/root/.msf4/modules/exploits/`, (don't use "-" on the name, rather use "_", otherwise the exploit wont appear), then on msfconsole run "updatedb", if you can't find the exploit with "search", you can use it directly by using the path where you put the exploit, for example I put the file inside "/root/.msf4/modules/exploits/linux/http/", so to use the exploit we can use "use exploit/linux/http/gitlab_rce", notice that I named the exploit `gitlab_rce.rb`. Once we have the exploit on metasploit we just have to set all the settings and the payload according to the target.

![](/assets/images/laboratory/msfoptions.png)

Once we run the exploit we get a shell inside the machine as git user.

![](/assets/images/laboratory/shell1.png)

# [](#header-1)Lateral Movement

After exploring the machine we see that we are inside a docker container, so on this case we want to escalate privileges on it or rather escape from it, earlier we saw that there is a user called "dexter" on gitlab, so now that we are inside there might be a way of accesing to his information. Going to the [documentation](https://docs.gitlab.com/ee/security/reset_user_password.html) of gitlab we find a way to reset the password of users so we follow the steps to reset the password of dexter user (We would rather recover the password of dexter, or at least his hash since further it would be handy on case of password reuse). The commands that we need to run are:

```bash
gitlab-rails console
user = User.find_by_username 'dexter'
user.password = 'hacked123'
user.password_confirmation = 'hacked123'
user.save!
```

![](/assets/images/laboratory/pwdreset.png)

Now we can access to dexter user on gitlab, there we find a private repository, "SecureDocker".

![](/assets/images/laboratory/repositories.png)

Checking that repository we find a ssh key, so using it we can access to the machine as dexter and retrieve user.txt.

![](/assets/images/laboratory/shell2.png)

# [](#header-1)Privilege Escalation

Searching for files with suid (find / -perm /4000 2> /dev/null) we find a strange file with suid, `/usr/local/bin/docker-security`, it is a ELF file so we would need to reverse engineer the file, but first we upload pspy to the machine and try to see what happens when the file is ran, there we see that chmod is ran by root.

![](/assets/images/laboratory/pspy.png)

As we see chmod is not called as a abosule path, se we can make a path hijacking to execute what we want on the machine, to do so we create file that will start a bash shell call it chmod, we give it run permissions, set our current locations as the first directory on our PATH, and when we run the file we will be root.

![](/assets/images/laboratory/root.png)