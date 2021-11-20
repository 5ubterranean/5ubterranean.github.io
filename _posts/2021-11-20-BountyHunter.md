---
title: BountyHunter Writeup [HTB]
tags: [HackTheBox, XXE, python]
image: /assets/images/bountyhunter/bountyhunter.png
published: true
banner: true
---

BountyHunter is a Linux based machine that was active since July 24th to November 20th, on this machine we will find a XXE vulnerability and use it with a php wrapper to read internal files and get sensitive information, with the information gotten we will be able to connect to the machine through SSH, once inside the machine we will analyze a python script to find how we can abuse it to get code execution as root user and finish with the machine.

# [](#header-1)Enumeration

We start using masscan to find all the available ports and then use nmap to get more information about them.

```
masscan -e tun0 --rate=500 -p 0-65535 10.10.11.100
nmap -sC -sV -p 80,22, -Pn -o scan.txt 10.10.11.100

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see only two ports open, SSH and a webpage on port 80, so we visite the webpage.

![](/assets/images/bountyhunter/website.png)

It's a simple page to display who they are, if we click on "portal" we get to a site that tells us to go to `http://10.10.11.100/log_submit.php`.

![](/assets/images/bountyhunter/submit.png)

We see that it is a report system where they probably put any vulnerability found together with the bounty gotten, let's upload a report to see what happens.

![](/assets/images/bountyhunter/report.png)

We get the message "If DB were ready, would have added", so that means that the database isn't implemented yet, let's see how the request looks like.

![](/assets/images/bountyhunter/request.png)

We see that the data is base64 encoded, inspector can decode the data automatically for us.

![](/assets/images/bountyhunter/inspector.png)

# [](#header-1)Gaining Access

We see that what we sent was a xml file, xml can be vulnerable to XXE, we can add an external entity and see if we can exploit this vulnerability, we will use [hackevector](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) to handle the encoding before sending the request to the server.

![](/assets/images/bountyhunter/xxereq.png)

![](/assets/images/bountyhunter/xxeres.png)

We successfully exploited the XXE vulnerability, now we can read internal files, while testing that we left feroxbuster on the backgroud, checking the results we see a "db.php" file which returns 0 size.

![](/assets/images/bountyhunter/ferox.png)

It probably just is written to don't show anything when accessed to, but there could be useful information so we can try to read the source code of it.

![](/assets/images/bountyhunter/filedb.png)

![](/assets/images/bountyhunter/filedbres.png)

We get nothing, we know that the file exists, so maybe the file is empty, or the output that we get from php files is the same that we would get when we access to them from the webpage, this can block us from reading php files, but what we do with the XXE vulnerability is use php wrappers, being "file://" one of those, so we can try another wrapper, `php://filter/convert.base64-encode/resource`, this will base64 encode the file before reading it, so we won't have problems with php code, then we use it to read the file.

![](/assets/images/bountyhunter/b64.png)

![](/assets/images/bountyhunter/b64res.png)

Decoding the output gotten we find the credentials to access the database on the server.

![](/assets/images/bountyhunter/dbfile.png)

When we read the passwd file we found out that the only user available on the server is "development", so let's try to access as that user with the password retrieved.

![](/assets/images/bountyhunter/shell.png)

# [](#header-1)Privilege Escalation

We read contract.txt

```
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

It talks about an internal tool that they're using, that there are tickets that have failed validation and that they have set up the proper permissions for testing, so we check if we can execute anything with sudo.

![](/assets/images/bountyhunter/sudo.png)

We see that we can run `/opt/skytrain_inc/ticketValidator.py`, so let's read it to see what it does.

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

So let's enumerate what this script does.

1.  Ask for the path to a file.
2.  Checks that the name of the file ends with ".md".
3.  Checks that the first line starts with "# Skutrain Inc".
4.  Checks that the second line starts with "## Ticket to" and prints what is after that.
5.  Validates that the third line starts with "_\_Ticket Code:_\_", if that's the case continues with the next line.
6.  Checks that the fourth line starts with "**".
7.  Erases the "**" on the line and splits the text if there is any "+" sign, and takes the first string.
8.  Checks that the module of the first vaule is equal to 4.
9.  Passes the origianl value (before spliting it) to an eval function.

If we can reach the eval function we can get code execution, we can use the information gotten to build our own ticket, also we can find some examples on `/opt/skytrain_inc/invalid_tickets/`, so we build our own ticket and pass it to the script, and finish with the machine.

![](/assets/images/bountyhunter/root.png)