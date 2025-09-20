---
title: Solving Caido labs using Zaproxy
tags: [ZAP,Caido]
image: /assets/images/caido-labs/caido-banner.png
published: true
banner: true
---

Caido just released a labs page ([https://labs.cai.do/](https://labs.cai.do/)) so I thought it would be a good idea to solve them using Zaproxy, this first batch of labs are meant to teach different vulnerabilities to people who is starting on cibersecurity so they do not use the full potential of any of the tools, the purpose of this blog is not to try to make a comparison between both tools, I just like to try to use Zaproxy of different scenarios ;).

### Match and Replace

This challenge can be found on the next URL:

[https://labs.cai.do/matchAndReplace.php](https://labs.cai.do/matchAndReplace.php)

On this challenge we are shown the next site.

![](/assets/images/caido-labs/matchrepsite.png)

If we read the HTML code we can see that there is a function that checks the current role, and if it happens to be admin it executes "displayAdminUI()".

![](/assets/images/caido-labs/matchcode.png)

We can validate what does that function by executing it manually.

![](/assets/images/caido-labs/matchadmin.png)

While this uncovers the *hidden* panel, when testing a website, things are not usually that easy, and also we don't have the time to check everything, on this scenario we can create a rule to replace the text "basic" to "admin" on the responses so the javascript code gets executed with that role, we can do that by creating a rule on the replacer AddOn (Ctrl + R as shortcut).

![](/assets/images/caido-labs/matchreplacer.png)

If we reload the page we notice that the admin panel is shown automatically.

![](/assets/images/caido-labs/matchrepadmin.png)

With that the challenge is solved.

![](/assets/images/caido-labs/matchsolve.png)

Notice that the replacer rule stays active even if you close Zaproxy, so it's always good to disable the rules when you are done with them.

### IDOR Vulnerability

This challenge can be found on the next URL:

[https://labs.cai.do/idor.php](https://labs.cai.do/idor.php)

On this challenge we are shown the next site.

![](/assets/images/caido-labs/idorsite.png)

If we click the button the next information gets retrieved.

![](/assets/images/caido-labs/idorinfo.png)

Checking the HTTP request we see that "user_id" is sent in a POST request.

![](/assets/images/caido-labs/idorreq.png)

We can send the request to Requester (Ctrl + W as shortcut) and try to send a different ID.

![](/assets/images/caido-labs/idoradmin.png)

We got the information of the user Admin, but it tells us there is a kind of super admin user, to try to get it we send the request to the Fuzzer, and selecting the value of the user_id we add a payload of type "Numberzz" and set it to iterate from 1 to 50.

![](/assets/images/caido-labs/idorfuzz.png)

Once it's done the easier way to notice any difference it's by changing the order by the size of the response Body, there we can see that besides the values "1" and "2", the value "42" is different.

![](/assets/images/caido-labs/idorfuzzed.png)

Cheking that request we can verify that we found the ID of the super admin user.

![](/assets/images/caido-labs/idorsuper.png)

While sorting by size works most of the time, there can be occasion where we want to look for something more specific, on that case we can write a "Fuzzer HTTP Processor" script:

```js
// Auxiliary variables/constants needed for processing.
var count = 1;

function processMessage(utils, message) {

	//message.getRequestHeader().setHeader("X-Unique-Id", count);
	count++;
}

function processResult(utils, fuzzResult){

    var response = fuzzResult.getHttpMessage().getResponseBody().toString()
	if (response.indexOf("super") !== -1)
    {
		fuzzResult.addCustomState("Key Custom State","Super found")
	}
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}
```

All this script does is look for the word "super" on the response of the body and add a state that flags it, notice this is a very basic example and these scripts are really flexible, also if you want to know what every function does you can read the example script on Zaproxy since it is detailed there.
Once we have our script loaded **and** enabled we can add it before executing the fuzzer.

![](/assets/images/caido-labs/idorprocessor.png)

After we run the fuzzer we can see that the responses that included the word "super" were flagged.

![](/assets/images/caido-labs/idorsuperfuzz.png)

### Too Many Requests

This challenge can be found on the next URL:

[https://labs.cai.do/tooManyRequests.php](https://labs.cai.do/tooManyRequests.php)

On this challenge we are shown the next site.

![](/assets/images/caido-labs/toomany.png)

If we click the start searching button we can see that the site sends 100 requests.

![](/assets/images/caido-labs/toomanyreq.png)

If we have the Zap session capturing a lot of traffic we can add a filter to only show the requests that include "secretValueHere" on the URL.

![](/assets/images/caido-labs/toomanyfilter.png)

Then ordering by the size of the responses we can see one is different.

![](/assets/images/caido-labs/toomanysize.png)

Checking the request we can find the secret value.

![](/assets/images/caido-labs/toomanysecret.png)

### ShaSigned

This challenge can be found on the next URL:

[https://labs.cai.do/shaSigned.php](https://labs.cai.do/shaSigned.php)

On this challenge we are shown the next site.

![](/assets/images/caido-labs/shasite.png)

The challenge seems to be a modified version of the IDOR challenge. If we click the button the next request is sent.

![](/assets/images/caido-labs/shareq.png)

Reading the HTML code we find the next function:

```js
    <script>
        function signRequest(event) {
            event.preventDefault();
            const form = document.getElementById('userForm');
            const userId = form.querySelector('[name="user_id"]').value;
            const postData = `user_id=${userId}`;
            const hash = CryptoJS.SHA256(postData).toString();
            form.querySelector('[name="hash"]').value = hash;
            form.submit();
        }
    </script>
```
We can see that the hash value is calculated by getting the SHA256 sum of the string "user_id=" plus the current ID, we can validate this by calculating it ourselves.

![](/assets/images/caido-labs/shalocal.png)

Now that we know how the hash is calculated we can Fuzz the values, if we were using Burpsuite we could create the list of hashes and use a *pitchfork* attack, however on Zaproxy if we add more than one payload it treats it as a *Cluster Bomb* attack, since this is not what we want we'll have to use a single payload field and create a **Payload Generator** script that generates the whole body. Here is the script that we will use, all is done on the "next()" function, to calculate the hash we are using the java "MessageDigest" class, since using it is not as straightforward as just calling it you can ask your favorite IA agent to write that part for you.

```js
var MessageDigest = Java.type("java.security.MessageDigest");
// Auxiliary variables/constants for payload generation.
var NUMBER_OF_PAYLOADS = 50;
var INITIAL_VALUE = 1;
var count = INITIAL_VALUE;

/**
 * Returns the number of generated payloads, zero to indicate unknown number.
 * The number is used as a hint for progress calculations.
 * 
 * @return {number} The number of generated payloads.
 */
function getNumberOfPayloads() {
	return NUMBER_OF_PAYLOADS;
}

/**
 * Returns true if there are still payloads to generate, false otherwise.
 * 
 * Called before each call to next().
 * 
 * @return {boolean} If there are still payloads to generate.
 */
function hasNext() {
	return (count <= NUMBER_OF_PAYLOADS);
}

/**
 * Returns the next generated payload.
 * 
 * This method is called while hasNext() returns true.
 * 
 * @return {string} The next generated payload.
 */
function next() {
  start = "user_id=";
  ID = count.toString();
  mid = "&hash="
  sign = sha256(start + ID)
	payload = start + ID + mid + sign;
	count++;
	return payload;
}

/**
 * Resets the internal state of the payload generator, as if no calls to
 * hasNext() or next() have been previously made.
 * 
 * Normally called once the method hasNext() returns false and while payloads
 * are still needed.
 */
function reset() {
	count = INITIAL_VALUE;
}

/**
 * Releases any resources used for generation of payloads (for example, a file).
 * 
 * Called once the payload generator is no longer needed.
 */
function close() {
}

function sha256(message) {
  const digest = MessageDigest.getInstance("SHA-256");
  const bytes = new java.lang.String(message).getBytes("UTF-8");
  const hash = digest.digest(bytes);

  let hex = "";
  for (let i = 0; i < hash.length; i++) {
    let byte = hash[i] & 0xff;
    // Manually pad with '0' if needed
    hex += (byte < 16 ? "0" : "") + byte.toString(16);
  }

  return hex;
}
```

Once we have the script ready and enabled we can start a fuzzer by selecting the whole post body and selecting our script as the payload.

![](/assets/images/caido-labs/shapayload.png)

After running the fuzzer we can see the requests that included "super" on the response.

![](/assets/images/caido-labs/shafuzzed.png)

Finally we check the request to be sure we got the value of the super admin.

![](/assets/images/caido-labs/shasuper.png)

### CSRF via Content-Type

This challenge can be found on the next URL:

[https://labs.cai.do/csrfContentType.php](https://labs.cai.do/csrfContentType.php)

On this challenge we are shown the next site.

![](/assets/images/caido-labs/csrfsite.png)

If we change our name the next request is sent.

![](/assets/images/caido-labs/csrfreq.png)

The challenge says we can send "text/plain" as Content-Type, so we validate that.

![](/assets/images/caido-labs/csrfplain.png)

Now we can use the community script [json_csrf_poc_generator](https://github.com/zaproxy/community-scripts/blob/main/targeted/json_csrf_poc_generator.js), to use it we right click and select "Invoke with Script..." -> json_csrf_poc_generator.py, this will generate the next page:

```html
<!DOCTYPE html>
<head>
 <title>CSRF POC</title>
</head>
<body>
<form action="https://labs.cai.do/csrfContentType.php" id="formid" method="post" enctype="text/plain">
<input type ='hidden' name='{"name":"hacked","ignore_me":"' value='something"}'>
</form>
<script>document.getElementById('formid').submit();</script>
</body></html>
```

We can see that the HTML adds the value `,"ignore_me":"' value='something"}` to the request, this is because the browser expects to send a POST form as a request, not a JSON, if the request does not look like a post form one the browser will try to format it, and that would send an invalid request.
Now we change the value of "name" and host the page using python and open it on our browser. After opening it we see that it opens the csrf site.

![](/assets/images/caido-labs/csrfpoc.png)

If we check the request that was sent we can validate that the request came from our local python server.

![](/assets/images/caido-labs/csrfpocreq.png)

If we go back to the challenge page we can validate the name was updated.

![](/assets/images/caido-labs/csrfsolved.png)

### Session Monitor

This challenge can be found on the next URL:

[https://labs.cai.do/sessionMonitor.php](https://labs.cai.do/sessionMonitor.php)

The purpose of this challenge is to learn how to store changing values from requests to a environment variable, I do not know how Caido can make use of this information, so I'm not replicating this laboratory, however Zaproxy supports [global variables](https://www.zaproxy.org/docs/desktop/addons/script-console/#global-variables), and you could easily monitor and store values from the requests, on this scenario creating a passive script for this purpose would be the most appropriate, however if you have a value that changes really fast you could run on the issue that the value stored is not the last one since passive scripts run in parallel, if that were the case you could use a "proxy script" instead, while doing that wouldn't be ideal it would work for that specific scenario.

### Reflected XSS Lab

This challenge can be found on the next URL:

[https://labs.cai.do/xss.php](https://labs.cai.do/xss.php)

On this challenge we are shown the next site.

![](/assets/images/caido-labs/xsssite.png)

If we set the classic xss poc as name `<script>alert(1)</script>` we can validate the vulnerability.

![](/assets/images/caido-labs/xsspoc.png)

On the main page the description of the challenge is the next one:
`Learn the basics of how to identify reflected XSS with two different vulnerabilities in the same lab.`
It says that there are **two** vulnerabilities, while on this case we could find the other value by reading the HTML code that's not always possible, so we will use param digger (equivalent of Burp's param miner) to find the other parameter, since the default wordlist is too small we will use Burp's list from Seclist.

![](/assets/images/caido-labs/xssparam.png)

Once the scan is finished it reports the "company" parameter.

![](/assets/images/caido-labs/xssparamresult.png)

We can read the response to find out how the parameter changes the response.

![](/assets/images/caido-labs/xsscompany.png)

Since we are already inside a *script* tag we use a different payload `';alert(1);'`:

![](/assets/images/caido-labs/xsscomppoc.png)

### HTTP Hunt Lottery

This challenge can be found on the next URL:

[https://labs.cai.do/http-hunt/index.php](https://labs.cai.do/http-hunt/index.php)

On this challenge we are shown the next site.

![](/assets/images/caido-labs/huntsite.png)

If we click the button we see the next message:

![](/assets/images/caido-labs/huntluck.png)

If we check the HTTP response we see extra information.

![](/assets/images/caido-labs/luckresponse.png)

If we enter to the revealed site we get the solution.

![](/assets/images/caido-labs/huntsolve.png)


And this is all, if Caido releases new labs in the future I might try to do this again, while learning to write scripts for Zaproxy can be a bit challenging due the lack of examples they are really flexible and can help us on a lot of scenearios.