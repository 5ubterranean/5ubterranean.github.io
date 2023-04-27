---
title: ZAP Scripting - Cheap Autorize
tags: [ZAP,Insecure Direct Object Reference]
image: /assets/images/zap-scripting/zap-banner.png
published: true
banner: true
---

# Introduction

The other day while I was testing a web app I thought that it would be nice to be able to automate some tests, then I remembered that you can write scripts in ZAP, I gave a quick look to it and it looked far easier than writing a plugin for burp (well you can ease that by asking chatgpt to write one for you, but let's leave that aside), so I decided to try to learn how to make scripts for ZAP and write about it in my blog so I have a place to check if I forget how I did certain things. The idea that I had could've been solved by using burp extension Autorize (well not quite, but we will get to that later), so let's try to write a cheap version of it for ZAP.

# Coding

Let's start by choosing a language, ZAP allows you to write scripts in 3 languages, Graal.js (javascript), Python and Ruby, for some reason when you have a script written in Python that will apply to a lot of requests, such a proxy, HTTP Sender or Passive Rules, the CPU usage skyrockets, it might be okay if you are just manually navigating through a page, but if you want to fuzz anything the usage is excessive, so to any script in those categories it's better to stick to Graal.js, luckily javascript isn't hard to understand and you can quickly rewrite Python scripts to Graal.js, at least the simple ones. Now that we have chosen a language let's start by writing the pieces of code necessary to do what we want and put it together at the end. We will write a Proxy script (we could also use an HTTP Sender if we want it to apply to more requests besides the proxy), so let's grab the Proxy default template.

```js
function proxyRequest(msg) {
	// Debugging can be done using println like this
	print('proxyRequest called for url=' + msg.getRequestHeader().getURI().toString())
	
	return true
}

function proxyResponse(msg) {
	// Debugging can be done using println like this
	print('proxyResponse called for url=' + msg.getRequestHeader().getURI().toString())
	return true
}
```

## Making an Extra HTTP Request

We don't want to modify the requests that go through our browser, but to send an extra request with a modified value, so first let's duplicate the request so we can mess with the cloned request. To send a separate HTTP Request we need to "import" the package "org.parosproxy.paros.network.HttpSender", to do so we use `Java.type(<package>)`, then we can clone the original request and send the duplicate request. It's also important to know that the scripts get disabled when they throw an error, so something like a timeout on a request would disable the script, to avoid that we have to put the requesting line inside a try catch block:

```js
//Importing the package
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender")

//Cloning the request
var newreq = msg.cloneRequest()
//Creating the HttpSender constructor
var sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)
//Sending the Request
try{
	sender.sendAndReceive(newreq)
} catch (error)
{
	print (error)
}
```

## Loging the Request on the History Tab

We were able to send an extra request, but where did it go? Well we have to manually add the request to the history of ZAP (this allows us to send as many requests as we want without filling our history with garbage), the code for logging our request would be:

```js
//Importing packages
var Model = Java.type("org.parosproxy.paros.model.Model")
var HistoryReference = Java.type("org.parosproxy.paros.model.HistoryReference")
var Control = Java.type("org.parosproxy.paros.control.Control")
var ExtensionHistory = Java.type("org.parosproxy.paros.extension.history.ExtensionHistory")

//Get our current session
Msess = Model.getSingleton().getSession()
//Creating a constructor giving our current session as input, TYPE_ZAP_USER History Reference so the history shows it as a manual request, and the cloned HTTPMessage
var href = new HistoryReference(Msess, HistoryReference.TYPE_ZAP_USER, newreq)
//Adding the request to the History by poiting the History Reference created
Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME).addHistory(href)
```

![](/assets/images/zap-scripting/log-request.png)

## Replacing Values in the new Request

Now that we have covered the part of sending the requests let's start by changing the cookies, Ids and whatever we need to a new one, we could just modify the cookies but there are certain session identifiers that don't go as cookies (JWTs for example), so let's modify any value inside the headers:

```js
var lookfor = "<value that will be replaced>"
var replacewith = "<new value to set>"

//Set variable containing all the headers
var msgHeaders = msg.getRequestHeader().getHeaders()

//It shouldn't be possible but first we evaluate if the request contains any header
if (msgHeaders){
	//Create a variable that will change if there is any header changed
	var HeadChanged = 0
	//cloning the request so we don't modify the headers on the original request
	var newreq = msg.cloneRequest()
	newreq.getRequestHeader().getHeaders().forEach((Header) => {
		//looking for the value to be changed
		if (Header.getValue().search(lookfor) != -1){
			//Setting the header with a new one where the value is replaced, notice we need two arguments, header name and its value
			newreq.getRequestHeader().setHeader(Header.getName(),Header.getValue().replace(lookfor,replacewith))
			HeadChanged += 1
		}
	})
	//Checking if any header was changed
	if (HeadChanged > 0){
		print ("Replacing Headers")
		//Here goes the code that will send and log the new request
	}
}
```

Other values that would interest us to change would be the path (in case the site uses something like /api/\<userid\>/action), the query (?user=\<userid\>), and the body in case of POST/PUT requests, all of those changes would be pretty similar to the last one so there is no need to show how to it in a separate section.

## Flagging Suspicious Responses

The final feature we want is to flag any result that might be a possible positive, to do so we can use the build in alerts that ZAP has to set an alert on any request that we think it might be a positive IDOR, first we have to create a Alert variable with the information that will be shown on the Alerts tab, then we can raise the alert with the same History reference we used before. On this example we will flag any request that gets the same status code as the original request, this is by no means a good way to test for positve IDORs, but let's just do that to avoid overcomplicating this example script.

```js
//Importing packages
var ExtensionAlert = Java.type("org.zaproxy.zap.extension.alert.ExtensionAlert")
var Alert = Java.type("org.parosproxy.paros.core.scanner.Alert")

//Comparing cloned Request Status code with original's one
if (newreq.getResponseHeader().getStatusCode() == msg.getResponseHeader().getStatusCode()){
	//Defining alert, AFAIK scripts do not have a Plugin Id so we set a random one
	var alert = new Alert(5000, Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "Insecure Direct Object Reference")
	alert.setDescription("It is possible to access to information belonging to another user without being authenticated as that user.")
	alert.setSolution("The server has to validate that the data being accessed belongs to the current user that is logged on the site, if it isn't it should deny the asccess.")
	alert.setCweId(639)
	alert.setWascId(2)
	alert.setMessage(newreq)
	alert.setUri(newreq.getRequestHeader().getURI().toString())
	alert.setReference("https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html")
	control.getExtensionLoader().getExtension(ExtensionAlert.NAME).alertFound(alert, href)
}
```
![](/assets/images/zap-scripting/flag-idor.png)

## Putting All Together

Now that we have all the pieces ready we only have to put everything together:

```js
//Importing the packages
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender")
var Model = Java.type("org.parosproxy.paros.model.Model")
var HistoryReference = Java.type("org.parosproxy.paros.model.HistoryReference")
var Control = Java.type("org.parosproxy.paros.control.Control")
var ExtensionHistory = Java.type("org.parosproxy.paros.extension.history.ExtensionHistory")
var ExtensionAlert = Java.type("org.zaproxy.zap.extension.alert.ExtensionAlert")
var Alert = Java.type("org.parosproxy.paros.core.scanner.Alert")

var lookfor = "<value that will be replaced>"
var replacewith = "<new value to set>"

function proxyRequest(msg) {
	// Debugging can be done using println like this
	print('proxyRequest called for url=' + msg.getRequestHeader().getURI().toString())
	
	return true
}

function proxyResponse(msg) {

	//Set variable containing all the headers
	var msgHeaders = msg.getRequestHeader().getHeaders()
	var msgPath = msg.getRequestHeader().getURI().getPath()
	var msgQuery = msg.getRequestHeader().getURI().getQuery()
	var msgMethod = msg.getRequestHeader().getMethod()

	//It shouldn't be possible but first we evaluate if the request contains any header
	if (msgHeaders){
		//Create a variable that will change if there is any header changed
		var HeadChanged = 0
		//cloning the request so we don't modify the headers on the original request
		var newreq = msg.cloneRequest()
		newreq.getRequestHeader().getHeaders().forEach((Header) => {
			//looking for the value to be changed
			if (Header.getValue().search(lookfor) != -1){
				//Setting the header with a new one where the value is replaced, notice we need two arguments, header name and its value
				newreq.getRequestHeader().setHeader(Header.getName(),Header.getValue().replace(lookfor,replacewith))
				HeadChanged += 1
			}
		})
		//Checking if any header was changed
		if (HeadChanged > 0){
			print ("Replacing Headers")
			//Send request
			repeatRequest(msg,newreq)
		}
	}

	//Replacing in Path
	if (msgPath){
		if (msgPath.search(lookfor) != -1){
			print ("Replacing in Path")
			//Cloning request
			var newreq = msg.cloneRequest()
			var newpath = newreq.getRequestHeader().getURI().getPath().replace(lookfor,replacewith)
			newreq.getRequestHeader().getURI().setPath(newpath)
			//Send request
			repeatRequest(msg,newreq)
		}	
     }

	//Replacing Query
	if (msgQuery){
		if (msgQuery.search(lookfor) != -1){
			print ("Replacing Query")
			//Cloning Request
			var newreq = msg.cloneRequest()
			var newquery = newreq.getRequestHeader().getURI().getQuery().replace(lookfor,replacewith)
			newreq.getRequestHeader().getURI().setQuery(newquery)
			//Send request
			repeatRequest(msg,newreq)
		}
	}

	//Replacing Body
	if (msgMethod == "POST" || msgMethod == "PUT"){
		if (msg.getRequestBody()){
			if (msg.getRequestBody().toString().search(lookfor) != -1){
				print ("Replacing Body")
				//Cloning Request
				var newreq = msg.cloneRequest()
				var newbody = newreq.getRequestBody().toString().replace(lookfor,replacewith)
				newreq.setRequestBody(newbody)
				newreq.getRequestHeader().setContentLength(newbody.length())
				//Send request
				repeatRequest(msg,newreq)	
			}
		}
	}

	return true
}

function repeatRequest(ori,newreq){
	//Creating the HttpSender constructor
	var sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)

	//Defining alert, AFAIK scripts do not have a Plugin Id so we set a random one
	var alert = new Alert(5000, Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "Insecure Direct Object Reference")
	alert.setDescription("It is possible to access to information belonging to another user without being authenticated as that user.")
	alert.setSolution("The server has to validate that the data being accessed belongs to the current user that is logged on the site, if it isn't it should deny the asccess.")
	alert.setCweId(639)
	alert.setWascId(2)
	alert.setMessage(newreq)
	alert.setUri(newreq.getRequestHeader().getURI().toString())
	alert.setReference("https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html")

	//Sending the Request
	try{
		sender.sendAndReceive(newreq)
		//Get our current session
		Msess = Model.getSingleton().getSession()
		//Creating a constructor giving our current session as input, TYPE_ZAP_USER History Reference so the history shows it as a manual request, and the cloned HTTPMessage
		var href = new HistoryReference(Msess, HistoryReference.TYPE_ZAP_USER, newreq)
		//Adding the request to the History by poiting the History Reference created
		Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME).addHistory(href)
		if (newreq.getResponseHeader().getStatusCode() == ori.getResponseHeader().getStatusCode()){
			control.getExtensionLoader().getExtension(ExtensionAlert.NAME).alertFound(alert, href)
		}
	} catch (error)
	{
		print (error)
	}
}
```

Now that we have our script all we have to do is enable it.

![](/assets/images/zap-scripting/enable-script.png)

On this case we tested changing the JWT of two users on  the Owasp Juice Shop and we can see that the requests are being repeated and some requests are being flagged while others aren't.

![](/assets/images/zap-scripting/multiple-requests.png)

## Issues

*	As mentioned earlier the filter for flagging IDORs is not good at all, every site has its own way on handling errors, so it would be a good idea to identify first how a site reacts when we are trying to access data of another user so we can set a better filter for setting the alerts.
*	We are sending the same request too many times, as you can see the script resends the request for any change it has made, I like it more that way so I know exactly what change was successful, on the other hand you could only send one request containing all the changes and then narrow down which change triggered the vulnerability if you find a successful request, we could also add some extra conditions so it won't search the value to replace in every place, also we could separate what value changes according to the place where we are making the changes.
*	The original request gets blocked until the duplicated ones are finished, one of the purposes of this kind of scripts if to modify values of the requests on the fly so nothing can be sent back to the browser until the code is finished, sending the same request a couple of times will delay the original request, so browsing with the script enabled will slow the webpage. It would be nice having something like Passive Rules for this, since those rules run in separate threads so it wouldn't slow the webpage, but passive rules aren't meant to send requests, so we have to stick to this way.
*	There is no separate section for configuring the script, I don't really mind but sometimes it can be nice to have a small screen where we can configure everything on some small fields and checkboxes, doing that would require making an add-on (which technically is also a script), if I manage to learn how to do it I'll talk about it in a future entry on the blog.

# Post Autorize

Great we have our script to automate our tests, now what? Well the script is very useful to run while we are exploring a web page, but what if we want to perform the tests after we have explored the site? We would need to enable the script and explore the site all over again, but since we have already explored the site we can automate that task too, so let's rewrite the script so it runs as a stand alone that will resend all the requests logged that match with the value we are looking for changed, since this script will only run once we don't need to care about the language, so let's use python to see the differences with js, so let's grab the script "Loop through history table.py" and write on it.

```python
from org.parosproxy.paros.control import Control
from org.parosproxy.paros.extension.history import ExtensionHistory
from org.parosproxy.paros.network import HttpSender
from org.parosproxy.paros.model import Model
from org.parosproxy.paros.model import HistoryReference
from org.zaproxy.zap.extension.alert import ExtensionAlert
from org.parosproxy.paros.core.scanner import Alert

lookfor = "<value that will be replaced>"
replacewith = "<new value to set>"

def repeatRequest(ori,newreq):
  #Creating the HttpSender constructor
  sender = HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)

  #Defining alert, AFAIK scripts do not have a Plugin Id so we set a random one
  alert = Alert(5000, Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "Insecure Direct Object Reference")
  alert.setDescription("It is possible to access to information belonging to another user without being authenticated as that user.")
  alert.setSolution("The server has to validate that the data being accessed belongs to the current user that is logged on the site, if it isn't it should deny the asccess.")
  alert.setCweId(639)
  alert.setWascId(2)
  alert.setMessage(newreq)
  alert.setUri(newreq.getRequestHeader().getURI().toString())
  alert.setReference("https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html")

  #Sending the Request
  try:
    sender.sendAndReceive(newreq)
    #Get our current session
    Msess = Model.getSingleton().getSession()
    #Creating a constructor giving our current session as input, TYPE_ZAP_USER History Reference so the history shows it as a manual request, and the cloned HTTPMessage
    href = HistoryReference(Msess, HistoryReference.TYPE_ZAP_USER, newreq)
    #Adding the request to the History by poiting the History Reference created
    Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME).addHistory(href)
    if newreq.getResponseHeader().getStatusCode() == ori.getResponseHeader().getStatusCode():
      control.getExtensionLoader().getExtension(ExtensionAlert.NAME).alertFound(alert, href)
  except Exception:
      print (Exception)

extHist = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME) 
if (extHist != None):
  i=1
  # Loop through the history table, printing out the history id and the URL
  hr = extHist.getHistoryReference(i)
  while (hr != None):
    #url = hr.getHttpMessage().getRequestHeader().getURI().toString()
    #print('Got History record id ' + str(hr.getHistoryId()) + ' URL=' + url) 

    #Only evaluate requests generated by the browser
    if hr.getHistoryType() == 1:
      msg = hr.getHttpMessage()
      #Set variable containing all the headers
      msgHeaders = msg.getRequestHeader().getHeaders()
      msgPath = msg.getRequestHeader().getURI().getPath()
      msgQuery = msg.getRequestHeader().getURI().getQuery()
      msgMethod = msg.getRequestHeader().getMethod()

      #It shouldn't be possible but first we evaluate if the request contains any header
      if msgHeaders:
        #Create a variable that will change if there is any header changed
        HeadChanged = 0
        #cloning the request so we don't modify the headers on the original request
        newreq = msg.cloneRequest()
        for Header in newreq.getRequestHeader().getHeaders():
          #looking for the value to be changed
          if Header.getValue().find(lookfor) != -1:
            #Setting the header with a new one where the value is replaced, notice we need two arguments, header name and its value
            newreq.getRequestHeader().setHeader(Header.getName(),Header.getValue().replace(lookfor,replacewith))
            HeadChanged += 1
        #Checking if any header was changed
        if HeadChanged > 0:
          print ("Replacing Headers")
          #Send request
          repeatRequest(msg,newreq)

      #Replacing in Path
      if msgPath:
        if msgPath.find(lookfor) != -1:
          print ("Replacing in Path")
          #Cloning request
          newreq = msg.cloneRequest()
          newpath = newreq.getRequestHeader().getURI().getPath().replace(lookfor,replacewith)
          newreq.getRequestHeader().getURI().setPath(newpath)
          #Send request
          repeatRequest(msg,newreq)

      #Replacing Query
      if msgQuery:
        if msgQuery.find(lookfor) != -1:
          print ("Replacing Query")
          #Cloning Request
          newreq = msg.cloneRequest()
          newquery = newreq.getRequestHeader().getURI().getQuery().replace(lookfor,replacewith)
          newreq.getRequestHeader().getURI().setQuery(newquery)
          #Send request
          repeatRequest(msg,newreq)

      #Replacing Body
      if msgMethod == "POST" or msgMethod == "PUT":
        if msg.getRequestBody():
          if msg.getRequestBody().toString().find(lookfor) != -1:
            print ("Replacing Body")
            #Cloning Request
            newreq = msg.cloneRequest()
            newbody = str(newreq.getRequestBody()).replace(lookfor,replacewith)
            newreq.setRequestBody(newbody)
            newreq.getRequestHeader().setContentLength(len(newbody))
            #Send request
            repeatRequest(msg,newreq)	

    i += 1
    hr = extHist.getHistoryReference(i)
```

Testing again with the juice shop to send the requests without a JWT we see all the requests going and just some getting an alert.

![](/assets/images/zap-scripting/post-autorize.png)

If we go to the Alerts tab we see all the alerts on the section we created.

![](/assets/images/zap-scripting/post-alerts.png)

With that we have a script that can test all the past requests and help us to identify vulnerabilities, since we would run this script after we have explored the site it will be easier to craft a reliable filter so we have less false positives among the alerts, a feature that would be interesting would be that the requests to be resend were showed on another tab and we could select which requests we don't want to send in case there is any sensitive action, I'll probably try to do so in the future when I get familiar with writing add-ons.
I'm leaving both scripts in my [github](https://github.com/5ubterranean/Random-Scripts/tree/main/zap-scripts) in case you want them and the blog is leaving some weird format errors.