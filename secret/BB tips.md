BB tips

## TIP:
try with changing Content-Type to application/xml
and use an XML/XXE payload in POST body.
With this i've found many XXE/SSRF in simple post request.

## TIP:

 site:(link: http://prog.com) prog.com inurl:lang=
 Or 
 inurl:locale=
 Language is generally saved in cookies so you have a chance of CRLF there.

Like ?lang=en sets a cookie language=en so...

## TIP:
It's always a good idea to use waybackurl by 
@TomNomNom
 even if the subdomain shows 403, 404 or even if it's redirecting you to the main site. It can sometimes fetch you interesting endpoints. :P
I ended up getting a couple of XSS in 10 mins using this method 😅

## TIP:

Tip- In every shopping website check if there is an option to share whishlist using email. Most of the time it is vulnerable to html injection. Don't forget to test with different encoding schemes. Once it worked for me with html entities.
