# Stage 1 - anonymous to user session
## Identify the case
| Case      | Probable exploit |
| ----------- | ----------- |
| tracking.js | Host header poisoning or Cache poisoning (in that case there is also X-Cache) |
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
