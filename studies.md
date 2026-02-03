# Stage 1 - anonymous to user session
## Identify the case
| Case      | Probable exploit |
| ----------- | ----------- |
| tracking.js | Host header poisoning or Cache poisoning (in that case there is also X-Cache) |
| <script>alert(1)</script> in the search | XSS |
| Post a comment | HTTP Request Smuggling |
| Different message error when resetting password | Bruteforce | 
| None of the above | Bruteforce |
