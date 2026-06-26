# Vulnerable Demo App — XSS & SQL Injection: Exploit, Detect, Fix

A small Flask app built **deliberately vulnerable**, then exploited, scanned, and hardened — to demonstrate the full vulnerability lifecycle from discovery to remediation.

This is part of my [#60DaysOfLearning](https://twitter.com/hashtag/60DaysOfLearning2026) DevSecOps challenge with Leapfrog Technology.

⚠️ **This app is intentionally insecure in its early commits. Never deploy code like this in production.**

---

## What this project demonstrates

| Stage | What I did |
|---|---|
| 1. Build vulnerable | Created an app with classic XSS and SQL injection bugs |
| 2. Exploit manually | Triggered both vulnerabilities by hand to understand the root cause |
| 3. Scan automatically | Used OWASP ZAP's active scanner — and learned it only catches what it can discover |
| 4. Fix properly | Applied output escaping and parameterized queries |
| 5. Harden further | Added rate limiting and bcrypt password hashing |
| 6. Verify | Re-ran ZAP to confirm vulnerabilities were actually resolved |

---

## The vulnerabilities

### Cross-Site Scripting (XSS)
**Before:**
```python
return f"<h1>Welcome, {name}!</h1>"
```
User input was inserted directly into HTML. Visiting `/?name=<script>alert('Hacked!')</script>` executed arbitrary JavaScript in the browser.

**After:**
```python
safe_name = escape(name)
return f"<h1>Welcome, {safe_name}!</h1>"
```
Input is HTML-escaped before rendering, so it displays as text instead of executing as code.

---

### SQL Injection
**Before:**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```
Submitting `password=' OR '1'='1` altered the query's logic and bypassed authentication entirely.

**After:**
```python
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```
Parameterized queries keep user input as pure data — it can never be interpreted as SQL syntax.

---

## Additional hardening

- **Rate limiting** — `/login` is capped at 5 attempts per minute per IP, blocking brute-force attempts with a `429` response
- **Password hashing** — passwords are hashed with bcrypt (with automatic per-password salting) instead of stored in plaintext

---

## Proof of fix: OWASP ZAP scan results

| Scan | XSS (Reflected) | XSS (DOM-based) |
|---|---|---|
| Before fix | ⚠️ WARN-NEW | ⚠️ WARN-NEW |
| After fix | ✅ PASS | ✅ PASS |

Full scan reports are included in this folder: `zap-active-report.html` (before) and `zap-fixed-report.html` (after).

---

## Key lesson

Automated scanners are powerful but not magic — **ZAP only detects vulnerabilities in parameters it can discover.** When pointed at a bare URL, it missed the XSS bug entirely. When given a URL with the vulnerable parameter included, it found it immediately. Manual security testing and automated scanning are complementary, not substitutes for each other.

---

## Tech used
Flask · SQLite · bcrypt · Flask-Limiter · OWASP ZAP · Docker

## Run it yourself
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 vulnerable_app.py
```
Visit `http://localhost:6001`
