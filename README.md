# DevSecOps Challenge — Secure CI/CD Pipeline with Full Auth System

A production-grade DevSecOps project built from scratch over 60 days as part of Leapfrog Technology's [#60DaysOfLearning2026](https://twitter.com/hashtag/60DaysOfLearning2026) challenge.

This repo demonstrates the full DevSecOps lifecycle: a Flask web application with a complete authentication system, protected by an automated CI/CD pipeline with six security scanning tools and enforced branch protection.

---

## What this project is

A Flask app with real user authentication (registration, login, sessions, password change), secured at every layer — application code, dependencies, container image, and live running app — all gated behind a pipeline that blocks vulnerable code from ever reaching main.

---

## The CI/CD Security Pipeline

Every push to a feature branch triggers this pipeline automatically:

| Step | Tool | What it does | Blocks merge? |
|---|---|---|---|
| Secret scanning | Gitleaks | Scans git history for leaked API keys, tokens, passwords | ✅ Yes |
| Dependency audit | pip-audit | Checks Python packages against PyPI vulnerability database | ✅ Yes |
| Unit tests | pytest | Runs 15+ tests covering auth flows and security headers | ✅ Yes |
| Code quality | SonarQube Cloud | Scans for bugs, vulnerabilities, and code smells | ⚠️ Reports only |
| Container build | Docker | Multi-stage build with non-root user and .dockerignore | — |
| Container scan | Trivy | Scans Docker image for OS-level CVEs (HIGH/CRITICAL) | ✅ Yes |
| Live app scan | OWASP ZAP | Attacks the running app like a real attacker would | ⚠️ Reports only |

Nothing merges to `main` without passing all blocking checks. Branch protection enforces this — even for the repo owner.

---

## Application Security Features

**Authentication system**
- User registration with input validation (length, format, duplicates)
- bcrypt password hashing with automatic salting
- Real login sessions with signed, HttpOnly, SameSite cookies
- Session expiry with server-side enforcement
- Remember Me (30-day persistent sessions)
- Secure password change requiring current password verification
- CSRF protection on every form (Flask-WTF)
- Rate limiting: 5 login attempts/minute, 10 registrations/hour, 5 password changes/hour

**HTTP Security Headers (on every response)**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'`
- `Permissions-Policy`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Resource-Policy`
- `Cache-Control: no-store`

**Container hardening**
- Multi-stage Docker build (no build tools in final image)
- Non-root user (`appuser`)
- `.dockerignore` reduces build context from 72MB to 51KB
- `HEALTHCHECK` tied to `/health` endpoint

---

## The Vulnerable Demo (Security Case Study)

`/vulnerable-demo` contains a deliberately broken Flask app used to demonstrate the full vulnerability lifecycle:

1. Built with classic XSS and SQL injection bugs
2. Exploited manually to understand the root cause
3. Scanned with OWASP ZAP's active scanner
4. Fixed with output escaping and parameterized queries
5. Hardened with rate limiting and bcrypt hashing
6. Re-scanned to confirm fixes — ZAP results went from 2 WARN-NEW to 0

See [`/vulnerable-demo/README.md`](./vulnerable-demo/README.md) for the full before/after writeup.

---

## Tech Stack

| Layer | Tools |
|---|---|
| App | Python, Flask, SQLite, bcrypt, Flask-WTF, Flask-Limiter |
| CI/CD | GitHub Actions |
| Security scanning | Gitleaks, pip-audit, SonarQube Cloud, Trivy, OWASP ZAP |
| Container | Docker (multi-stage, non-root) |
| Code quality | SonarQube Cloud |

---

## Running locally

```bash
git clone https://github.com/AashishChaudhari/devsecops-challenge.git
cd devsecops-challenge
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Visit `http://localhost:5000`

Routes:
- `/` — home
- `/health` — health check (used by Docker HEALTHCHECK)
- `/register` — create an account
- `/login-page` — log in
- `/dashboard` — protected, requires login
- `/change-password` — update password (requires login)
- `/logout` — end session

---

## Running the tests

```bash
pytest test_app.py -v
```

---

## Project background

Built as part of Leapfrog Technology's #60DaysOfLearning2026 challenge — one day at a time, from absolute Linux beginner to a working DevSecOps pipeline with a real authentication system.

Daily progress: Twitter/X under [#60DaysOfLearning2026](https://twitter.com/hashtag/60DaysOfLearning2026) and [#LearningWithLeapfrog](https://twitter.com/hashtag/LearningWithLeapfrog), tagging [@lftechnology](https://twitter.com/lftechnology).
