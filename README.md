# DevSecOps Challenge — Production-Grade Secure CI/CD Pipeline

[![CI Pipeline](https://github.com/AashishChaudhari/devsecops-challenge/actions/workflows/ci.yml/badge.svg)](https://github.com/AashishChaudhari/devsecops-challenge/actions/workflows/ci.yml)

A production-grade DevSecOps project built from scratch over 60 days as part of Leapfrog Technology's [#60DaysOfLearning2026](https://twitter.com/hashtag/60DaysOfLearning2026) challenge.

**Live app:** https://aashishchaudhari.duckdns.org

---

## What this project is

A Flask web application with a complete authentication system, user profiles, API key authentication, and a notes feature — protected at every layer by an automated CI/CD pipeline with seven security scanning tools, enforced branch protection, and real-time Discord security alerting.

---

## The CI/CD Security Pipeline

Every push to a feature branch triggers this pipeline automatically. Nothing merges to `main` without passing all blocking checks.

| Step | Tool | What it does | Blocks merge? |
|---|---|---|---|
| Secret scanning | Gitleaks | Scans git history for leaked API keys and tokens | ✅ Yes |
| Dependency audit | pip-audit | Checks Python packages against PyPI vulnerability database | ✅ Yes |
| Unit tests | pytest | Runs 48 tests covering auth flows, security headers, API endpoints | ✅ Yes |
| Code quality | SonarQube Cloud | Scans for bugs, vulnerabilities and code smells | ⚠️ Reports |
| Container build | Docker | Multi-stage build with smoke test | ✅ Yes |
| Container scan | Trivy | Scans Docker image for OS-level CVEs (HIGH/CRITICAL) | ✅ Yes |
| Live app scan | OWASP ZAP | Attacks the running app like a real attacker | ⚠️ Reports |
| Auto-deploy | SSH action | Deploys to AWS EC2 on successful merge to main | — |

---

## Application Security Features

**Authentication**
- User registration with input validation, regex enforcement, duplicate detection
- bcrypt password hashing with automatic salting
- Flask sessions with HttpOnly, SameSite=Lax cookies
- Session expiry with server-side enforcement (30-day max)
- Remember Me with persistent cookies
- Password change requiring current password verification
- Account deletion with password confirmation
- CSRF protection on every form (Flask-WTF)
- Rate limiting: 5 login attempts/minute, 10 registrations/hour

**API Security**
- API key authentication with Bearer token support
- Keys hashed with SHA-256 before storage — never stored in plaintext
- Shown only once at creation time
- Session or API key accepted on all `/api/` endpoints

**HTTP Security Headers (on every response via WSGI middleware)**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=()`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `X-Permitted-Cross-Domain-Policies: none`
- `Cache-Control: no-store`

**Container Hardening**
- Multi-stage Docker build (no build tools in final image)
- Non-root user (`appuser`)
- `.dockerignore` reduces build context from 72MB to 51KB
- `HEALTHCHECK` tied to `/health` endpoint
- Gunicorn WSGI server (not Flask dev server)
- Docker Compose for stack orchestration

**Server Security (AWS EC2)**
- UFW firewall (deny all incoming except 22, 80, 443, 5000)
- Fail2ban (SSH brute-force protection, 3 attempts = 24h ban)
- SSH key-only authentication (password auth disabled)
- Automatic security updates (unattended-upgrades)
- Nginx reverse proxy with Let's Encrypt SSL certificate
- HTTPS enforced — HTTP redirects to HTTPS

**Monitoring & Alerting**
- Structured JSON logging (structlog) for all auth events and requests
- Real-time Discord webhook alerts for: failed logins, rate limit hits, new registrations, account deletions
- Security monitor running as systemd service on EC2
- Dependabot for automated dependency security updates

---

## The Vulnerable Demo (Security Case Study)

`/vulnerable-demo` contains a deliberately broken Flask app demonstrating the full vulnerability lifecycle:

1. Built with XSS and SQL injection bugs
2. Exploited manually (XSS alert box, SQLi auth bypass)
3. Scanned with OWASP ZAP active scanner
4. Fixed with output escaping and parameterized queries
5. Hardened with rate limiting and bcrypt
6. Re-scanned to confirm fixes — ZAP warnings dropped from 7 to 0 FAIL

See [`/vulnerable-demo/README.md`](./vulnerable-demo/README.md)

---

## Architecture

```
Developer → Git push → GitHub (feature branch)
                           ↓
                    GitHub Actions CI
           ┌───────────────────────────────┐
           │ Gitleaks → pip-audit → pytest │
           │ SonarQube → Docker build      │
           │ Trivy → OWASP ZAP             │
           └───────────────────────────────┘
                           ↓ (merge to main)
                    Auto-deploy via SSH
                           ↓
                      AWS EC2
           ┌───────────────────────────────┐
           │ Nginx (reverse proxy + HTTPS) │
           │ Gunicorn → Flask app          │
           │ SQLite database               │
           │ UFW + Fail2ban + SSL          │
           │ Security monitor (systemd)    │
           └───────────────────────────────┘
                           ↑
                    Browser (HTTPS)
```

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/health` | None | Health check |
| GET | `/api/docs` | None | API documentation |
| GET | `/api/stats` | None | Total user count |
| GET | `/api/profile` | Session or API key | Get your profile |
| PUT | `/api/profile` | Session or API key | Update profile |
| GET | `/api/keys` | Session | List API keys |
| POST | `/api/keys` | Session | Create API key |
| DELETE | `/api/keys/<id>` | Session | Delete API key |

Full docs: https://aashishchaudhari.duckdns.org/api/docs

---

## Tech Stack

| Layer | Tools |
|---|---|
| App | Python, Flask, SQLite, bcrypt, Flask-WTF, Flask-Limiter, structlog, Gunicorn |
| Security scanning | Gitleaks, pip-audit, SonarQube Cloud, Trivy, OWASP ZAP |
| CI/CD | GitHub Actions, Docker Compose, appleboy/ssh-action |
| Infrastructure | AWS EC2 (t2.micro), Nginx, Let's Encrypt, UFW, Fail2ban |
| Monitoring | structlog, Discord webhooks, systemd |
| Automation | Dependabot |

---

## Running locally

```bash
git clone https://github.com/AashishChaudhari/devsecops-challenge.git
cd devsecops-challenge
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit with your values
python3 app.py
```

Visit `http://localhost:5000`

---

## Running with Docker Compose

```bash
cp .env.example .env  # edit with your values
docker compose up --build -d
```

---

## Running the tests

```bash
pytest test_app.py -v
```

48 tests covering: registration, login, sessions, password change, account deletion, API keys, security headers, rate limiting, database initialization, and more.

---

## Project background

Built as part of Leapfrog Technology's #60DaysOfLearning2026 challenge — one day at a time, from Linux beginner to a working DevSecOps pipeline with a real authentication system deployed on AWS.

Daily progress on Twitter/X: [#60DaysOfLearning2026](https://twitter.com/hashtag/60DaysOfLearning2026) · [#LearningWithLeapfrog](https://x.com/aashishhq) · [@lftechnology](https://x.com/lftechnology)
