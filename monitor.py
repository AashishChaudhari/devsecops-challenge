#!/usr/bin/env python3
import subprocess
import json
import smtplib
import os
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from collections import defaultdict

ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "chaudhariaashish18@gmail.com")
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
CONTAINER_NAME = "devsecops-app"
FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_MINUTES = 5

def send_alert(subject, body):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print(f"[ALERT] {subject}: {body}")
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = f"[DevSecOps Alert] {subject}"
        msg["From"] = SMTP_EMAIL
        msg["To"] = ALERT_EMAIL
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, ALERT_EMAIL, msg.as_string())
        print(f"[ALERT SENT] {subject}")
    except Exception as e:
        print(f"[ALERT FAILED] {e}")

def parse_log_line(line):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None

def monitor():
    print(f"Starting security monitor for container: {CONTAINER_NAME}")
    failed_logins = defaultdict(list)
    alerted_ips = set()

    process = subprocess.Popen(
        ["docker", "logs", "-f", "--tail", "0", CONTAINER_NAME],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    print("Monitoring started. Watching for suspicious activity...")

    for line in process.stdout:
        line = line.strip()
        if not line:
            continue

        log = parse_log_line(line)
        if not log:
            continue

        event = log.get("event", "")
        ip = log.get("ip", "unknown")
        timestamp = log.get("timestamp", "")

        if event == "login_failed":
            now = datetime.now(timezone.utc)
            failed_logins[ip].append(now)
            window = now - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
            failed_logins[ip] = [t for t in failed_logins[ip] if t > window]
            count = len(failed_logins[ip])
            print(f"[WARNING] Failed login from {ip} — {count} attempts in last {FAILED_LOGIN_WINDOW_MINUTES} mins")
            if count >= FAILED_LOGIN_THRESHOLD and ip not in alerted_ips:
                alerted_ips.add(ip)
                send_alert(
                    f"Brute Force Detected from {ip}",
                    f"IP {ip} has made {count} failed login attempts in the last {FAILED_LOGIN_WINDOW_MINUTES} minutes.\n\nTimestamp: {timestamp}\nConsider blocking this IP in your security group."
                )

        elif event == "request" and log.get("status") == 429:
            print(f"[WARNING] Rate limit hit from {ip} on {log.get('path')}")
            send_alert(
                f"Rate Limit Hit from {ip}",
                f"IP {ip} hit the rate limit on {log.get('path')} at {timestamp}"
            )

        elif event == "account_deleted":
            print(f"[INFO] Account deleted by user_id {log.get('user_id')} from {ip}")

if __name__ == "__main__":
    monitor()
