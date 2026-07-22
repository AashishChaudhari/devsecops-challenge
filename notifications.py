import os
import json
import urllib.request
from datetime import datetime, timezone


def send_discord_alert(title, description, color=0xff0000, fields=None):
    """
    Send an alert to Discord via webhook.
    color: 0xff0000 = red (critical), 0xffa500 = orange (warning), 0x00ff00 = green (info)
    """
    DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
    if not DISCORD_WEBHOOK_URL:
        print(f"[WEBHOOK] {title}: {description}")
        return False

    embed = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {
            "text": "DevSecOps Security Monitor"
        }
    }

    if fields:
        embed["fields"] = [
            {"name": k, "value": str(v), "inline": True}
            for k, v in fields.items()
        ]

    payload = json.dumps({
        "content": f"**{title}**\n{description}"
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DiscordBot (devsecops, 1.0)"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 204
    except Exception as e:
        print(f"[WEBHOOK FAILED] {e}")
        return False


def alert_failed_login(username, ip, attempt_count):
    send_discord_alert(
        title="🚨 Brute Force Attempt Detected",
        description=f"Multiple failed login attempts from the same IP",
        color=0xff0000,
        fields={
            "Username": username,
            "IP Address": ip,
            "Attempts": attempt_count
        }
    )


def alert_account_deleted(user_id, ip):
    send_discord_alert(
        title="⚠️ Account Deleted",
        description="A user account was permanently deleted",
        color=0xffa500,
        fields={
            "User ID": user_id,
            "IP Address": ip
        }
    )


def alert_new_registration(username, ip):
    send_discord_alert(
        title="✅ New User Registered",
        description="A new account was created",
        color=0x00ff00,
        fields={
            "Username": username,
            "IP Address": ip
        }
    )


def alert_rate_limit_hit(ip, path):
    send_discord_alert(
        title="⚡ Rate Limit Hit",
        description=f"An IP hit the rate limit",
        color=0xffa500,
        fields={
            "IP Address": ip,
            "Endpoint": path
        }
    )
