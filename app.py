from logger import setup_logging, get_logger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask import Flask, request, jsonify, session, redirect, url_for
from markupsafe import escape
from datetime import timedelta
from flask_limiter.errors import RateLimitExceeded
import bcrypt
import os
import secrets
import re
from database import init_db, get_db

app = Flask(__name__)
setup_logging()
log = get_logger(__name__)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; form-action 'self'; frame-ancestors 'none'"
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Server'] = 'webserver'
    return response

from datetime import datetime, timezone

@app.before_request
def check_session_expiry():
    if "user_id" in session:
        last_active = session.get("last_active")
        now = datetime.now(timezone.utc).isoformat()

        if last_active:
            last_active_dt = datetime.fromisoformat(last_active)
            # Force logout after 30 days regardless of cookie
            if (datetime.now(timezone.utc) - last_active_dt).days >= 30:
                session.clear()
                return redirect(url_for("login_page"))

        session["last_active"] = now

@app.after_request
def apply_security_headers(response):
    if request.path != "/health":
        log.info("request",
            method=request.method,
            path=request.path,
            status=response.status_code,
            ip=request.remote_addr
        )
    return add_security_headers(response)

@app.route("/")
def home():
    return "Hello from my DevSecOps app! Now live on AWS EC2!"

@app.route("/health")
@limiter.exempt
def health():
    return {"status": "ok"}

@app.route("/register", methods=["GET"])
@limiter.limit("10 per hour")
def register_page():
    token = generate_csrf()
    return f"""
    <html>
    <head><title>Register</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
        <h2>Create an account</h2>
        <form action="/register" method="post">
            <input type="hidden" name="csrf_token" value="{token}">
            <label>Username:</label><br>
            <input type="text" name="username" required minlength="3" maxlength="30"><br><br>
            <label>Password:</label><br>
            <input type="password" name="password" required minlength="8"><br><br>
            <label>Confirm password:</label><br>
            <input type="password" name="confirm_password" required minlength="8"><br><br>
            <button type="submit">Register</button>
        </form>
        <p>Already have an account? <a href="/login-page">Log in</a></p>
    </body>
    </html>
    """

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not username or not password:
        log.warning("registration_failed",
            reason="missing_fields",
            ip=request.remote_addr
        )
        return {"error": "Username and password are required"}, 400

    if len(username) < 3 or len(username) > 30:
        log.warning("registration_failed",
            reason="invalid_username_length",
            username=username,
            ip=request.remote_addr
        )
        return {"error": "Username must be between 3 and 30 characters"}, 400

    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        log.warning("registration_failed",
            reason="invalid_username_format",
            username=username,
            ip=request.remote_addr
        )
        return {"error": "Username can only contain letters, numbers, underscores, dots and hyphens"}, 400

    if len(password) < 8:
        log.warning("registration_failed",
            reason="password_too_short",
            username=username,
            ip=request.remote_addr
        )
        return {"error": "Password must be at least 8 characters"}, 400

    if password != confirm_password:
        log.warning("registration_failed",
            reason="password_mismatch",
            username=username,
            ip=request.remote_addr
        )
        return {"error": "Passwords do not match"}, 400

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
        log.info("registration_success",
            username=username,
            ip=request.remote_addr
        )
        return {"message": f"Account created successfully! Welcome, {escape(username)}"}, 201

    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            log.warning("registration_failed",
                reason="username_taken",
                username=username,
                ip=request.remote_addr
            )
            return {"error": "Username already taken"}, 409
        log.error("registration_error",
            username=username,
            error=str(e),
            ip=request.remote_addr
        )
        return {"error": "Registration failed"}, 500

@app.route("/login-page")
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    token = generate_csrf()
    return f"""
    <html>
    <head><title>Login</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
        <h2>Login</h2>
        <form action="/login" method="post">
            <input type="hidden" name="csrf_token" value="{token}">
            <label>Username:</label><br>
            <input type="text" name="username" required><br><br>
            <label>Password:</label><br>
            <input type="password" name="password" required><br><br>
            <label>
                <input type="checkbox" name="remember_me" value="1">
                Remember me for 30 days
            </label><br><br>
            <button type="submit">Log in</button>
        </form>
        <p>Don't have an account? <a href="/register">Register</a></p>
    </body>
    </html>
    """

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    remember_me = request.form.get("remember_me") == "1"

    if not username or not password:
        return {"error": "Username and password are required"}, 400

    with get_db() as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if row and bcrypt.checkpw(password.encode("utf-8"), row["password_hash"]):
        session.clear()
        session["user_id"] = row["id"]
        session["username"] = username

        with get_db() as conn:
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), row["id"])
            )

        log.info("login_success",
            username=username,
            ip=request.remote_addr,
            remember_me=remember_me
        )

        if remember_me:
            session.permanent = True
        else:
            session.permanent = False

        return redirect(url_for("dashboard"))

    log.warning("login_failed",
        username=username,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "unknown")
    )
    return {"error": "Invalid username or password"}, 401

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(e):
    return {
        "error": "Too many requests. Please slow down and try again later.",
        "retry_after": str(e.description)
    }, 429

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    username = escape(session["username"])
    last_active = session.get("last_active", "Unknown")
    session_type = "Persistent (30 days)" if session.permanent else "Session only"
    return f"""
    <html>
    <head><title>Dashboard</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
        <h2>Welcome, {username}!</h2>
        <p>You are logged in.</p>
        <p>User ID: {session['user_id']}</p>
        <p>Session type: {session_type}</p>
        <p>Last active: {last_active}</p>
        <p><a href="/change-password">Change password</a></p>
	<p><a href="/delete-account-page">Delete account</a></p>
	<p><a href="/api/profile">View profile (JSON)</a></p>
        <a href="/logout">Log out</a>
    </body>
    </html>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/change-password", methods=["GET"])
def change_password_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    token = generate_csrf()
    return f"""
    <html>
    <head><title>Change Password</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
        <h2>Change Password</h2>
        <form action="/change-password" method="post">
            <input type="hidden" name="csrf_token" value="{token}">
            <label>Current password:</label><br>
            <input type="password" name="current_password" required><br><br>
            <label>New password:</label><br>
            <input type="password" name="new_password" required minlength="8"><br><br>
            <label>Confirm new password:</label><br>
            <input type="password" name="confirm_password" required minlength="8"><br><br>
            <button type="submit">Change Password</button>
        </form>
        <p><a href="/dashboard">Back to dashboard</a></p>
    </body>
    </html>
    """

@app.route("/change-password", methods=["POST"])
@limiter.limit("5 per hour")
def change_password():
    if "user_id" not in session:
        return {"error": "Not logged in"}, 401

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # Validation
    if not current_password or not new_password:
        return {"error": "All fields are required"}, 400

    if len(new_password) < 8:
        return {"error": "New password must be at least 8 characters"}, 400

    if new_password != confirm_password:
        return {"error": "New passwords do not match"}, 400

    if current_password == new_password:
        return {"error": "New password must be different from current password"}, 400

    # Verify current password
    with get_db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    if not row or not bcrypt.checkpw(current_password.encode("utf-8"), row["password_hash"]):
        return {"error": "Current password is incorrect"}, 401

    # Hash and save new password
    new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, session["user_id"])
        )

    log.info("password_changed",
        user_id=session["user_id"],
        ip=request.remote_addr
    )

    # Clear session — force re-login with new password
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/api/profile", methods=["GET"])
def api_profile():
    if "user_id" not in session:
        return {"error": "Authentication required"}, 401

    with get_db() as conn:
        row = conn.execute(
            "SELECT id, username, email, bio, created_at, last_login FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    if not row:
        return {"error": "User not found"}, 404

    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "bio": row["bio"],
        "created_at": row["created_at"],
        "last_login": row["last_login"]
    }, 200

@app.route("/api/profile", methods=["PUT"])
@limiter.limit("10 per hour")
def api_update_profile():
    if "user_id" not in session:
        return {"error": "Authentication required"}, 401

    data = request.get_json()

    if not data:
        return {"error": "Request body must be JSON"}, 400

    email = data.get("email", "").strip()
    bio = data.get("bio", "").strip()

    if email and ("@" not in email or "." not in email.split("@")[-1]):
        return {"error": "Invalid email format"}, 400

    if len(bio) > 200:
        return {"error": "Bio must be 200 characters or less"}, 400

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET email = ?, bio = ? WHERE id = ?",
            (email or None, bio, session["user_id"])
        )

    return {"message": "Profile updated successfully"}, 200

@app.route("/delete-account-page")
def delete_account_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    token = generate_csrf()
    return f"""
    <html>
    <head><title>Delete Account</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
        <h2>Delete Account</h2>
        <p style="color: red;">This action is permanent and cannot be undone.</p>
        <form action="/delete-account" method="post">
            <input type="hidden" name="csrf_token" value="{token}">
            <label>Enter your password to confirm:</label><br>
            <input type="password" name="password" required><br><br>
            <button type="submit" style="background: red; color: white; padding: 8px 16px;">
                Delete my account
            </button>
        </form>
        <p><a href="/dashboard">Cancel</a></p>
    </body>
    </html>
    """

@app.route("/delete-account", methods=["POST"])
@limiter.limit("3 per hour")
def delete_account():
    if "user_id" not in session:
        return {"error": "Not logged in"}, 401

    password = request.form.get("password", "")

    if not password:
        return {"error": "Password required to delete account"}, 400

    with get_db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    if not row or not bcrypt.checkpw(password.encode("utf-8"), row["password_hash"]):
        return {"error": "Incorrect password"}, 401

    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (session["user_id"],))

    log.info("account_deleted",
        user_id=session["user_id"],
        ip=request.remote_addr
    )

    session.clear()
    return {"message": "Account deleted successfully"}, 200

@app.route("/api/stats")
def api_stats():
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return {"total_users": count}, 200

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
