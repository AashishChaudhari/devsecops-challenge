from flask import Flask, request, jsonify, session, redirect, url_for
from markupsafe import escape
from datetime import timedelta
import bcrypt
import os
import secrets
from database import init_db, get_db

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
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
    return add_security_headers(response)

@app.route("/")
def home():
    return "Hello from my DevSecOps app!"

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/register", methods=["GET"])
def register_page():
    return """
    <html>
    <head><title>Register</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
        <h2>Create an account</h2>
        <form action="/register" method="post">
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
        return {"error": "Username and password are required"}, 400

    if len(username) < 3 or len(username) > 30:
        return {"error": "Username must be between 3 and 30 characters"}, 400

    if len(password) < 8:
        return {"error": "Password must be at least 8 characters"}, 400

    if password != confirm_password:
        return {"error": "Passwords do not match"}, 400

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
        return {"message": f"Account created successfully! Welcome, {escape(username)}"}, 201

    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return {"error": "Username already taken"}, 409
        return {"error": "Registration failed"}, 500

@app.route("/login-page")
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return """
    <html>
    <head><title>Login</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
        <h2>Login</h2>
        <form action="/login" method="post">
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

        if remember_me:
            # Makes the cookie persist on disk for PERMANENT_SESSION_LIFETIME
            session.permanent = True
        else:
            # Session cookie only — disappears when browser closes
            session.permanent = False

        return redirect(url_for("dashboard"))

    return {"error": "Invalid username or password"}, 401

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
        <a href="/logout">Log out</a>
    </body>
    </html>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
