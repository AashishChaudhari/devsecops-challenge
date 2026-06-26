from flask import Flask, request
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import bcrypt

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

DB_PATH = "users.db"

def hash_password(plain_password):
    # bcrypt automatically generates a random "salt" each time,
    # so even identical passwords produce different hashes
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())

def check_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash BLOB NOT NULL
        )
    """)
    # Only seed users if the table is empty (avoids re-hashing on every restart)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users VALUES (?, ?)",
            ("admin", hash_password("supersecret123"))
        )
        cursor.execute(
            "INSERT INTO users VALUES (?, ?)",
            ("aashish", hash_password("mypassword"))
        )
    conn.commit()
    conn.close()

@app.route("/")
def home():
    name = request.args.get("name", "Guest")
    safe_name = escape(name)
    return f"<h1>Welcome, {safe_name}!</h1>"

@app.route("/login-page")
def login_page():
    return """
    <html>
    <head><title>Login</title></head>
    <body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
        <h2>Login</h2>
        <form action="/login" method="get">
            <label>Username:</label><br>
            <input type="text" name="username" required><br><br>
            <label>Password:</label><br>
            <input type="password" name="password" required><br><br>
            <button type="submit">Log in</button>
        </form>
    </body>
    </html>
    """

@app.route("/login", methods=["GET"])
@limiter.limit("5 per minute")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    # FIXED: compare hashes, never compare or store plaintext passwords
    if row and check_password(password, row[0]):
        return f"<h2>Login successful! Welcome {escape(username)}</h2>"
    else:
        return "<h2>Login failed</h2>"

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=6001)
