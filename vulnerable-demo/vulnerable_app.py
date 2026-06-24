from flask import Flask, request
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3

app = Flask(__name__)

# Tracks requests per IP address, in memory (fine for learning/demo purposes)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('admin', 'supersecret123')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('aashish', 'mypassword')")
    conn.commit()
    conn.close()

@app.route("/")
def home():
    name = request.args.get("name", "Guest")
    safe_name = escape(name)
    return f"<h1>Welcome, {safe_name}!</h1>"

@app.route("/login", methods=["GET"])
@limiter.limit("5 per minute")   # FIXED: max 5 login attempts per minute per IP
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    )
    user = cursor.fetchone()
    conn.close()

    if user:
        return f"<h2>Login successful! Welcome {escape(username)}</h2>"
    else:
        return "<h2>Login failed</h2>"

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=6001)
