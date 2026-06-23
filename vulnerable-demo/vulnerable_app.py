from flask import Flask, request
from markupsafe import escape
import sqlite3
import os

app = Flask(__name__)

# Set up a real SQLite database instead of fake in-memory checks
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
    # FIXED: escape() converts <, >, ", ' into safe HTML entities
    # so the browser displays them as TEXT, never executes them as code
    safe_name = escape(name)
    return f"<h1>Welcome, {safe_name}!</h1>"

@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # FIXED: parameterized query — the ? placeholders mean username/password
    # are ALWAYS treated as data, never as part of the SQL command itself.
    # No string ever gets "built" — so there's no query for an attacker to break out of.
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
