from flask import Flask, request, jsonify
from markupsafe import escape
import bcrypt
from database import init_db, get_db

app = Flask(__name__)

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

    # Input validation
    if not username or not password:
        return {"error": "Username and password are required"}, 400

    if len(username) < 3 or len(username) > 30:
        return {"error": "Username must be between 3 and 30 characters"}, 400

    if len(password) < 8:
        return {"error": "Password must be at least 8 characters"}, 400

    if password != confirm_password:
        return {"error": "Passwords do not match"}, 400

    # Hash the password
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Insert into database
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
        return {"message": f"Account created successfully! Welcome, {escape(username)}"}, 201

    except Exception as e:
        # The UNIQUE constraint on username will raise an error for duplicates
        if "UNIQUE constraint failed" in str(e):
            return {"error": "Username already taken"}, 409
        return {"error": "Registration failed"}, 500

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
