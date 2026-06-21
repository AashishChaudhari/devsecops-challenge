from flask import Flask, request

app = Flask(__name__)

# Fake in-memory "database"
users = {
    "admin": "supersecret123",
    "aashish": "mypassword"
}

@app.route("/")
def home():
    name = request.args.get("name", "Guest")
    # VULNERABLE: directly inserting user input into HTML
    return f"<h1>Welcome, {name}!</h1>"

@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # VULNERABLE: fake SQL-style check using string building
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"Running query: {query}")  # simulate what a real SQL query would look like

    if username in users and users[username] == password:
        return f"<h2>Login successful! Welcome {username}</h2>"
    elif "' OR '1'='1" in password or "' OR '1'='1" in username:
        return "<h2>Login successful! (Bypassed with SQL Injection!) 🚨</h2>"
    else:
        return "<h2>Login failed</h2>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6001)
