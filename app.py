from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello from my DevSecOps app!"

@app.route("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
