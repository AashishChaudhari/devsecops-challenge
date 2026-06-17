from flask import Flask

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
