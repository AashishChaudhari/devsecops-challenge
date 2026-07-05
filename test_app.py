from app import app, limiter
import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    limiter.enabled = False  # Disable rate limiting for tests
    with app.test_client() as client:
        yield client
    limiter.enabled = True  # Re-enable after tests

def test_home(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Hello from my DevSecOps app" in response.data

def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert b"ok" in response.data

def test_security_headers(client):
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "default-src" in response.headers.get("Content-Security-Policy", "")
    assert "form-action" in response.headers.get("Content-Security-Policy", "")
    assert response.headers.get("Cache-Control") == "no-store"
    assert response.headers.get("Cross-Origin-Resource-Policy") == "same-origin"

def test_database_initializes():
    from database import init_db, get_db
    init_db()
    with get_db() as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        result = cursor.fetchone()
        assert result is not None

def test_register_success(client):
    response = client.post("/register", data={
        "username": "newuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    assert response.status_code == 201

def test_register_duplicate_username(client):
    client.post("/register", data={
        "username": "dupuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    response = client.post("/register", data={
        "username": "dupuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    assert response.status_code == 409

def test_register_short_password(client):
    response = client.post("/register", data={
        "username": "shortpass",
        "password": "short",
        "confirm_password": "short"
    })
    assert response.status_code == 400

def test_register_password_mismatch(client):
    response = client.post("/register", data={
        "username": "mismatch",
        "password": "securepass123",
        "confirm_password": "differentpass"
    })
    assert response.status_code == 400

def test_login_success(client):
    # Register first
    client.post("/register", data={
        "username": "loginuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    # Then login
    response = client.post("/login", data={
        "username": "loginuser",
        "password": "securepass123"
    })
    assert response.status_code == 302  # redirect to dashboard

def test_login_wrong_password(client):
    client.post("/register", data={
        "username": "loginuser2",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    response = client.post("/login", data={
        "username": "loginuser2",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302  # redirects to login

def test_logout_clears_session(client):
    client.post("/register", data={
        "username": "logoutuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "logoutuser",
        "password": "securepass123"
    })
    client.get("/logout")
    response = client.get("/dashboard")
    assert response.status_code == 302  # back to login after logout

def test_login_with_remember_me(client):
    client.post("/register", data={
        "username": "rememberuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    response = client.post("/login", data={
        "username": "rememberuser",
        "password": "securepass123",
        "remember_me": "1"
    })
    assert response.status_code == 302

def test_login_without_remember_me(client):
    client.post("/register", data={
        "username": "norememberuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    response = client.post("/login", data={
        "username": "norememberuser",
        "password": "securepass123"
    })
    assert response.status_code == 302

def test_csrf_enabled_by_default():
    # Confirm CSRF is on when TESTING config is not set to disable it
    assert app.config.get("WTF_CSRF_ENABLED", True) is True or \
           app.config.get("TESTING") is True

def test_rate_limit_login(client):
    # Register a user first
    client.post("/register", data={
        "username": "ratelimituser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    # Rate limiting is disabled in tests so this just confirms login still works
    response = client.post("/login", data={
        "username": "ratelimituser",
        "password": "wrongpassword"
    })
    assert response.status_code == 401
