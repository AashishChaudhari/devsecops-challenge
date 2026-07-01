import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

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
