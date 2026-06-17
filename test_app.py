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
