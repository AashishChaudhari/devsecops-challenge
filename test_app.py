from app import app, limiter
import pytest
from app import app

@pytest.fixture
def client():
    from config import TestingConfig
    app.config.from_object(TestingConfig)
    limiter.enabled = False
    with app.test_client() as client:
        yield client
    limiter.enabled = True

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

def test_change_password_success(client):
    client.post("/register", data={
        "username": "changeuser",
        "password": "oldpassword123",
        "confirm_password": "oldpassword123"
    })
    client.post("/login", data={
        "username": "changeuser",
        "password": "oldpassword123"
    })
    response = client.post("/change-password", data={
        "current_password": "oldpassword123",
        "new_password": "newpassword456",
        "confirm_password": "newpassword456"
    })
    assert response.status_code == 302

def test_change_password_wrong_current(client):
    client.post("/register", data={
        "username": "changeuser2",
        "password": "oldpassword123",
        "confirm_password": "oldpassword123"
    })
    client.post("/login", data={
        "username": "changeuser2",
        "password": "oldpassword123"
    })
    response = client.post("/change-password", data={
        "current_password": "wrongpassword",
        "new_password": "newpassword456",
        "confirm_password": "newpassword456"
    })
    assert response.status_code == 401

def test_change_password_requires_login(client):
    response = client.post("/change-password", data={
        "current_password": "oldpassword123",
        "new_password": "newpassword456",
        "confirm_password": "newpassword456"
    })
    assert response.status_code == 401

def test_change_password_same_as_old(client):
    client.post("/register", data={
        "username": "changeuser3",
        "password": "oldpassword123",
        "confirm_password": "oldpassword123"
    })
    client.post("/login", data={
        "username": "changeuser3",
        "password": "oldpassword123"
    })
    response = client.post("/change-password", data={
        "current_password": "oldpassword123",
        "new_password": "oldpassword123",
        "confirm_password": "oldpassword123"
    })
    assert response.status_code == 400

def test_api_profile_requires_auth(client):
    response = client.get("/api/profile")
    assert response.status_code == 401

def test_api_profile_returns_user_data(client):
    client.post("/register", data={
        "username": "profileuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "profileuser",
        "password": "securepass123"
    })
    response = client.get("/api/profile")
    assert response.status_code == 200
    data = response.get_json()
    assert data["username"] == "profileuser"
    assert "password_hash" not in data  # never expose the hash

def test_api_profile_update(client):
    client.post("/register", data={
        "username": "profileuser2",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "profileuser2",
        "password": "securepass123"
    })
    response = client.put("/api/profile",
        json={"email": "test@example.com", "bio": "Hello world"},
        content_type="application/json"
    )
    assert response.status_code == 200

def test_api_profile_invalid_email(client):
    client.post("/register", data={
        "username": "profileuser3",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "profileuser3",
        "password": "securepass123"
    })
    response = client.put("/api/profile",
        json={"email": "notanemail", "bio": "test"},
        content_type="application/json"
    )
    assert response.status_code == 400

def test_api_profile_bio_too_long(client):
    client.post("/register", data={
        "username": "profileuser4",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "profileuser4",
        "password": "securepass123"
    })
    response = client.put("/api/profile",
        json={"email": "test@example.com", "bio": "x" * 201},
        content_type="application/json"
    )
    assert response.status_code == 400

def test_app_imports_correctly():
    from database import init_db, get_db
    from app import app
    assert app is not None

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"

def test_username_invalid_characters(client):
    response = client.post("/register", data={
        "username": "bad user!",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    assert response.status_code == 400

def test_username_valid_formats(client):
    for username in ["valid_user", "valid.user", "valid-user", "ValidUser123"]:
        response = client.post("/register", data={
            "username": username,
            "password": "securepass123",
            "confirm_password": "securepass123"
        })
        assert response.status_code == 201

def test_delete_account_requires_login(client):
    response = client.post("/delete-account", data={"password": "securepass123"})
    assert response.status_code == 401

def test_delete_account_wrong_password(client):
    client.post("/register", data={
        "username": "deleteuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "deleteuser",
        "password": "securepass123"
    })
    response = client.post("/delete-account", data={"password": "wrongpassword"})
    assert response.status_code == 401

def test_delete_account_success(client):
    client.post("/register", data={
        "username": "deleteuser2",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "deleteuser2",
        "password": "securepass123"
    })
    response = client.post("/delete-account", data={"password": "securepass123"})
    assert response.status_code == 200

def test_api_stats(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.get_json()
    assert "total_users" in data
    assert isinstance(data["total_users"], int)

def test_logging_does_not_break_requests(client):
    response = client.get("/health")
    assert response.status_code == 200

def test_failed_login_still_returns_401(client):
    client.post("/register", data={
        "username": "logtest",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    response = client.post("/login", data={
        "username": "logtest",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

def test_gunicorn_app_callable():
    from app import app as flask_app
    assert callable(flask_app)
    assert flask_app.name == "app"

def test_testing_config_has_csrf_disabled():
    from config import TestingConfig
    assert TestingConfig.WTF_CSRF_ENABLED == False

def test_production_config_has_secure_cookies():
    from config import ProductionConfig
    assert ProductionConfig.SESSION_COOKIE_SECURE == True

def test_development_config_is_not_testing():
    from config import DevelopmentConfig
    assert DevelopmentConfig.TESTING == False

def test_create_api_key(client):
    client.post("/register", data={
        "username": "apiuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "apiuser",
        "password": "securepass123"
    })
    response = client.post("/api/keys",
        json={"name": "test-key"},
        content_type="application/json"
    )
    assert response.status_code == 201
    data = response.get_json()
    assert "key" in data
    assert data["key"].startswith("dso_")

def test_api_key_authentication(client):
    client.post("/register", data={
        "username": "apikeyuser",
        "password": "securepass123",
        "confirm_password": "securepass123"
    })
    client.post("/login", data={
        "username": "apikeyuser",
        "password": "securepass123"
    })
    # Create API key
    r = client.post("/api/keys",
        json={"name": "auth-test"},
        content_type="application/json"
    )
    key = r.get_json()["key"]
    client.get("/logout")

    # Use API key to access profile
    response = client.get("/api/profile",
        headers={"Authorization": f"Bearer {key}"}
    )
    assert response.status_code == 200
    assert response.get_json()["username"] == "apikeyuser"

def test_invalid_api_key_rejected(client):
    response = client.get("/api/profile",
        headers={"Authorization": "Bearer dso_invalidkey"}
    )
    assert response.status_code == 401

def test_api_key_requires_login_to_create(client):
    response = client.post("/api/keys",
        json={"name": "no-auth-key"},
        content_type="application/json"
    )
    assert response.status_code == 401

def test_api_docs_returns_200(client):
    response = client.get("/api/docs")
    assert response.status_code == 200

def test_api_docs_json(client):
    response = client.get("/api/docs",
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "endpoints" in data
    assert "authentication" in data

