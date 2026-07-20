import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change-in-production"
    DB_PATH = os.environ.get("DB_PATH", "app.db")
    RATELIMIT_STORAGE_URI = "memory://"
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME_DAYS = 30

class DevelopmentConfig(Config):
    DEBUG = False
    TESTING = False
    LOG_LEVEL = "DEBUG"
    WTF_CSRF_ENABLED = True

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    LOG_LEVEL = "INFO"
    SESSION_COOKIE_SECURE = True  # HTTPS only in production
    WTF_CSRF_ENABLED = True

class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False
    DB_PATH = ":memory:"
    LOG_LEVEL = "ERROR"

config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig
}

def get_config():
    env = os.environ.get("FLASK_ENV", "development")
    return config.get(env, config["default"])
