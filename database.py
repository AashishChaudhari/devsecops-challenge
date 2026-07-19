import sqlite3
from contextlib import contextmanager

import os
DB_PATH = os.environ.get("DB_PATH", "app.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            email TEXT UNIQUE,
            bio TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

@contextmanager
def get_db():
    """
    A context manager so every route can safely open and close
    a connection without forgetting to close it (connection leaks
    are a real, common bug in small Flask apps).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name, not just index
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
