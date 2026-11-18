"""A tiny user store backed by SQLite (Python standard library only).

Deliberately vulnerable: `find_user` builds its SQL with an f-string, so a
crafted name injects SQL (CWE-89). This repository exists to exercise RSOLV.
"""
import sqlite3


def connect(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, "
        "email TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0)"
    )
    return conn


def add_user(conn, name, email, is_admin=False):
    conn.execute(
        "INSERT INTO users (name, email, is_admin) VALUES (?, ?, ?)",
        (name, email, int(is_admin)),
    )
    conn.commit()


def find_user(conn, name):
    """Return (id, name, email) for the user called `name`, or None."""
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, name, email FROM users WHERE name = '{name}'")
    return cursor.fetchone()
