"""
Authentication & User Management Module
Implements secure password hashing with bcrypt, constant-time verification,
user creation, and Streamlit session state binding.
"""

import hashlib
import os
import secrets
from typing import Optional, Tuple
import bcrypt

from modules.database import get_db_connection


def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using bcrypt with a generated salt.
    Falls back to salted PBKDF2-HMAC-SHA256 if bcrypt encounters runtime library issues.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    try:
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")
    except Exception:
        # PBKDF2 Fallback
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return f"pbkdf2${salt}${key.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verifies a plaintext password against the stored password hash.
    """
    if not plain_password or not stored_hash:
        return False
    try:
        if stored_hash.startswith("pbkdf2$"):
            parts = stored_hash.split("$")
            if len(parts) == 3:
                _, salt, key_hex = parts
                test_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100000)
                return secrets.compare_digest(test_key.hex(), key_hex)
        return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        return False


def register_user(username: str, password: str, role: str = "Security Analyst", db_path: Optional[str] = None) -> Tuple[bool, str]:
    """
    Registers a new user with hashed password.
    """
    username = username.strip().lower()
    if len(username) < 3:
        return False, "Username must be at least 3 characters long."
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."

    pwd_hash = hash_password(password)
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, pwd_hash, role)
        )
        conn.commit()
        conn.close()
        return True, "User registered successfully."
    except Exception as exc:
        conn.close()
        if "UNIQUE constraint failed" in str(exc):
            return False, f"Username '{username}' is already taken."
        return False, f"Registration failed: {str(exc)}"


def authenticate_user(username: str, password: str, db_path: Optional[str] = None) -> Tuple[bool, Optional[dict], str]:
    """
    Authenticates a user against stored hash.
    """
    username = username.strip().lower()
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, None, "Invalid username or password."

    stored_hash = row["password_hash"]
    if verify_password(password, stored_hash):
        user_info = {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
        }
        return True, user_info, "Authentication successful."
    return False, None, "Invalid username or password."


def seed_default_admin(db_path: Optional[str] = None) -> None:
    """
    Seeds a default analyst account if the users table is completely empty.
    Default credentials: analyst / socAnalyst2026!
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users;")
    count = cur.fetchone()[0]
    conn.close()

    if count == 0:
        register_user("analyst", "socAnalyst2026!", role="Senior SOC Analyst", db_path=db_path)
        register_user("admin", "socAdmin2026!", role="SOC Lead", db_path=db_path)
