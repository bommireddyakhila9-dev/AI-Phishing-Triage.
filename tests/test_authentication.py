"""
Tests for authentication: password hashing, registration, and login verification.
"""

import os
import tempfile
import pytest
from modules.authentication import authenticate_user, hash_password, register_user, verify_password
from modules.database import init_db


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_password_hashing():
    pwd = "SecretPassword123!"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_user_registration_and_auth(temp_db):
    ok, msg = register_user("sec_analyst", "ComplexPassword99!", role="SOC Lead", db_path=temp_db)
    assert ok is True

    # Duplicate username rejection
    ok_dup, msg_dup = register_user("sec_analyst", "AnotherPassword!", db_path=temp_db)
    assert ok_dup is False
    assert "already taken" in msg_dup

    # Successful authentication
    auth_ok, user_data, auth_msg = authenticate_user("sec_analyst", "ComplexPassword99!", db_path=temp_db)
    assert auth_ok is True
    assert user_data["username"] == "sec_analyst"
    assert user_data["role"] == "SOC Lead"

    # Failed authentication (bad password)
    auth_bad, _, _ = authenticate_user("sec_analyst", "BadPassword!", db_path=temp_db)
    assert auth_bad is False

    # Failed authentication (non-existent user)
    auth_none, _, _ = authenticate_user("ghost_analyst", "ComplexPassword99!", db_path=temp_db)
    assert auth_none is False
