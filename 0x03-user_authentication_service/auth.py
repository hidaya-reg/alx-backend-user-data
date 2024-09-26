#!/usr/bin/env python3
"""Module for authentication.
"""

import bcrypt


def _hash_password(password: str) -> bytes:
    """Hash a password using bcrypt.
    """
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed
