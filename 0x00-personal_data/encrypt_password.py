#!/usr/bin/env python3
"""Implement the hash_password function"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt and returns the salted, hashed password.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a hashed password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
