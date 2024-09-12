#!/usr/bin/env python3
"""Implement the hash_password function"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt and returns the salted, hashed password.
    
    :param password: The password to hash (string).
    :return: The hashed password (byte string).
    """
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password
