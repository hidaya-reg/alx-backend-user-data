#!/usr/bin/env python3
""" Authentication module
"""
from typing import List, TypeVar
from flask import request


class Auth:
    """a class to manage the API authentication."""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines if a path requires authentication """
        return False

    def authorization_header(self, request=None) -> str:
        """ Returns the authorization header """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns the current user """
        return None
