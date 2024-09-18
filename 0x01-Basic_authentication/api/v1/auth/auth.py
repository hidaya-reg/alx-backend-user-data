#!/usr/bin/env python3
""" Authentication module
"""
from typing import List, TypeVar
from flask import request


class Auth:
    """a class to manage the API authentication."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines if a path requires authentication """
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True
        normalized_path = path.rstrip('/') + '/'
        for excluded in excluded_paths:
            normalized_excluded = excluded.rstrip('/') + '/'
            if normalized_path == normalized_excluded:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Returns the authorization header """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns the current user """
        return None
