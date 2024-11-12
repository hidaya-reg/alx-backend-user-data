#!/usr/bin/env python3
""" Authentication module for the API. """
from flask import request
from typing import List, TypeVar


class Auth:
    """ A template for all authentication systems. """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines if authentication is required. """
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True

        if not path.endswith('/'):
            path += '/'

        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """ Retrieves the authorization header from the request. """
        return None

    def authorization_header(self, request=None) -> str:
        """ Retrieves the authorization header from the request. """
        if request is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retrieves the current user. """
        return None
