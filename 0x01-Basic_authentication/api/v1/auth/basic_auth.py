#!/usr/bin/env python3
""" Module for Basic Authentication
"""
from api.v1.auth.auth import Auth
import base64
from typing import Tuple, TypeVar, Optional
from models.user import User


class BasicAuth(Auth):
    """ Basic Authentication class that inherits from Auth """

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """ Extracts the Base64 part of the Authorization header """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """Decodes the Base64 string to its UTF-8 value."""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extracts the user email and password
        from the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        parts = decoded_base64_authorization_header.split(':', 1)
        if len(parts) != 2:
            return None, None

        return parts[0], parts[1]

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """ Retrieve User instance from email and password """
        if isinstance(user_email, str) and isinstance(user_pwd, str):
            try:
                users = User.search({'email': user_email})
                if users and users[0].is_valid_password(user_pwd):
                    return users[0]
            except Exception:
                pass
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retrieves the current user based on the request's Auth header
        """
        if request is None:
            return None

        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return None

        base64_auth = self.extract_base64_authorization_header(auth_header)
        if base64_auth is None:
            return None

        decoded_auth = self.decode_base64_authorization_header(base64_auth)
        if decoded_auth is None:
            return None

        user_email, user_pwd = self.extract_user_credentials(decoded_auth)
        if user_email is None or user_pwd is None:
            return None

        return self.user_object_from_credentials(user_email, user_pwd)
