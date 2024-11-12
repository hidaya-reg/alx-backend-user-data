#!/usr/bin/env python3
"""Basic Authentication module for the API."""
from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ BasicAuth class that inherits from Auth. """

    def extract_base64_authorization_header(
            self,
            authorization_header: str
    ) -> str:
        """
        Extracts the Base64 part of the Authorization header
        for Basic Authentication.

        Args:
            authorization_header (str): The authorization header
            from the request.

        Returns:
            str: The Base64 part of the Authorization header,
            or None if conditions are not met.
        """
        if (authorization_header is None or
                not isinstance(authorization_header, str)):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes the Base64 part of an authorization header to a UTF-8 string.

        Args:
            base64_authorization_header (str): The Base64 encoded
            authorization header.

        Returns:
            str: The decoded string in UTF-8 if the decoding is successful.
            None: If the input is invalid, not a string, or cannot be
            decoded as Base64.

        """
        if (base64_authorization_header is None or
                not isinstance(base64_authorization_header, str)):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts the user email and password from the
        decoded Base64 authorization header.

        Args:
            decoded_base64_authorization_header (str):
            The decoded Base64 authorization header.

        Returns:
            tuple: A tuple containing the email and password as strings.
                   Returns (None, None) if input is invalid or if the
                   format is incorrect.
        """
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(":", 1)
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Retrieves a User instance based on the email and password provided.

        Args:
            user_email (str): The email of the user.
            user_pwd (str): The password of the user.

        Returns:
            User: The User instance if credentials are valid.
            None: If any validation fails (invalid email or password).
        """
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        # Search for the user by email
        user = User.search(user_email)

        # Check if user exists and password is valid
        if user is None or not user.is_valid_password(user_pwd):
            return None

        return user
