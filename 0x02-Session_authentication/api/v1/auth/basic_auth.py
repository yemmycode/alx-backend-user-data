#!/usr/bin/env python3
"""Handle basic authentication."""
import base64
from typing import Tuple, TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Class to define attributes and methods for Basic Authorization.
    Inherits from Auth class.
    
    Args:
        Auth (class): Parent authentication class
    """

    def extract_base64_authorization_header(
            self,
            authorization_header: str
            ) -> str:
        """Extracts the Base64 part of the Authorization header
        for Basic Authentication.
        
        Args:
            authorization_header (str): The authorization header.
        
        Returns:
            str: The base64 part of the header.
        """
        if not (authorization_header and isinstance(authorization_header, str) 
                and authorization_header.startswith('Basic ')):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str
            ) -> str:
        """Decodes the Base64 string in the Authorization header.
        
        Args:
            base64_authorization_header (str): The Base64 encoded authorization header.
        
        Returns:
            str: The decoded value of the Base64 string.
        """
        if not (base64_authorization_header and isinstance(base64_authorization_header, str)):
            return None
        
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except BaseException:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
            ) -> Tuple[str, str]:
        """Extracts the user email and password from the decoded Base64 string.
        
        Args:
            decoded_base64_authorization_header (str): The decoded authorization header.
        
        Returns:
            Tuple[str, str]: A tuple containing the email and password.
        """
        if not (decoded_base64_authorization_header and isinstance(decoded_base64_authorization_header, str)
                and ':' in decoded_base64_authorization_header):
            return None, None

        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on email and password.
        
        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.
        
        Returns:
            User: A user object if credentials are valid, otherwise None.
        """
        if not (user_email and isinstance(user_email, str) 
                and user_pwd and isinstance(user_pwd, str)):
            return None

        try:
            users = User.search({'email': user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current user based on the request."""
        try:
            auth_header = self.authorization_header(request)
            encoded = self.extract_base64_authorization_header(auth_header)
            decoded = self.decode_base64_authorization_header(encoded)
            email, password = self.extract_user_credentials(decoded)
            return self.user_object_from_credentials(email, password)
        except Exception:
            return None

