#!/usr/bin/env python3
"""
Module for managing session-based authentication in the API.
"""
from uuid import uuid4
from flask import request

from .auth import Auth
from models.user import User


class SessionAuth(Auth):
    """
    A class to handle session authentication.
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Generates a session ID for a given user and associates it with the user ID.
        
        Args:
            user_id (str): The ID of the user.

        Returns:
            str: The generated session ID, or None if the user ID is invalid.
        """
        if isinstance(user_id, str):
            session_id = str(uuid4())
            self.user_id_by_session_id[session_id] = user_id
            return session_id
        return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieves the user ID associated with a specific session ID.
        
        Args:
            session_id (str): The session ID to look up.

        Returns:
            str: The user ID associated with the session ID, or None if not found.
        """
        if isinstance(session_id, str):
            return self.user_id_by_session_id.get(session_id)
        return None

    def current_user(self, request=None) -> User:
        """
        Fetches the User object corresponding to the session cookie in the request.
        
        Args:
            request (Request): The HTTP request containing the session cookie.

        Returns:
            User: The User object corresponding to the session, or None if invalid.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        return User.get(user_id)

    def destroy_session(self, request=None) -> bool:
        """
        Invalidates a session, removing the session ID and its association.
        
        Args:
            request (Request): The HTTP request containing the session cookie.

        Returns:
            bool: True if the session was successfully destroyed, False otherwise.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if not request or not session_id or not user_id:
            return False
        self.user_id_by_session_id.pop(session_id, None)
        return True

