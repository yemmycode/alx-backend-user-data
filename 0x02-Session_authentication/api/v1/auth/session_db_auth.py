#!/usr/bin/env python3
"""
Module for session authentication with expiration and persistent storage.
"""
from flask import request
from datetime import datetime, timedelta

from models.user_session import UserSession
from .session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """
    Handles session authentication with expiration and database storage.
    """

    def create_session(self, user_id=None) -> str:
        """
        Creates a session ID for a user and stores it in the database.

        Args:
            user_id (str): The ID of the user to associate with the session.

        Returns:
            str: The created session ID, or None if invalid.
        """
        session_id = super().create_session(user_id)
        if isinstance(session_id, str):
            user_session = UserSession(user_id=user_id, session_id=session_id)
            user_session.save()
            return session_id
        return None

    def user_id_for_session_id(self, session_id=None):
        """
        Retrieves the user ID associated with a given session ID, considering expiration.

        Args:
            session_id (str): The session ID to search for.

        Returns:
            str: The user ID associated with the session ID, or None if expired or not found.
        """
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None

        if not sessions:
            return None

        session = sessions[0]
        cur_time = datetime.now()
        exp_time = session.created_at + timedelta(seconds=self.session_duration)

        if cur_time > exp_time:
            return None

        return session.user_id

    def destroy_session(self, request=None) -> bool:
        """
        Deletes a session ID and removes its database entry.

        Args:
            request (Request): The HTTP request containing the session cookie.

        Returns:
            bool: True if the session was successfully deleted, False otherwise.
        """
        session_id = self.session_cookie(request)
        if not session_id:
            return False

        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False

        if not sessions:
            return False

        sessions[0].remove()
        return True

