#!/usr/bin/env python3
"""
Module for session authentication with expiration.
"""
import os
from flask import request
from datetime import datetime, timedelta

from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """
    Handles session authentication with expiration support.
    """

    def __init__(self) -> None:
        """
        Initializes the SessionExpAuth instance with session duration.

        The session duration is fetched from the environment variable 
        'SESSION_DURATION'. If it's not set or invalid, the duration defaults to 0.
        """
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """
        Creates a session ID for the specified user and records its creation time.

        Args:
            user_id (str): The ID of the user to associate with the session.

        Returns:
            str: The created session ID, or None if invalid.
        """
        session_id = super().create_session(user_id)
        if not isinstance(session_id, str):
            return None

        self.user_id_by_session_id[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """
        Retrieves the user ID associated with the provided session ID,
        considering session expiration.

        Args:
            session_id (str): The session ID to look up.

        Returns:
            str: The user ID if the session is valid and not expired, 
            or None otherwise.
        """
        session_data = self.user_id_by_session_id.get(session_id)
        if not session_data:
            return None

        # Check if the session duration is set; if not, return the user ID.
        if self.session_duration <= 0:
            return session_data['user_id']

        # Ensure 'created_at' exists in the session data.
        created_at = session_data.get('created_at')
        if not created_at:
            return None

        # Check if the session has expired.
        expiration_time = created_at + timedelta(seconds=self.session_duration)
        if datetime.now() > expiration_time:
            return None

        return session_data['user_id']

