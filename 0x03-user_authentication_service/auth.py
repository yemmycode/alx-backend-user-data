#!/usr/bin/env python3
"""Module for handling authentication-related operations."""
import bcrypt
from uuid import uuid4
from typing import Union
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Generates a hashed version of the provided password."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt)


def _generate_uuid() -> str:
    """Creates and returns a unique identifier (UUID)."""
    return str(uuid4())


class Auth:
    """Handles authentication actions and database interactions."""

    def __init__(self):
        """Sets up a new instance of the Auth class with database access."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user with an email and password."""
        try:
            # Check if the user already exists in the database
            self._db.find_user_by(email=email)
        except NoResultFound:
            # If user does not exist, create and return the new user
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)
        # Raise an error if the user already exists
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Validates a user's login credentials."""
        try:
            user = self._db.find_user_by(email=email)
            if user and bcrypt.checkpw(password.encode("utf-8"), user.hashed_password):
                return True
        except NoResultFound:
            pass
        return False

    def create_session(self, email: str) -> Union[str, None]:
        """Generates a session ID for a user."""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        if user:
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Finds a user by their session ID."""
        if not session_id:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Removes a user's session by setting their session ID to None."""
        if user_id:
            self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset token for password recovery."""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError("User not found")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password using a reset token."""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")

        hashed_password = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)

