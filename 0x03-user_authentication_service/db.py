#!/usr/bin/env python3
"""Database module for managing user records."""
from sqlalchemy import create_engine, tuple_
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session

from user import Base, User


class DB:
    """Database class to manage interactions with the user table."""

    def __init__(self) -> None:
        """Sets up the database engine and initializes tables."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)  # Clear existing tables
        Base.metadata.create_all(self._engine)  # Create fresh tables
        self.__session = None

    @property
    def _session(self) -> Session:
        """Provides a cached session object for database operations."""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Inserts a new user into the database."""
        try:
            new_user = User(email=email, hashed_password=hashed_password)
            self._session.add(new_user)
            self._session.commit()
            return new_user
        except Exception:
            self._session.rollback()
            return None

    def find_user_by(self, **kwargs) -> User:
        """Searches for a user using specified filters."""
        fields, values = [], []
        for key, value in kwargs.items():
            if hasattr(User, key):
                fields.append(getattr(User, key))  # Attribute matching
                values.append(value)
            else:
                raise InvalidRequestError(f"Invalid field: {key}")
        
        result = self._session.query(User).filter(
            tuple_(*fields).in_([tuple(values)])
        ).first()
        
        if result is None:
            raise NoResultFound()
        return result

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates user attributes based on the provided filters."""
        user = self.find_user_by(id=user_id)
        if not user:
            return
        
        updates = {}
        for key, value in kwargs.items():
            if hasattr(User, key):
                updates[getattr(User, key)] = value  # Map attributes to new values
            else:
                raise ValueError(f"Invalid attribute: {key}")
        
        self._session.query(User).filter(User.id == user_id).update(
            updates,
            synchronize_session=False
        )
        self._session.commit()

