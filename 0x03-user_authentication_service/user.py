#!/usr/bin/env python3
"""Module defining the User model for database interactions."""
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

# Base class for all models
Base = declarative_base()

class User(Base):
    """Defines the `User` table schema in the database."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)  # Primary key column
    email = Column(String(250), nullable=False)  # User email (required)
    hashed_password = Column(String(250), nullable=False)  # Password hash (required)
    session_id = Column(String(250), nullable=True)  # Optional session ID
    reset_token = Column(String(250), nullable=True)  # Optional reset token
