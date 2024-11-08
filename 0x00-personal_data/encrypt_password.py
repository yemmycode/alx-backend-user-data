#!/usr/bin/env python3
"""Module for password encryption and validation.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Generates a hash for the given password using a random salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Verifies whether a given password matches its hashed version.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

