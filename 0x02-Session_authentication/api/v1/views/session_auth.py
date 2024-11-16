#!/usr/bin/env python3
"""
Module for session authentication views.
"""
import os
from typing import Tuple
from flask import abort, jsonify, request

from models.user import User
from api.v1.views import app_views


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    """
    Handles user login via session authentication.

    POST /api/v1/auth_session/login
    Returns:
        Tuple[str, int]: JSON response containing the user object and status code.
    """
    # Define the error response for a user not found.
    not_found_res = {"error": "no user found for this email"}

    # Retrieve and validate the 'email' parameter from the request.
    email = request.form.get('email')
    if not email or email.strip() == "":
        return jsonify({"error": "email missing"}), 400

    # Retrieve and validate the 'password' parameter from the request.
    password = request.form.get('password')
    if not password or password.strip() == "":
        return jsonify({"error": "password missing"}), 400

    # Attempt to find the user in the database using the provided email.
    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify(not_found_res), 404

    # Check if any user was found with the given email.
    if not users:
        return jsonify(not_found_res), 404

    # Verify the provided password for the found user.
    if users[0].is_valid_password(password):
        # Create a session for the user and set it in the response cookie.
        from api.v1.app import auth
        session_id = auth.create_session(getattr(users[0], 'id'))
        response = jsonify(users[0].to_json())
        response.set_cookie(os.getenv("SESSION_NAME"), session_id)
        return response

    # Return an error response if the password is invalid.
    return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout() -> Tuple[str, int]:
    """
    Handles user logout by ending their session.

    DELETE /api/v1/auth_session/logout
    Returns:
        Tuple[str, int]: JSON response indicating success or an error status.
    """
    from api.v1.app import auth

    # Attempt to destroy the user's session.
    if not auth.destroy_session(request):
        abort(404)

    # Return an empty JSON response on successful logout.
    return jsonify({})

