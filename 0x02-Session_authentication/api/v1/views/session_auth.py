#!/usr/bin/env python3
""" View for Session Authentication
"""
from flask import Flask, request, jsonify, abort
from api.v1.views import app_views
from models.user import User
from os import getenv
from api.v1.app import auth

app = Flask(__name__)


@app_views.route(
        '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout():
    """Deletes the user session by logging them out."""
    if not auth.destroy_session(request):
        abort(404)

    return jsonify({}), 200


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """Handles user login"""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    users = User.search({"email": email})
    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth

    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    cookie_name = getenv("SESSION_NAME", "_my_session_id")
    response.set_cookie(cookie_name, session_id)
    return response
