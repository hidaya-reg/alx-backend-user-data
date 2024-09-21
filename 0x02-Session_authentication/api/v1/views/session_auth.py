from flask import Flask, request, jsonify
from models.user import User
from api.v1.app import auth
from os import getenv

app = Flask(__name__)

@app.route('/api/v1/auth_session/login', methods=['POST'], strict_slashes=False)
@app.route('/api/v1/auth_session/login/', methods=['POST'], strict_slashes=False)
def login():
    """Handles user login"""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    user = User.search(email=email)
    if not user:
        return jsonify({"error": "no user found for this email"}), 404
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    cookie_name = getenv("SESSION_NAME", "_my_session_id")
    response.set_cookie(cookie_name, session_id)
    
    return response
