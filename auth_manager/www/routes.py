from www import app, auth, models
from flask import Flask, request, make_response
import json
from requests.status_codes import codes

# Login user
@app.route("/login", methods=["POST"])
def login():

    # Get credentials
    try:
        data = request.json
        uid = data["uid"]
        password = data["password"]
    except:
        return make_response("unauthorized", codes.unauthorized)
    
    # Authenticate user and generate authorization token
    token = auth.auth_user(uid, password)
    
    # Check authorization token was created (i.e., user has successfully authenticated)
    if not token:
        return make_response("unauthorized", codes.unauthorized)

    return  make_response({'token' : token}, codes.created)


# Get user information in database
@app.route("/users", methods=["GET"])
@auth.token_required
def get_info(u: models.Users):
    return make_response(u.json(), codes.all_ok)

# Apply changes to a user data
@app.route("/users", methods=["POST"])
@auth.token_required
def change_info(u: models.Users):
    
    # Get the required updates
    try:
        updates = request.json
    except:
        return make_response("malformed request", codes.server_error)
    
    # Update user
    u = models.update_user(u, updates)

    # Note: an empty update generates a success reply
    return make_response("success", codes.created)