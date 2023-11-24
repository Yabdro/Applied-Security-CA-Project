from www import app, auth, models, ca
from flask import Flask, request, make_response
import json
from requests.status_codes import codes
import subprocess

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


# Apply changes to a user data
@app.route("/issue_cert", methods=["POST"])
@auth.token_required
def issue_cert(u: models.Users):
    
    uid = u.uid
    try:
        cert = ca.issue_new_certificate(uid)
        print(ca.verify_certificate(cert))
    except Exception as e:
        print(e)
        return make_response("could not create certificate", codes.server_error)
    
    return make_response(cert, codes.created)


"""
@app.route("/cert_login", methods=["POST"])
def issue_cert():
    
    cert = request.json["cert"]
    uid = ca.verify_certificate(cert)
    if not uid:
        return make_response("invalid certificate", codes.server_error)
    
    return make_response("success", codes.created)
"""


# Revoke certificates associated with user 

# Ca login

# Check certificate login