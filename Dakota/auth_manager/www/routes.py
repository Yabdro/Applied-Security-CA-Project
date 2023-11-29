from www import app, auth, models, ca
from flask import Flask, request, make_response, send_file
import json
from requests.status_codes import codes
import subprocess
import base64

CA_PATH = "/var/www/auth_manager/ssl/CA"
KEY_PATH = f"{CA_PATH}/private"

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


# Login for user already authenticated with certificate
@app.route("/cert_login", methods=["POST"])
def cert_login():

    try:
        data = request.json
        crt = data["cert"]
    except:
        return make_response("invalid request", codes.server_error)
    
    user = None
    valid = False
    try: 
        uid = ca.parse_certificate(crt.encode()) 
        user = models.get_user(uid)
        valid = ca.check_against_crl(crt.encode())
    except Exception as e:
        print(e)

    if not user or not valid:
        return make_response("unauthorized", codes.unauthorized)


    # Authenticate user and generate authorization token
    token = auth.create_token(user)
    
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


# Issue a new certificate for the user
@app.route("/issue_cert", methods=["POST"])
@auth.token_required
def issue_cert(u: models.Users):
    try:
        cert = ca.issue_new_certificate(u) 
        cert_path =  f"{KEY_PATH}/{u.uid}.key"
        if not cert:
            return make_response("could not create certificate", codes.unauthorized)
        return send_file(cert_path, mimetype='application/x-pkcs12')
    except Exception as e:
        print(e)
        return make_response("could not create certificate", codes.unauthorized)


# admin interface
@app.route("/ca/admin_info", methods=["GET"])
@auth.token_required
@auth.admin_required
def get_ca_info(user: models.Users):
    return make_response(ca.get_state(), 200)


# Revoke ALL certificates associated with user 
@app.route("/revoke", methods=["POST"])
@auth.token_required
def revoke_cert(u: models.Users):
    try:
        success = ca.revoke_user_certs(u)

        #return the CRL file
        if(success):
            resp = send_file(ca.CRL_PATH, as_attachment=True)
            resp.status_code = codes.created
            return resp
        else:
            return make_response("No certificates to revoke for current user", codes.ok)
    except:
        make_response("Something went wrong while revoking certificate", codes.unauthorized)
