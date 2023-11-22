from www import app, auth, models
from flask import Flask, request, make_response
import json
from requests.status_codes import codes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Issue Certificate
# TODO check token
# TODO figure out what to do after getting token
# TODO what is token and what do I do with token? --> TOKEN is jwt token and contains uid 
# TODO how does it check token?
@app.route("/issue_cert", methods=["POST"])
@auth.token_required
def issue_cert():

    #TODO do I need this part? 
    
    # Get credentials
    try:
        data = request.json
        token = data["token"]
    except:
        return make_response("unauthorized", codes.unauthorized)

    #TODO call to public private key generation 

    #TODO build and return cert 

@app.route("/revoke_cert", methods=["POST"])
@auth.token_required
def revoke_cert():
    #TODO use OpenSSL to manage CRL
    return None






