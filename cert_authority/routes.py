from www import app, auth, models
from flask import Flask, request, make_response
import json
from requests.status_codes import codes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core_ca import generate_key_pair

# Issue Certificate
@app.route("/issue_cert", methods=["POST"])
@app.token_required
def issue_cert(u: models.Users):

    cert_pkcs12 = generate_key_pair(u.uid).hex()  #TODO hexify?
    return  make_response({'cert' : cert_pkcs12}, codes.created)

@app.route("/revoke_cert", methods=["POST"])
@auth.token_required
def revoke_cert():
    #TODO use OpenSSL to manage CRL
    return None






