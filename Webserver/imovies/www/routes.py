from www import app
from flask import Flask, request, make_response, render_template
import json
from requests.status_codes import codes
from multiprocessing import Process, Queue
import requests
from hashlib import sha256
import urllib3

server_err = requests.status_codes.codes.server_error
unauthorized = requests.status_codes.codes.unauthorized
ok = requests.status_codes.codes.ok
created = requests.status_codes.codes.created

verify = "/etc/ssl/CA/cacert.pem"
base_url = "https://auth_manager:443"
cert=("/etc/ssl/CA/newcerts/02.pem","/etc/ssl/CA/private/webserver.key")

# Welcome page
@app.route("/", methods=["GET"])
def welcome():
    return render_template('welcome.html')


# Login form
@app.route("/cred_login", methods=["GET"])
def cred_login():
    return render_template('cred_login.html')

# Login user
@app.route("/login", methods=["POST"])
def login():
    uid = None
    try:
        uid = request.json["uid"]
        # Send credentials to auth manager
        response = requests.post(url=f"{base_url}/login", 
                                 json=request.json, verify=verify, cert=cert)
    except:
        return make_response("unauthorized: wrong credentials", codes.unauthorized)
    # If authenticated
    if response.status_code == created:
        hashed_uid = sha256(uid.encode()).hexdigest()
        try:
            # Retrieve user info
            response = requests.get(url=f"{base_url}/users/{hashed_uid}", 
                                    verify=verify, cert=cert)
        except:
            return make_response("unauthorized", codes.unauthorized)
        user = response.json()
        context = {"user": user}
        # Send user info back to user for corrections, if necessary
        return render_template('cred-authenticated/succesful_login.html', **context)
    return make_response("unauthorized", codes.unauthorized)



# Apply changes to a user data
@app.route("/update_cred", methods=["POST"])
def update_cred():
    #TODO: could we add a backdoor here by taking the hashed uid from the url and not
    # validating it?
    hashed_uid = ''
    # send updates to auth manager
    try:
        response = requests.post(url=f"{base_url}/users/{hashed_uid}", 
                                json=request.json, verify=verify, cert=cert)
    except:
        return make_response("malformed request", codes.server_error)
    if response.status_code == created:
        return render_template('cred-authenticated/issue_or_revoke.html')

