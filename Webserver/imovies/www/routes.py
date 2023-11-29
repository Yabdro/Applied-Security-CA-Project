from www import app
from flask import Flask, request, make_response, render_template, send_file
import os
from requests.status_codes import codes
import requests
import urllib3
import traceback


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

# Authentication using client certificate
@app.route("/cert-authenticated/successful_login", methods=["GET"])
def cert_login():
    try:
        client_cert = request.headers.get("X-SSL-CLIENT-CERT")
        if client_cert == None:
            return make_response("unauthorized: no certificate provided", codes.unauthorized)

        data = {"cert":client_cert}
    
        # Send certificate to auth manager
        response = requests.post(url=f"{base_url}/cert_login", 
                                json=data, verify=verify, cert=cert)
        if not response.status_code == created:
            return make_response("unauthorized: invalid certificate", codes.unauthorized)
        
        # Certificate checks out, retrieve user data
        token = response.json()['token']
        headers = {'x-access-token':token}
        response = requests.get(url=f"{base_url}/users", 
                                verify=verify, cert=cert, headers=headers)
        if not response.status_code == ok:
            return make_response("unauthorized: couldn't retrieve user data", codes.unauthorized)
        
        # Send user info back to user for corrections
        user_json = response.json()
        context = {"user": user_json}
        resp = make_response(render_template('cert-authenticated/successful_login.html', **context))
        resp.set_cookie(key='x-access-token', value=token)

        return resp
    except:
        return make_response(f"unauthorized: {traceback.format_exc()}", codes.unauthorized)



# Login user
@app.route("/login", methods=["POST"])
def login():
    try:
        uid = request.form.get("uid")
        password = request.form.get("password")
        data = {"uid":uid, "password": password}
        # Send credentials to auth manager
        response = requests.post(url=f"{base_url}/login", 
                                json=data, verify=verify, cert=cert)

        if not response.status_code == created:
            return make_response("unauthorized: wrong credentials", codes.unauthorized)

        # Credentials check out, retrieve user data
        token = response.json()['token']
        headers = {'x-access-token':token}
        response = requests.get(url=f"{base_url}/users", 
                                verify=verify, cert=cert, headers=headers)
        if not response.status_code == ok:
            return make_response("unauthorized: couldn't retrieve user data", codes.unauthorized)
      
        # Send user info back to user for corrections
        user_json = response.json()
        context = {"user": user_json}
        resp = make_response(render_template('cred-authenticated/successful_login.html', **context))
        resp.set_cookie(key='x-access-token', value=token)

        return resp

    except Exception as e:
        return make_response(f"unauthorized: {traceback.format_exc()}", codes.unauthorized)

@app.route("/cert-authenticated/ca_admin", methods=["GET"])
def ca_admin():
    try:
        token = request.cookies["x-access-token"]
        headers = {'x-access-token':token}
        resp = requests.get(url=f"{base_url}/ca/admin_info",
                                verify=verify, cert=cert, headers=headers)
        if resp.status_code != ok:
            return make_response("unauthorized: couldn't retrieve CA data", codes.unauthorized)

        ca_info = resp.json()
        context= {"ca": ca_info}

        return render_template('cert-authenticated/ca_admin_interface.html', **context)
    except:
        return make_response(f"unauthorized: {traceback.format_exc()}", codes.unauthorized)



# Apply changes to a user data
@app.route("/update_cred", methods=["POST"])
def update_cred():
    try: 
        #retrieve auth token
        token = request.cookies["x-access-token"]
        headers = {'x-access-token':token}

        # Collect updates in a dictionary
        psw = request.form.get("psw")
        email = request.form.get("email")
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        data = {}
        if not (psw == ''):
            data["psw"] = psw
        if not (email == ''):
            data["email"] = email
        if not (firstname == ''):
            data["firstname"] = firstname
        if not (lastname == ''):
            data["lastname"] = lastname

        # Send data (together with token) to auth manager
        response = requests.post(url=f"{base_url}/users", json=data,
                                verify=verify, cert=cert, headers=headers)

        if response.status_code == created:
            response = requests.get(url=f"{base_url}/users", 
                                verify=verify, cert=cert, headers=headers)
            if not response.status_code == ok:
                return make_response("unauthorized: couldn't retrieve user data", codes.unauthorized)
      
            # Send user info back to user for corrections
            user_json = response.json()
            context = {"user": user_json}
            return make_response(render_template('cred-authenticated/successful_login.html', **context))

        return make_response("unauthorized", codes.unauthorized)
    except Exception as e:
        return make_response(f"unauthorized: {traceback.format_exc()}", codes.unauthorized)



# Apply changes to a user data
@app.route("/issue_cert", methods=["GET"])
def issue_cert():
    try: 
        #retrieve auth token
        token = request.cookies["x-access-token"]
        headers = {'x-access-token':token}
        resp = requests.get(url=f"{base_url}/users", 
                                verify=verify, cert=cert, headers=headers)
        if not (resp.status_code == ok):
            return make_response("unauthorized: couldn't retrieve user data", codes.unauthorized)

        uid = resp.json()["uid"]
        filepath = f"/var/www/imovies/downloads/{uid}/cert.pfx"

        resp = requests.post(url=f"{base_url}/issue_cert", 
                                verify=verify, cert=cert, headers=headers)
        
        if not resp.status_code == ok:
            return make_response("unauthorized: couldn't issue a new certificate", codes.unauthorized)

        os.makedirs(f"/var/www/imovies/downloads/{uid}", exist_ok=True);
        with open(filepath, "wb") as f:
            f.write(resp.content)

        return render_template('issue_cert.html')
    
    except Exception as e:
        return make_response(f"unauthorized: {traceback.format_exc()}", codes.unauthorized)


# Apply changes to a user data
@app.route("/revoke_cert", methods=["GET"])
def revoke_cert():
    try: 
        #retrieve auth token
        token = request.cookies["x-access-token"]
        headers = {'x-access-token':token}
    
        resp = requests.post(url=f"{base_url}/revoke", headers=headers,
                             verify=verify, cert=cert)

        if (resp.status_code == ok):
            return make_response("No certificates associated with current user were found", codes.ok)
        if (resp.status_code != created):
            return make_response("Something went wrong while revoking certificate", codes.unauthorized)
        
        filepath = "/var/www/imovies/ssl.crl/crl.pem"
        with open(filepath, "wb") as f:
            f.write(resp.content)

        return make_response("All certificates associated with current user were revoked and the CRL updated.", codes.created)


    except Exception as e:
        return make_response(f"unauthorized: {traceback.format_exc()}", codes.unauthorized)


@app.route('/download_cert')
def download_cert():
    try:
        token = request.cookies["x-access-token"]
        headers = {'x-access-token':token}
        resp = requests.get(url=f"{base_url}/users", 
                                verify=verify, cert=cert, headers=headers)
        if not (resp.status_code == ok):
            return make_response("unauthorized: couldn't retrieve user data", codes.unauthorized)

        uid = resp.json()["uid"]
        filepath = f"/var/www/imovies/downloads/{uid}/cert.pfx"

        resp = send_file(filepath, as_attachment=True)
        resp.headers['Content-Type'] = 'application/x-pkcs12'
        os.remove(filepath)
        return resp
    except Exception as e:
        return make_response(f"unauthorized: {traceback.format_exc()}", codes.unauthorized)
