from www import app, auth, models
from flask import Flask, request, make_response
import json
from requests.status_codes import codes


from core_ca import generate_key_pair

# Issue Certificate
@app.route("/issue_cert", methods=["POST"])
@auth.token_required 
def issue_cert(u: models.Users):

    uid = u.uid 
    gen_csr_path = '/core_ca/gen_csr.sh'
    csr = subprocess.run(['bash', gen_csr_path, uid], capture_output=True, text=True)

    sign_cert_path = '/core_ca/sign_cert.sh'
    cert_pkcs12 = subprocess.run(['bash', sign_cert_path, uid], capture_output=True, text=True)

    return  make_response({'cert' : cert_pkcs12}, codes.created)

@app.route("/revoke_cert", methods=["POST"])
@auth.token_required
def revoke_cert(u: models.Users):

    uid = u.uid 
    revoke_cert_path = '/core_ca/revoke_cert.sh'
    exit_stat = subprocess.run(['bash', uid], capture_output=True, text=True)
    return None


#TODO verify cert
#TODO request CRL 


