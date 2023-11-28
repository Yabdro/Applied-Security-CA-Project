from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, load_pem_private_key, pkcs12, NoEncryption
from cryptography.hazmat.backends import default_backend
import OpenSSL
from OpenSSL import crypto
import subprocess
import os
import json
from www.models import Users
from datetime import datetime


PRE_ISSUED_CERTS = 2
COUNTRY = "CH"
PROVINCE = "Zurich"
LOCALITY = "Zurich"
ORG_UNIT = "Applied Sec Lab"
ORG_NAME = "ETHZ"

CONFIG = "/var/www/auth_manager/ssl/openssl.cnf"
WWW = "/var/www/auth_manager/www"
CA_PATH = "/var/www/auth_manager/ssl/CA"
CA_PUB_KEY = f"{CA_PATH}/cacert.pem"
KEY_PATH = f"{CA_PATH}/private"
NEW_CERTS = f"{CA_PATH}/newcerts"
CRL_PATH = f"{CA_PATH}/crl/crl.pem"

def gen_key():
    return ec.generate_private_key(curve=ec.SECP256R1(), backend=default_backend())

def store_pkcs12(key: ec.EllipticCurvePrivateKey, cert, uid, path):
    data = pkcs12.serialize_key_and_certificates(uid.encode(), key, cert, None, NoEncryption())
    with open(path, "wb") as f:
        f.write(data)
    return data

def store_csr(csr, uid: str):
    with open(f"{WWW}/{uid}.csr", "wb") as f:
        data = csr.public_bytes(encoding=serialization.Encoding.PEM)
        f.write(data)

def delete_csr(uid: str):
    try:
        os.remove(f"{WWW}/{uid}.csr")
    except:
        pass

def load_ca_certificate():
    with open(f"{CA_PATH}/cacert.pem", "rb") as f:
        cert = f.read()
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    return cert


def load_cert(path):
    try:
        with open(path, "rb") as f:
            cert = f.read()
            return x509.load_pem_x509_certificate(cert)
    except:
        print("Error while loading client certrificate")
    
def move_crt(uid, old_path, new_path):

    if not os.path.isdir(f"{NEW_CERTS}/{uid}"):
        os.mkdir(f"{NEW_CERTS}/{uid}")
    try:
        os.replace(old_path, new_path)
    except Exception as e:
        print(e)
        return 1
    return 0


def get_next_serial_id() -> str:
    with open(f"{CA_PATH}/serial") as f:
        return f.read().strip("\n")

def get_next_revoked_id():
    with open(f"{CA_PATH}/crlnumber") as f:
        return f.read().strip("\n")
    
def issue_new_certificate(user: Users) -> bytes:
    uid = user.uid
    serial_id = get_next_serial_id()

    priv = gen_key()

    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user.firstname),
            x509.NameAttribute(NameOID.SURNAME, user.lastname),
            x509.NameAttribute(NameOID.USER_ID, user.uid),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
            x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, PROVINCE),
            x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ORG_UNIT),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_NAME)
        ])).add_extension(
        x509.SubjectAlternativeName([
        x509.DNSName(uid)]), critical=False).sign(priv, hashes.SHA256(), default_backend())

    store_csr(csr, uid)

    ret_code = subprocess.call(f"openssl ca -in {WWW}/{uid}.csr -batch -config {CONFIG}".split(" "))
    
    if ret_code:
        delete_csr(uid)
        return None

    old_path =  f"{NEW_CERTS}/{serial_id}.pem"
    new_path =  f"{NEW_CERTS}/{uid}/{serial_id}.pem"

    move_crt(uid, old_path, new_path)

    new_cert = load_cert(f"{NEW_CERTS}/{uid}/{serial_id}.pem")
   
    delete_csr(uid)
    
    pkcs12 = store_pkcs12(priv, new_cert, uid, f"{KEY_PATH}/{uid}.key")
    return pkcs12



    #TODO: get #revoked certs

def parse_certificate(client_cert: bytes):
    try:
                
        client_cert = client_cert.removeprefix(b"-----BEGIN CERTIFICATE-----").removesuffix(b"-----END CERTIFICATE----- ").replace(b" ", b"\r\n")
        client_cert = b"-----BEGIN CERTIFICATE-----"+client_cert+b"-----END CERTIFICATE-----\r\n"

        client_cert = x509.load_pem_x509_certificate(client_cert)
        
        uid = client_cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value
        
    
        return uid

    except Exception as e:
        print(e)
        return None


def check_against_crl(client_cert: bytes):
    client_cert = client_cert.removeprefix(b"-----BEGIN CERTIFICATE-----").removesuffix(b"-----END CERTIFICATE----- ").replace(b" ", b"\r\n")
    client_cert = b"-----BEGIN CERTIFICATE-----"+client_cert+b"-----END CERTIFICATE-----\r\n"
    client_cert = x509.load_pem_x509_certificate(client_cert)

    cert_path = "/var/www/auth_manager/tocheck.pem"
    with open(cert_path, 'wb') as f:
        f.write(client_cert.public_bytes(encoding=serialization.Encoding.PEM))

    ret = subprocess.call(f"/var/www/auth_manager/www/./check_against_crl.sh".split(" "))
    # ret = subprocess.call(f"openssl verify -CAfile revoked.pem -crl_check {cert_path}".split(" "))
    # os.remove(cert_path)
    # os.remove("/var/www/auth_manager/revoked.pem")
    if ret == 0:
        return True
    return False


def revoke_user_certs(user: Users):
    uid = user.uid

    #Get the certificate paths of this user 
    certs_directory = f"{CA_PATH}/newcerts/{uid}"
    cert_filenames = os.listdir(certs_directory)

    #Get paths 
    cert_paths = [os.path.join(certs_directory, cert_fn) for cert_fn in cert_filenames]
    cert_paths = list(filter(os.path.isfile, cert_paths))
    
    
    if len(cert_paths) == 0:
        return False


    for cert_path in cert_paths:
        subprocess.call(f"openssl ca -revoke {cert_path} -config {CONFIG}".split(" "))
        os.remove(cert_path)
    
    subprocess.call(f"openssl ca -gencrl -out {CRL_PATH} -config {CONFIG}".split(" "))

    return True


def get_state():
    
    serial = get_next_serial_id()
    
    issued = int(serial, base=16)-(PRE_ISSUED_CERTS+1)
    
    revoked = get_next_revoked_id()
    revoked = int(revoked, base=16) - 1

    return json.dumps({
        "serial": serial,
        "issued": issued,
        "revoked": revoked
    })

