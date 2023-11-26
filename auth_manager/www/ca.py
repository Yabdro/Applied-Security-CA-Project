from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, load_pem_private_key, pkcs12, NoEncryption
from cryptography.hazmat.backends import default_backend
import OpenSSL
import subprocess
import os
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
KEY_PATH = f"{CA_PATH}/private"

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
    

def get_next_serial_id() -> str:
    with open(f"{CA_PATH}/serial") as f:
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

    return_code = subprocess.call(f"openssl ca -in {WWW}/{uid}.csr -batch -config {CONFIG}".split(" "))

    if not return_code:
        delete_csr(uid)
        return None

    new_cert = load_cert(f"{CA_PATH}/newcerts/{serial_id}.pem")

    delete_csr(uid)
    
    pkcs12 = store_pkcs12(priv, new_cert, uid, f"{KEY_PATH}/{uid}.key")

    return pkcs12



def verify_certificate(client_cert: bytes):

    try:
        
        root_cert = load_ca_certificate()
        _, client_cert, _ = pkcs12.load_key_and_certificates(client_cert, None, None)
        
        # Check certificate was generated for actual client
        #uid = client_cert.subject
        
        store = OpenSSL.crypto.X509Store()  
        store.add_cert(root_cert)  

        ctx = OpenSSL.crypto.X509StoreContext(store, client_cert)
        ctx.verify_certificate()  
        
        return True
    
    except Exception as e:
        print(e)
        return None

def revoke_cert(client_cert: bytes):
    try: 
        #First check that certificate is valid before revoking it 
        verify_certificate(client_cert)

        ca_root_PATH =  "/var/www/auth_manager/ssl/CA"
        ca_cert_PATH = ca_root_PATH + "/cacert.pem"
        ca_key_PATH  = ca_root_PATH + "/cakey.pem"

        ca_cert = crypto.load_certificate(FILETYPE_PEM, open(ca_cert_PATH, "rb").read())  
        ca_key = crypto.load_privatekey(FILETYPE_PEM, open(ca_key_PATH, "rb").read())  

        cert = crypto.load_certificate(FILETYPE_PEM, client_cert)

        #Get current date andd format the date as "YYYYMMDDHHMMSSZ"
        current_date = datetime.utcnow()
        formatted_date = current_date.strftime("%Y%m%d%H%M%SZ").encode()

        crl = None 

        crl_file_PATH = ca_root_PATH + "/crl.pem" 


        #TODO security risk of open? 

        #Load or create CRL 
        try:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, open(crl_file_PATH, "rb").read())
        except crypto.Error:
            crl = crypto.CRL()
        
        # Create a revoked certificate entry
        revoked = crypto.Revoked()

        #Set date of revocation 
        revoked.set_rev_date(formatted_date) 

        #Set serial number of revocation  
        revoked.set_serial(hex(cert.get_serial_number())[2:]) #TODO  double check 

        #Add revocation entry to CRL object 
        crl.add_revoked(revoked)

        crl.set_version(1)
        crl.set_lastUpdate(formatted_date)  
        crl.set_nextUpdate(formatted_date) 
        crl.set_issuer(ca_cert.get_subject())

        #Sign the updated CRL object 
        crl.sign(ca_key, "sha256")

        #Write CRL object to file 
        with open(crl_file_PATH, "wb") as crl_file:  
            crl_file.write(crypto.dump_crl(FILETYPE_PEM, crl))

    except Exception as e:
        print(e)
        return None

   
def get_state():
    #TODO: get #revoked certs
    revoked = 0
    serial = get_next_serial_id()
    issued = int(serial)-(PRE_ISSUED_CERTS+1)

    return {
        "serial": serial,
        "issued": issued,
        "revoked": revoked
    }



#Keys in /etc/ssl/CA/privates: 
#CA key: cakey.pem 
#auth_manager: auth_manager.key 
#webserver: webserver.key
#New certificates in /etc/ssl/CA/newcerts
#auth_manager: 01.pem 
#webserver: 02.pem