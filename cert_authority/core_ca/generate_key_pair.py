from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta


#TODO Double check choice of algorithms and parameters for key pair generation  

def generate_key_pair(user_id):

    # Generate a private key
    user_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get the public key
    user_public_key = user_private_key.public_key()

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    #TODO store key pair in database  

    #TODO not needed 
    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #TODO get CA private key
    ca_private_key = None
    ca_public_key = ca_private_key.public_key() 

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])

    user_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365) #TODO valid for one year?
    ).sign(private_key, algorithm=hashes.SHA256(), backend=default_backend())

    # Create a PKCS#12 archive
    pkcs12_data = serialization.pkcs12.serialize_key_and_certificates(
        name=('user_' + user_id + 'cert_bundle').encode('utf-8'), #TODO name?
        key=user_private_key,
        cert=user_cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')) #TODO need encryption?
    )

    return pkcs12_data

