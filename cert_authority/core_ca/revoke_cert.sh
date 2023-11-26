#!/bin/bash
sudo openssl ca -revoke ${uid}.crt -config /etc/ssl/openssl.cnf
#Update and recreate CRL
sudo openssl ca -gencrl -out /path/to/crl.pem -config /path/to/openssl.cnf
