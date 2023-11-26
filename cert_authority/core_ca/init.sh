#!/bin/bash
#Directory with CA certificate files
sudo mkdir /etc/ssl/CA
sudo mkdir /etc/ssl/CA/certs
sudo mkdir /etc/ssl/CA/newcerts
sudo mkdir /etc/ssl/CA/private
#file to keep track of serial number, initialized to 1  
sudo bash -c "echo ’01’ > /etc/ssl/CA/serial"
#file to record issued certificates 
sudo touch /etc/ssl/CA/index.txt
#TODO CA config file 

#Create self-signed root certificate 
sudo openssl req -new -x509 -extensions v3_ca -keyout cakey.pem -out cacert.pem -days 3650
#Having successfully created the key and the certificate, install them into the correct directory
sudo mv cakey.pem /etc/ssl/CA/private/
sudo mv cacert.pem /etc/ssl/CA/
sudo openssl ca -in key.csr -config /etc/ssl/openssl.cnf

#Create CRL
sudo mkdir /etc/ssl/CA/crl
sudo bash -c "echo ’01’ > /etc/ssl/CA/crlnumber"
