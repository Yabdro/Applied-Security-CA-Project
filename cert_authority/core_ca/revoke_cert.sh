#!/bin/bash
sudo openssl ca -revoke ${uid}.crt -config /etc/ssl/openssl.cnf