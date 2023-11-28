#!/bin/bash
cat /var/www/auth_manager/ssl/CA/cacert.pem /var/www/auth_manager/ssl/CA/crl/crl.pem > /var/www/auth_manager/revoked.pem
openssl verify /var/www/auth_manager/revoked.pem -crl_check /var/www/auth_manager/tocheck.pem