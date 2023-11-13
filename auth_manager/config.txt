1. Activate shared clipboard in VM settings

2. Create shared directory: https://www.virtualbox.org/manual/ch04.html#sharedfolders

3. Install mysql, apache2 and pip with apt

4. Re-hash password in database using argon2 (memory hard) https://argon2-cffi.readthedocs.io/en/stable/api.html

5. HTTPS webserver:
	- configuration file in /etc/apache2/sites-available/auth_manager.conf: TLS1.3 with client authentication
	- all scripts are in /var/www/auth_manager folder
	- test APIs with "pytest -s test.py" inside folder /var/www/auth_manager/www
	- install requirements.txt in auth_manager folder (pip install -r requirements.txt)
	APIs:

	- auth_manager/login: 
		method: POST  
		json: {"uid":uid, "password": password}
		response: 
			* 201: authorization jwt in body
			* 401: unauthorized
 	
	- auth_manager/users/sha256(uid):
		method: GET
		header x-access-token: authorization jwt	
		response: 
			* 200: user info in body
			* 401: unauthorized
	
	- auth_manager/users/sha256(uid):
		method: POST
		header x-access-token: authorization jwt	
		json: updates (e.g., {"pwd": "new password"})
		response: 
			* 201: successfully updated
			* 400: bad request
			* 401: unauthorized

6. Setup CA for issuing client certificates to be used for client authentication as in Chapter 7 of applied sec book
	- CA certificate (to be used for verification of auth_manager cert): /etc/ssl/cacert.pem 
	- Keys in /etc/ssl/CA/privates: 
		* CA key: cakey.pem 
		* auth_manager: auth_manager.key 
		* webserver: webserver.key
	- New certificates in /etc/ssl/CA/newcerts
		* auth_manager: 01.pem 
		* webserver: 02.pem


