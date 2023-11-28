import requests

server_err = requests.status_codes.codes.server_error
unauthorized = requests.status_codes.codes.unauthorized
ok = requests.status_codes.codes.ok
created = requests.status_codes.codes.created

verify = "/etc/ssl/CA/cacert.pem"
base_url = "https://auth_manager:443"
cert=("/etc/ssl/CA/newcerts/02.pem","/etc/ssl/CA/private/webserver.key")

ts_cred = {"uid": "ts", "password":"test"}
ps_cred = {"uid": "ps", "password":"KramBamBuli"}

ts_token = {}
admin_token = {}


def test_suite1():
    print("\n\n-------------- login with valid credentials --------------\n\n")
    r = requests.post(url=f"{base_url}/login", json=ts_cred, verify=verify, cert=cert)
    assert r.status_code == created 
    assert r.json().__contains__("token")
    global ts_token
    ts_token = r.json()["token"]

    r = requests.post(url=f"{base_url}/login", json=ps_cred, verify=verify, cert=cert)
    assert r.status_code == created 
    assert r.json().__contains__("token")
    global admin_token
    admin_token = r.json()["token"]

def test_suite2():
    print("\n\n-------------- cert login with no certificate --------------\n\n")
    r = requests.post(url=f"{base_url}/cert_login", verify=verify, cert=cert)
    assert r.status_code == server_err


def test_suite3():
    print("\n\n-------------- get new certificate  --------------\n\n")
    global admin_token 
    global ts_token

    print(admin_token)
    r = requests.post(url=f"{base_url}/issue_cert", headers={"x-access-token": admin_token}, verify=verify, cert=cert)
    assert r.status_code == ok
    global ps_cert
    ps_cert = r.content

    r = requests.post(url=f"{base_url}/issue_cert", headers={"x-access-token": ts_token}, verify=verify, cert=cert)
    assert r.status_code == ok
    global ts_cert
    ts_cert = r.content
    
"""
def test_suite4():
    global ts_cert, ps_cert
    print("\n\n-------------- cert login with valid certificate --------------\n\n")
    r = requests.post(url=f"{base_url}/cert_login", verify=verify, cert=cert, json={"cert": ts_cert})
    assert r.status_code == created
    assert r.json().__contains__("token")
    global ts_token 
    ts_token = r.json()["token"]

    r = requests.post(url=f"{base_url}/cert_login", verify=verify, cert=cert, json={"cert": ps_cert})
    assert r.status_code == created
    assert r.json().__contains__("token")
    global admin_token 
    admin_token = r.json()["token"]
"""

def test_suite5():
    print("\n\n-------------- access ca info from non admin user  --------------\n\n")
    r = requests.get(url=f"{base_url}/ca/admin_info", verify=verify, cert=cert, headers={"x-access-token": ts_token})
    assert r.status_code == unauthorized
    print(r.content)

def test_suite6():
    print("\n\n-------------- access ca info from admin user  --------------\n\n")
    r = requests.get(url=f"{base_url}/ca/admin_info", verify=verify, cert=cert, headers={"x-access-token": admin_token})
    assert r.status_code == ok
    print(r.content)



def test_suite7():
    print("\n\n-------------- revoke certificate --------------\n\n")
    
    r = requests.post(url=f"{base_url}/revoke", headers={"x-access-token": admin_token}, verify=verify, cert=cert)
    print(r.content)
    assert r.status_code == ok
    client_cert = r.content
    print(client_cert)
