import requests

server_err = requests.status_codes.codes.server_error
unauthorized = requests.status_codes.codes.unauthorized
ok = requests.status_codes.codes.ok
created = requests.status_codes.codes.created

verify = "/etc/ssl/CA/cacert.pem"
base_url = "https://auth_manager:443"
cert=("/etc/ssl/CA/newcerts/02.pem","/etc/ssl/CA/private/webserver.key")

ts_token = {}
admin_token = {}

def test_suite1():
    print("\n\n-------------- cert login with no uid --------------\n\n")
    r = requests.post(url=f"{base_url}/cert_login", verify=verify, cert=cert)
    assert r.status_code == unauthorized


def test_suite2():
    print("\n\n-------------- cert login with invalid uid --------------\n\n")
    r = requests.post(url=f"{base_url}/cert_login", verify=verify, cert=cert, json={"uid": "invalid"})
    assert r.status_code == unauthorized

def test_suite3():
    print("\n\n-------------- cert login with valid uid --------------\n\n")
    r = requests.post(url=f"{base_url}/cert_login", verify=verify, cert=cert, json={"uid":"ts"})
    assert r.status_code == created
    assert r.json().__contains__("token")
    global ts_token 
    ts_token = r.json()["token"]

    r = requests.post(url=f"{base_url}/cert_login", verify=verify, cert=cert, json={"uid":"ps"})
    assert r.status_code == created
    assert r.json().__contains__("token")
    global admin_token 
    admin_token = r.json()["token"]

def test_suite4():
    print("\n\n-------------- get new certificate and verify --------------\n\n")
    
    r = requests.post(url=f"{base_url}/issue_cert", headers={"x-access-token": token}, verify=verify, cert=cert)
    print(r.content)
    assert r.status_code == ok
    client_cert = r.content
    print(client_cert)



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