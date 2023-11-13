"""
Integration tests that verify different aspects of the protocol.
You can *add* new tests here, but it is best to  add them to a new test file.

ALL EXISTING TESTS IN THIS SUITE SHOULD PASS WITHOUT ANY MODIFICATION TO THEM.
"""

from multiprocessing import Process, Queue
import requests
from hashlib import sha256
import urllib3

server_err = requests.status_codes.codes.server_error
unauthorized = requests.status_codes.codes.unauthorized
ok = requests.status_codes.codes.ok
created = requests.status_codes.codes.created

uid = "ts"
hashed_uid = sha256(uid.encode()).hexdigest()

verify = "/etc/ssl/CA/cacert.pem"
base_url = "https://auth_manager:443"
cert=("/etc/ssl/CA/newcerts/02.pem","/etc/ssl/CA/private/webserver.key")
cred = {"uid": "ts", "password":"test"}
token = {}

def test_suite1():
    print("\n\n-------------- login without credentials --------------\n\n")

    r = requests.post(url=base_url+"/login", verify=verify, cert=cert)

    assert r.status_code == unauthorized

def test_suite2():
    print("\n\n-------------- login with empty credentials --------------\n\n")
    r = requests.post(url=f"{base_url}/login", json={}, verify=verify, cert=cert)
    assert r.status_code == unauthorized

def test_suite3():
    print("\n\n-------------- login with invalid credentials --------------\n\n")
    r = requests.post(url=f"{base_url}/login", json={"uid": "ts", "password": "tst"}, verify=verify, cert=cert)
    assert r.status_code == unauthorized

def test_suite4():
    print("\n\n-------------- login with valid credentials --------------\n\n")
    r = requests.post(url=f"{base_url}/login", json=cred, verify=verify, cert=cert)
    assert r.status_code == created 
    assert r.json().__contains__("token")
    global token
    token = r.json()["token"]

def test_suite5():
    print("\n\n-------------- query invalid user url --------------\n\n")
    r = requests.get(url=f"{base_url}/users/{hashed_uid}a", headers={"x-access-token": token}, verify=verify, cert=cert)
    assert r.status_code == unauthorized

def test_suite6():
    print("\n\n-------------- get user info with valid access token --------------\n\n")
    r = requests.get(url=f"{base_url}/users/{hashed_uid}", headers={"x-access-token": token}, verify=verify, cert=cert)
    assert r.status_code == ok

def test_suite7():
    print("\n\n-------------- update user info without access token --------------\n\n")
    r = requests.post(url=f"{base_url}/users/{hashed_uid}", verify=verify, cert=cert)
    assert r.status_code == unauthorized

def test_suite8():
    print("\n\n-------------- update user info without updates --------------\n\n")
    r = requests.post(url=f"{base_url}/users/{hashed_uid}", headers={"x-access-token": token}, verify=verify, cert=cert)
    assert r.status_code == server_err

def test_suite9():
    print("\n\n-------------- update user info with empty updates --------------\n\n")
    r = requests.post(url=f"{base_url}/users/{hashed_uid}", json={}, headers={"x-access-token": token}, verify=verify, cert=cert)
    assert r.status_code == created

def test_suite10():
    print("\n\n-------------- update all user info --------------\n\n")
    update = {"firstname": "tst", "lastname": "tst", "email": "tst@imovies.ch", "pwd": "tst"}
    r = requests.post(url=f"{base_url}/users/{hashed_uid}", json=update, headers={"x-access-token": token}, verify=verify, cert=cert)
    assert r.status_code == created
    print("\n\n-------------- check we can't login with previous credentials --------------\n\n")
    r = requests.post(url=f"{base_url}/login", json=cred, verify=verify, cert=cert)
    assert r.status_code == unauthorized

def test_suite11():
    print("\n\n-------------- reset all user info --------------\n\n")
    update = {"uid":"ts", "firstname": "test", "lastname": "test", "email": "test", "pwd": "test"}
    r = requests.post(url=f"{base_url}/users/{hashed_uid}", json=update, headers={"x-access-token": token}, verify=verify, cert=cert)
    assert r.status_code == created

