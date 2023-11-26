from www.db_func import select, update
from www import db
from argon2 import PasswordHasher
from json import dumps


class PwdHash:
    
    def argon2_hash(password: str) -> str:
       return PasswordHasher().hash(password)

    def argon2_verify(hash: str, password: str) -> bool:
        return PasswordHasher().verify(hash, password)


class PrintableMixin:
    def __repr__(self) -> str:
        s = "{} object: ".format(type(self).__name__)
        s += " ".join([attr + "=" + str(getattr(self, attr))
                      for attr in self.print_fields])
        return s


class Users(db.Model):
    uid = db.Column(db.String(64), primary_key=True)
    pwd = db.Column(db.String(97))
    lastname = db.Column(db.String(64))
    firstname = db.Column(db.String(64))
    email = db.Column(db.String(64))
    admin = db.Column(db.Boolean)

    print_fields = ["uid", "pwd"]

    def __init__(self, user_id: str, hash: str) -> None:
        self.uid = user_id
        self.pwd = hash

    def check_password(self, password: str) -> bool:
        try:
            PwdHash.argon2_verify(hash=str(self.pwd), password=password)
        except Exception:
            return False
        return True

    def json(self):
        return dumps({"uid": self.uid, "firstname": self.firstname, "lastname": self.lastname, "email": self.email})


def get_user(uid: str) -> Users:
    return select(Users, uid=uid)

def update_user(u: Users, updates: dict) -> Users:

    # Need to hash the password before updating
    if updates.__contains__("pwd"): 
        updates["pwd"] = PwdHash.argon2_hash(updates["pwd"])
    
    # Cannot change uid
    if updates.__contains__("uid"):
        updates.pop("uid")

    try:
        u = update(u, **updates)
    except Exception as e:
        print(e)
        return None
    
    return u
    
