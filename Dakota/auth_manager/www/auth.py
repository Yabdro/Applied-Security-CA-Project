from flask import make_response, request, jsonify
from requests.status_codes import codes
from functools import wraps
from www import app
from www import models
import jwt
from datetime import datetime, timedelta

JWT_VALIDITY = 20 
JWT_ALGORITHM = "HS512"

def auth_user(uid:str, password: str) -> jwt:
    user = models.get_user(uid)

    if not user.check_password(password):
        return None

    return create_token(user)


def create_token(user: models.Users):

    payload = {
        "uid": user.uid,
        "exp": datetime.utcnow() + timedelta(minutes=15)
    }

    jwt_token = jwt.encode(
        payload=payload, 
        key=app.config["SECRET_KEY"], 
        algorithm=JWT_ALGORITHM
    )

    return jwt_token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check authorization token is passed
        try: 
            token = request.headers['x-access-token']
        except:
            return make_response('missing authorization token', codes.unauthorized)

        # Check token is valid
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[JWT_ALGORITHM])
            uid = data["uid"]
        except:
            return make_response('unauthorized', 401)
        
        # Get user associated with uid in token 
        logged_u = models.get_user(uid)
        
        # Check logged user was actually in DB
        if not logged_u:
            return make_response('unauthorized', 401)
        
        # Return the current logged user to the routes
        return  f(logged_u, *args, **kwargs)
  
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(logged_u: models.Users, *args, **kwargs):
        
        # Check that the logged user is admin
        if not logged_u or not logged_u.admin:
            return make_response('not admin', 401)
        
        # Return the current logged user to the routes
        return  f(logged_u, *args, **kwargs)
  
    return decorated
