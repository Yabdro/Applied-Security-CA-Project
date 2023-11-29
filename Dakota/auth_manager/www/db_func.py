import datetime
from www import db

def select(table, **kwargs):
    q = table.query
    for k,v in kwargs.items():
        q = q.filter(getattr(table, k) == v)
    return q.first()

def update(obj, **kwargs):
    for k,v in kwargs.items():
        setattr(obj, k, v)
    db.session.commit()
    return obj

