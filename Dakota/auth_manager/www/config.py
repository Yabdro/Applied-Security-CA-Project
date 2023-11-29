class Config(object):
    SECRET_KEY = "f5d24fa4a31189f43777dc14b8e9441df0631ff28ca54fdf26c8afc46fe0adba"
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:root@localhost/imovies"
    SQLALCHEMY_TRACK_MODIFICATIONS = False