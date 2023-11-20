import flask 
from www.config import Config

app = flask.Flask(__name__)
app.config.from_object(Config)
import www.routes
