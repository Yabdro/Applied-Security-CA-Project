import flask 
import flask_migrate
import flask_sqlalchemy
from www.config import Config

app = flask.Flask(__name__)
app.config.from_object(Config)
db = flask_sqlalchemy.SQLAlchemy(app)
migrate = flask_migrate.Migrate(app, db)

import www.routes
import www.models
