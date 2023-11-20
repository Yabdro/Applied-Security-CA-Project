#!/var/www/auth_manager/env/bin/python3
# WSGI File requires to start Flask application on Apache Web Server

import sys
import logging

sys.path.insert(0, '/var/www/imovies/')

from www import app as application

logging.basicConfig(stream=sys.stderr)








