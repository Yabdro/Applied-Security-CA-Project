#!/var/www/auth_manager/env/bin/python3

import sys
import logging

sys.path.insert(0, '/var/www/auth_manager')

from www import app as application

logging.basicConfig(stream=sys.stderr)
