# -*- coding: utf-8 -*-
"""
Initialise the stapled module.

This file only contains some variables we need in the ``stapled`` name space.
"""

import sys
import os
from stapled.version import __version__, __app_name__

#: The extensions the daemon will try to parse as certificate files
FILE_EXTENSIONS_DEFAULT = 'crt,pem,cer'

#: The default refresh interval for the
#: :class:`stapled.core.certfinder.CertFinderThread`.
DEFAULT_REFRESH_INTERVAL = 60

#: How many times should we restart threads that crashed.
MAX_RESTART_THREADS = 3

#: Directory where logs and traces will be saved.
LOG_DIR = "/var/log/stapled/"

#: Default locations to look for config files in order of importance.
DEFAULT_CONFIG_FILE_LOCATIONS = [
    os.path.join(os.path.realpath(''), 'stapled.conf'),
    '~/.stapled.conf',
    '/etc/stapled/stapled.conf'
]
