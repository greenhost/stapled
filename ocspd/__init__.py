# -*- coding: utf-8 -*-
"""
Initialise the ocspd module.

This file only contains some variables we need in the ``ocspd`` name space.
"""

import sys
import os
from ocspd.version import __version__, __app_name__

LIB_PATHS = [
    "certvalidator",
    "oscrypto",
    "asn1crypto",
    "ocspbuilder"
]

sys.path.extend([os.path.abspath("lib/{}".format(path)) for path in LIB_PATHS])

#: The extensions the daemon will try to parse as certificate files
FILE_EXTENSIONS_DEFAULT = 'crt,pem,cer'

#: The default refresh interval for the
#: :class:`ocspd.core.certfinder.CertFinderThread`.
DEFAULT_REFRESH_INTERVAL = 60

#: How many times should we restart threads that crashed.
MAX_RESTART_THREADS = 3

#: Directory where logs and traces will be saved.
LOG_DIR = "/var/log/ocspd/"

#: Default locations to look for config files in order of importance.
DEFAULT_CONFIG_FILE_LOCATIONS = [
    os.path.join(os.path.realpath(''), 'ocspd.conf'),
    '~/.ocspd.conf',
    '/etc/ocspd/ocspd.conf'
]
