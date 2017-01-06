#!/usr/bin/env python3
"""
    This is the main script that starts the OCSP Staple daemon which indexes
    your certificate directories and requests staples for all certificates
    in them. They will be saved as `certificatename.pem.staple` in the
    directories that are being indexed.

    This is meant as a helper daemon for HAProxy which doesn't do OCSP stapling
    out of the box, even though it can serve staple files, which is what we use
    to our benefit.

    Type ocsp.py -h for all command line arguments.

    This module collects the command line arguments and detaches the process
    from the user's context if `-d` (daemon mode) is specified, then spawns a
    bunch of threads for:
     - Indexing certificates in the given directories.
     - Parsing certificate files and determining validity, then requesting a
       staple if valid.
     - Renewing staples for certificates from the queue. This process requires
       a connection to the CA of that issued the certificate and is blocking. It
       is therefore heavily threaded. This is also the only process you can
       select the amount of threads for with a command line argument.
"""

import argparse
import logging
import logging.handlers
import os
import daemon
from core import certfinder
from core.daemon import OCSPSDaemon

LOGFORMAT = '(%(threadName)-10s) %(levelname)s %(message)s'

logging.basicConfig(
    level=logging.DEBUG,
    format=LOGFORMAT
)
LOG = logging.getLogger()

def init():
    """
        Parse arguments
    """
    parser = argparse.ArgumentParser(
        description=(
            "Update OCSP staples from CA\'s and store the result so "
            "HAProxy can serve them to clients."
        ),
        conflict_handler='resolve',
        epilog="This will not serve OCSP responses."
    )

    parser.add_argument(
        '--minimum-validity',
        type=int,
        default=7200,
        help=(
            "If the staple is valid for less than this time in seconds an "
            "attempt will be made to get a new, valid staple (default: 7200)."
        )
    )

    parser.add_argument(
        '-t',
        '--renewal-threads',
        type=int,
        default=2,
        help="Amount of threads to run for renewing staples."
    )

    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        help="Print more info (default: FATAL)."
    )

    parser.add_argument(
        '-d',
        '--daemon',
        action='store_true',
        help=(
            "Daemonise the process, release from shell and process group, run"
            "under new process group, optionally drop privileges and chroot."
        )
    )

    parser.add_argument(
        '--file-extensions',
        type=str,
        default=certfinder.FILE_EXTENSIONS_DEFAULT,
        help=(
            "Files with which extensions should be scanned? Comma separated "
            "list (default: crt,pem,cer)"
        )
    )

    parser.add_argument(
        '-r',
        '--refresh-interval',
        type=int,
        default=60,
        help="Minimum time to wait between parsing cert dirs and "
        "certificates (default=60)."
    )

    parser.add_argument(
        '-l',
        '--logfile',
        type=str,
        help="File to log output to."
    )

    parser.add_argument(
        '--syslog',
        action='store_true',
        default=False,
        help="Output to syslog."
    )

    parser.add_argument(
        'directories',
        type=str,
        nargs='+',
        help=(
            "Directories containing the certificates used by HAProxy. "
            "Multiple directories may be specified separated by a space. "
            "This is a positional argument and nothing but directories may "
            "succeed it."
        )
    )

    log_file_handles = []

    args = parser.parse_args()
    args.directories = [os.path.abspath(d) for d in args.directories]

    log_level = max(min(50 - args.verbose * 10, 50), 0)
    LOG.setLevel(log_level)
    if args.logfile:
        file_handler = logging.FileHandler(args.logfile)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(LOGFORMAT))
        LOG.addHandler(file_handler)
        log_file_handles.append(file_handler.stream)

    if args.syslog:
        syslog_handler = logging.handlers.SysLogHandler()
        syslog_handler.setLevel(log_level)
        syslog_handler.setFormatter(logging.Formatter(LOGFORMAT))
        LOG.addHandler(syslog_handler)

    if args.daemon:
        LOG.info("Daemonising now..")
        with daemon.DaemonContext(files_preserve=log_file_handles):
            OCSPSDaemon(args)
    else:
        LOG.info("Running interactively..")
        OCSPSDaemon(args)

if __name__ == '__main__':
    init()
