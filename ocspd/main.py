#!/usr/bin/env python3
"""
This is the main script that parses your command line arguments and then starts
the OCSP Staple daemon, which indexes your certificate directories and requests
staples for all certificates in them. They will then be saved as
``certificatename.pem.ocsp`` in the same directories that are being indexed.

Type ``ocsp.py -h`` for all command line arguments.

This module collects the command line arguments and detaches the process
from the user's context if ``-d`` (daemon mode) is specified, then spawns a
bunch of threads for:

 - Indexing certificates in the given directories.
 - Parsing certificate files and determining validity, then requesting a
   staple if valid.
 - Renewing staples for certificates from the queue. This process requires
   a connection to the CA of that issued the certificate and is blocking. It
   is therefore heavily threaded. This is also the only process you can
   select the amount of threads for with a command line argument.
 - Optionally, a thread for adding the gathered OCSP staples to a running
   HAProxy instance through a HAProxy socket.

If the ``-d`` argument is specified, this module is responsible for starting
the application in daemonised mode, and disconnecting the process from the
user's process hierarchy node. In any case, it starts up the :mod:`core.daemon`
module to bootstrap the application.
"""

import argparse
import logging
import logging.handlers
import os
import daemon
import ocspd.core.daemon

#: :attr:`logging.format` format string (default:
#: ``%(threadName)-10s [%(levelname)s] %(message)s``)
LOGFORMAT = '%(threadName)-10s [%(levelname)s] %(message)s'

#: The extensions the daemon will try to parse as certificate files
#: (default:``crt,pem,cer``)
FILE_EXTENSIONS_DEFAULT = 'crt,pem,cer'

#: The amount of OSCP request retry attempts before giving up (default:``3``).
OCSP_REQUEST_RETRY_COUNT = 3

logging.basicConfig(
    level=logging.DEBUG,
    format=LOGFORMAT
)
LOG = logging.getLogger()

def get_cli_arg_parser():
    """
    Make a CLI argument parser and return it. It does not parse the arguments
    because a plain parser object is used for documentation purposes.

    :return: Argument parser with all of ocspd's options configured
    :rtype: argparse.ArgumentParser
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
        help="Verbose output, repeat to increase verbosity (default: CRITICAL)."
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
        default=FILE_EXTENSIONS_DEFAULT,
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
        '-s',
        '--haproxy-sockets',
        type=str,
        nargs='+',
        # FIXME: Maybe we want to move this to the documentation and reduce the
        # size of the help message here.
        help=(
            "Sockets to connect to HAProxy. Each directory you pass with "
            "the `directory` argument, should have its own haproxy socket. "
            "The order of the socket arguments should match the order of the "
            "directory arguments."
            "Example:"
            "I have a directory `/etc/haproxy1` with certificates, and a "
            "HAProxy that serves these certificates and has stats socket "
            "`/etc/haproxy1/haproxy.sock`. I have another directory "
            "`/etc/haproxy2` with certificates and another haproxy instance "
            "that serves these and has stats socket "
            "`/etc/haproxy2/haproxy.sock`. I would then start ocspd as "
            "follows:"
            "`./ocspd /etc/haproxy1 /etc/haproxy2 -s /etc/haproxy1.sock "
            "/etc/haproxy2.sock"
        )
    )

    parser.add_argument(
        'directories',
        type=str,
        nargs='+',
        help=(
            "Directories containing the certificates used by HAProxy. "
            "Multiple directories may be specified separated by a space. "
        )
    )

    return parser

def init():
    """
        Configures logging and log level, then calls :func:`core.daemon.run()`
        either in daemonised mode if the ``-d`` argument was supplied, or in
        the current context if it wasn't supplied.
    """
    log_file_handles = []
    parser = get_cli_arg_parser()
    args = parser.parse_args()
    args.directories = [os.path.abspath(d) for d in args.directories]

    log_level = max(min(50 - args.verbose * 10, 50), 10)
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
            ocspd.core.daemon.run(args)
    else:
        LOG.info("Running interactively..")
        ocspd.core.daemon.run(args)

if __name__ == '__main__':
    init()
