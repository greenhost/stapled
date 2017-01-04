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
import threading
import queue
import daemon
import time
from core import certfinder, ocsprenewer

logging.basicConfig(
    level=logging.DEBUG,
    format='(%(threadName)-10s) %(message)s'
)
LOG = logging.getLogger()

QUEUE_MAX_SIZE_PARSE = 0  # 0 = unlimited


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
        default=10,
        help="Minimum time to wait between parsing cert dirs and certificates."
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

    args = parser.parse_args()

    LOG.setLevel(max(min(50 - args.verbose * 10, 50), 0))

    if args.daemon:
        LOG.info("Daemonising now..")
        with daemon.DaemonContext():
            context = OCSPSDaemon(args)
    else:
        LOG.info("Running interactively..")
        context = OCSPSDaemon(args)


class OCSPSDaemon(object):

    def __init__(self, args):
        LOG.debug("Started with CLI args: %s", str(args))
        self.parse_queue = queue.Queue(QUEUE_MAX_SIZE_PARSE)
        self.directories = args.directories
        self.file_extensions = args.file_extensions.replace(" ", "").split(",")
        self.renewal_threads = args.renewal_threads
        self.refresh_interval = args.refresh_interval
        self.ignore_list = []

        LOG.info(
            "Starting OCSP Stapling daemon, finding files of types: %s with "
            "%d threads.",
            ", ".join(self.file_extensions),
            self.renewal_threads
        )

        # Start ocsp response gathering threads
        self.threads_list = []
        for tid in range(0, self.renewal_threads):
            thread = ocsprenewer.OCSPRenewerThreaded(
                parse_queue=self.parse_queue,
                ignore_list=self.ignore_list,
                tid=tid
            )
            self.threads_list.append(thread)

        # Start certificate finding thread
        self.parser_thread = certfinder.CertFinderThreaded(
            directories=self.directories,
            parse_queue=self.parse_queue,
            refresh_interval=self.refresh_interval,
            file_extensions=self.file_extensions,
            ignore_list=self.ignore_list
        )

if __name__ == '__main__':
    init()
