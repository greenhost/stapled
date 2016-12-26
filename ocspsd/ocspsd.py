#!/usr/bin/env python3
import os
import sys
import argparse
import time
import logging
import threading
from queue import Queue
import daemon
import cryptography

logging.basicConfig(
    level=logging.DEBUG,
    format='(%(threadName)-10s) %(message)s'
)
LOG = logging.getLogger()

QUEUE_MAX_SIZE = 0  # 0 = unlimited
FILE_EXTENSIONS_DEFAULT = 'crt,pem,cer'


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
        '--threads',
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
        default=FILE_EXTENSIONS_DEFAULT,
        help=(
            "Files with which extensions should be scanned? Comma separated "
            "list (default: crt,pem,cer)"
        )
    )

    parser.add_argument(
        'certdirs',
        type=str,
        nargs='+',
        help="Directory containing the certificates used by HAProxy."
    )

    args = parser.parse_args()

    LOG.setLevel(max(min(args.verbose*10, 50), 0))

    if args.daemon:
        LOG.info("Daemonising now..")
        with daemon.DaemonContext():
            daemon = OCSPSDaemon(args)
    else:
        LOG.info("Running interactively..")
        daemon = OCSPSDaemon(args)


class OCSPSDaemon(object):

    def __init__(self, args):
        LOG.debug("Started with CLI args: %s", str(args))
        self.queue = Queue(QUEUE_MAX_SIZE)
        self.certdirs = args.certdirs
        self.file_extensions = args.file_extensions.replace(" ","").split(",")
        self.thread_count = args.threads

        # Ledger of files and their data.
        self.cert_files = {}

        LOG.info(
            "Starting OCSP Stapling daemon, finding files of types: %s with "
            "%d threads.",
            args.file_extensions,
            self.thread_count
        )

        self.run()

    def run(self):
        #while True:
        self.find_new_certs()

        for tid in range(self.thread_count):
            thread = OSCPSRenew()
            thread.name = "thread-{}".format(tid)
            thread.daemon = True
            thread.start()
        time.sleep(2)

    def find_new_certs(self):
        files = []
        LOG.info("Scanning directories: %s", ", ".join(self.certdirs))
        try:
            for path in self.certdirs:
                LOG.debug("Scanning directory: %s", path)
                for file in os.listdir(path):
                    ext = os.path.splitext(file)[1].lstrip(".")
                    file = os.path.join(path, file)
                    if ext in self.file_extensions:
                        LOG.debug("Found a candidate file %s", file)
                        if file not in self.cert_files:
                            self.cert_files[file] = ParsedCertFile(file)
        except FileNotFoundError:
            LOG.error("Can't read directory: %s, does not exist.", path)


class ParsedCertFile(object):

    def __init__(self, file):
        pass

class OSCPSRenew(threading.Thread):
    '''
        The thread that renews OCSP staples.
    '''

    def run(self):
        super(OSCPSRenew, self).__init__()
        i = 0
        while True:
            self.hello_world(i)
            i = i+1
            time.sleep(.1)

    @staticmethod
    def hello_world(iteration):
        """
            Print Hello world, the iteration and the thread ID
        """
        LOG.info(
            "Hello world %s",
            iteration
        )

if __name__ == '__main__':
    init()
