#!/usr/bin/env python3
import os
import sys
import argparse
import time
import logging
import threading
from queue import Queue
import daemon
from models.parsedcert import ParsedCertFile

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
        '-r',
        '--refresh-interval',
        type=int,
        default=10,
        help="Minimum time to wait between parsing cert dirs and certificates."
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
            context = OCSPSDaemon(args)
    else:
        LOG.info("Running interactively..")
        DaemonContext = OCSPSDaemon(args)


class OCSPSDaemon(object):

    def __init__(self, args):
        LOG.debug("Started with CLI args: %s", str(args))
        self.queue = Queue(QUEUE_MAX_SIZE)
        self.certdirs = args.certdirs
        self.file_extensions = args.file_extensions.replace(" ","").split(",")
        self.thread_count = args.threads
        self.refresh_interval = args.refresh_interval

        # Ledger of files and their data.
        self.crt_files = {}

        LOG.info(
            "Starting OCSP Stapling daemon, finding files of types: %s with "
            "%d threads.",
            args.file_extensions,
            self.thread_count
        )

        self.run()
        self.queue.join()

    def run(self):

        for tid in range(self.thread_count):
            thread = OSCPSRenew()
            thread.name = "thread-{}".format(tid)
            thread.daemon = True
            thread.start()

        # Initially find all certs in cert dirs.
        self.refresh(forever=True)

    def _find_new_certs(self):
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
                        if file not in self.crt_files:
                            parsed_crt = ParsedCertFile(file)
                            self.crt_files[file] = parsed_crt
                            self.queue.put(parsed_crt)

        except FileNotFoundError:
            LOG.error("Can't read directory: %s, does not exist.", path)

    def _update_cached_certs(self):
        for crt_file, parsed_cert in self.crt_files.items():
            # purge certs that no longer exist in the cert dirs
            if not os.path.exists(crt_file):
                del self.crt_file[crt_file]
            if os.path.getmtime(crt_file) > parsed_cert.time_parsed:
                self.queue.put(parsed_crt)

    def refresh(self, forever=False):
        self.last_refresh = time.time()
        LOG.info("Updating current cache..")
        self._update_cached_certs()
        LOG.info("Adding new certificates to cache..")
        self._find_new_certs()

        # Schedule the next refresh run..
        if forever:
            since_last = time.time() - self.last_refresh
            # Check if the last refresh took longer than the interval..
            if since_last > self.refresh_interval:
                # It did so start right now..
                LOG.info(
                    "Starting a new refresh immediately because the last "
                    "refresh took %0.3f seconds while the minimum interval is "
                    "%d seconds.",
                    since_last,
                    self.refresh_interval
                )
                self.refresh()
            else:
                # Wait the remaining time before refreshing again..
                LOG.info(
                    "Scheduling a new refresh in %0.2f seconds because the "
                    "last refresh took %0.2f seconds while the minimum "
                    "interval is %d seconds.",
                    self.refresh_interval - since_last,
                    since_last,
                    self.refresh_interval
                )
                threading.Timer(
                    self.refresh_interval - since_last,
                    self.refresh,
                    kwargs=dict(forever=forever)
                ).start()

class OSCPSRenew(threading.Thread):
    '''
        The thread that renews OCSP staples.
    '''

    def run(self):
        super(OSCPSRenew, self).__init__()
        i = 0
        while i<3000:
            # self.hello_world(i)
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
