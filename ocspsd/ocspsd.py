import sys
import argparse
import time
import logging
import threading
from OpenSSL import crypto

logging.basicConfig(
    level=logging.DEBUG,
    format='(%(threadName)-10s) %(message)s'
)
LOG = logging.getLogger()


def main():
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
        'certdir',
        type=str,
        help='Directory containing the certificates used by HAProxy.'
    )

    parser.add_argument(
        '--minimum-validity',
        type=int,
        default=7200,
        help=(
            'If the staple is valid for less than this time in seconds an '
            'attempt will be made to get a new, valid staple (default: 7200).'
        )
    )

    parser.add_argument(
        '-t',
        '--threads',
        type=int,
        default=2,
        help='Amount of threads to run for renewing staples.'
    )

    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        help='Print more info (default: FATAL).'
    )

    args = parser.parse_args()

    LOG.setLevel(max(min(args.verbose*10, 50), 0))

    LOG.info("Spawning main thread.")
    d = threading.Thread(name='daemon', target=daemon, kwargs=args.__dict__)
    d.setDaemon(True)
    d.start()
    LOG.info("Started main thread (%s)", d.ident)
    d.join()


def daemon(**kwargs):
    time.sleep(0.1)
    LOG.info(kwargs)
    LOG.info('Spawning OSCP stapling renewal threads.')
    threads = []
    for tid in range(kwargs['threads']):
        thread = OSCPSRenew()
        thread.name = "thread-{}".format(tid)
        thread.start()
        threads.append(thread)

    while True:
        for thread in threads:
            if not thread.is_alive():

                thread = OSCPSRenew()


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
            time.sleep(1)

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
    main()
