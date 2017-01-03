"""
    This module holds methods to renew OCSP staples from servers.
    The
"""

import threading
import time
import logging

LOG = logging.getLogger()


def _ocsp_renewal_factory(threaded=True):

    if threaded:
        base_object = threading.Thread
    else:
        base_object = object

    class _OSCPSRenew(base_object):
        '''
            The thread that renews OCSP staples.
        '''

        def run(self):
            super(_OSCPSRenew, self).__init__()
            i = 0
            while i < 3000:
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

    return _OSCPSRenew

OSCPSRenewThreaded = _ocsp_renewal_factory()
OSCPSRenew = _ocsp_renewal_factory(threaded=False)
