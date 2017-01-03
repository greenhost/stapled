"""
    This module parses certificate in a queue so the data contained in the
    certificate can be used to request OCSP responses.
"""

import threading
import time
import logging
import os
from models.certificates import CertFile

LOG = logging.getLogger()


def _cert_parser_factory(threaded=True):
    """
        Returns a threaded or non-threaded class (not an instance) of
            CertParser

        :param bool threaded: Should the returned class be threaded?
        :return class: _CertFinder class threaded if threaded argument == True
    """

    if threaded:
        base_object = threading.Thread
    else:
        base_object = object

    class _CertParser(base_object):
        """
            This object takes tasks from a queue, the tasks contain certificate
            files that have to be pared to extract the certificate chain and
            the server certificate.
        """

        def __init__(self, *args, **kwargs):
            if base_object is threading.Thread:
                self.threaded = True
                super(_CertParser, self).__init__()
                tid = kwargs.pop('tid', 0)
                self.name = "cert-parser-{}".format(tid)
                self.daemon = False
                self.start()
            else:
                self.threaded = False
                self.run(*args, **kwargs)

        def run(self, *args, **kwargs):
            """
                Start the thread if threaded, otherwise just run the same
                process.
            """
            LOG.info("Started a parser thread.")

    return _CertParser

# Create the objects for a threaded and a non-threaded CertFinder
CertParserThreaded = _cert_parser_factory()
CertParser = _cert_parser_factory(threaded=False)
