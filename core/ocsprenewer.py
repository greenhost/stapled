"""
    This module parses certificate in a queue so the data contained in the
    certificate can be used to request OCSP responses.
"""

import threading
import logging
import os
from models import CertFile, OCSPRenewError, CertValidationError

LOG = logging.getLogger()


def _ocsp_renewer_factory(threaded=True):
    """
        Returns a threaded or non-threaded class (not an instance) of
            OCSPRenewer

        :param bool threaded: Should the returned class be threaded?
        :return class: OCSPRenewer class threaded if threaded argument == True
    """

    if threaded:
        base_object = threading.Thread
    else:
        base_object = object

    class _OCSPRenewer(base_object):
        """
            This object takes tasks from a queue, the tasks contain certificate
            files that have to be pared to extract the certificate chain and
            the server certificate.
        """

        def __init__(self, *args, **kwargs):
            self.renew_queue = kwargs.pop('renew_queue', None)
            self.cert_list = kwargs.pop('cert_list', None)
            if base_object is threading.Thread:
                self.threaded = True
                super(_OCSPRenewer, self).__init__()
                tid = kwargs.pop('tid', 0)
                self.name = "ocsp-renewer-{}".format(tid)
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
            if self.renew_queue is None:
                raise ValueError(
                    "You need to pass a queue where parsed certificates can "
                    "be retrieved from for renewing."
                )
            if self.cert_list is None:
                raise ValueError(
                    "You need to pass a dict for certificate data to be kept."
                )
            LOG.info("Started a parser thread.")
            while True:
                crt = self.renew_queue.get()
                LOG.info("Renewing OCSP staple for file \"%s\"..", crt)
                try:
                    crt.renew_ocsp_staple()
                except OCSPRenewError as err:
                    self._handle_failed_validation(crt, err)
                except CertValidationError as err:
                    self._handle_failed_validation(crt, err)

                # Keep cached record of parsed crt
                self.cert_list[crt.filename] = crt
                self.renew_queue.task_done()
                self.schedule_renew(crt)

        def _handle_failed_validation(
                self, crt, msg, delete_ocsp=True, ignore=False):
            if ignore:
                self.ignore_list.append(crt.filename)
            LOG.critical(msg)
            if delete_ocsp:
                LOG.info(
                    "Deleting any OCSP staple: \"%s.ocsp\" if it exists.",
                    crt
                )
                try:
                    os.remove("{}.ocsp".format(crt))
                except IOError:
                    LOG.debug(
                        "Can't delete OCSP staple, maybe it doesn't exist."
                    )

        @classmethod
        def schedule_renew(crt, sched_time=None):
            """
                Schedule to renew this certificate's OCSP staple in
                `sched_time` seconds.

                :param models.certificates.CertFile crt: CertFile instance
                    None to calculate it automatically.
                :param int shed_time: Amount of seconds to wait for renewal or
                    None to calculate it automatically.
            """
            if not sched_time:
                sched_time = 1  # TODO: Implement a scheduling here.

    return _OCSPRenewer

# Create the objects for a threaded and a non-threaded OCSPRenewer
OCSPRenewerThreaded = _ocsp_renewer_factory()
OCSPRenewer = _ocsp_renewer_factory(threaded=False)
