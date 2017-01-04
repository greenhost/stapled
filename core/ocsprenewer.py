"""
    This module parses certificate in a queue so the data contained in the
    certificate can be used to request OCSP responses.
"""

import threading
import time
import logging
import os
import base64
from asn1crypto import pem, x509
import certvalidator
from models.certificates import CertFile

LOG = logging.getLogger()


def _ocsp_renewer_factory(threaded=True):
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

    class _OCSPRenewer(base_object):
        """
            This object takes tasks from a queue, the tasks contain certificate
            files that have to be pared to extract the certificate chain and
            the server certificate.
        """

        def __init__(self, *args, **kwargs):
            self.ignore_list = kwargs.pop('ignore_list', [])
            self.parse_queue = kwargs.pop('parse_queue', None)
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
            if self.parse_queue is None:
                raise ValueError(
                    "You need to pass a queue where found certificates can be "
                    "retrieved from for parsing."
                )
            LOG.info("Started a parser thread.")
            while True:
                crt = self.parse_queue.get()
                LOG.info("Parsing file \"%s\"..", crt.filename)
                self.parse_cert_chain(crt)
                self.parse_queue.task_done()

        def parse_cert_chain(self, crt):
            # Extract the certificate (end_entity) and the chain
            # (intermediates)
            end_entity, intermediates = self._read_full_chain(crt.filename)
            if not self._validate_cert(end_entity, intermediates, crt):
                self.ignore_list.append(crt.filename)
                LOG.error(
                    "Failed to validate certificate \"%s\", will not try to "
                    "parse it again.",
                    crt.filename
                )

        def _validate_cert(self, end_entity, intermediates, crt):
            try:
                validator = certvalidator.CertificateValidator(
                    end_entity, intermediates
                )
                validator.validate_usage(
                    key_usage=set(['digital_signature']),
                    extended_key_usage=set(['server_auth']),
                    extended_optional=True
                )
            except certvalidator.errors.PathValidationError:
                self._handle_failed_validation(
                    crt,
                    "Failed to validate certificate path for \"%s\", will not "
                    " try to parse it again."
                )
                return False
            except certvalidator.errors.RevokedError:
                self._handle_failed_validation(
                    crt,
                    "Certificate \"%s\" was revoked, will not try to parse it "
                    "again."
                )
                return False
            except certvalidator.errors.InvalidCertificateError:
                self._handle_failed_validation(
                    crt,
                    "Certificate \"%s\" is invalid, will not try to parse it "
                    "again."
                )
                return False
            except KeyError as err:
                self._handle_failed_validation(
                    crt,
                    "KeyError {}, processing file \"%s\"".format(err),
                    delete_ocsp=False
                )
                raise err
                return False
            return True

        @staticmethod
        def _read_full_chain(filename):
            end_entity = None
            intermediates = []
            with open(filename, 'rb') as f:
                pem_obj = pem.unarmor(f.read(), multiple=True)
                for type_name, headers, der_bytes in pem_obj:
                    if type_name == 'CERTIFICATE':
                        cert = x509.Certificate.load(der_bytes)
                        if cert.ca:
                            LOG.debug("Found part of the chain..")
                            intermediates.append(der_bytes)
                        else:
                            LOG.debug("Found the end entity..")
                            end_entity = der_bytes
            return end_entity, intermediates

        def _handle_failed_validation(self, crt, msg, delete_ocsp=True):
            self.ignore_list.append(crt.filename)
            LOG.error(msg, crt.filename)
            if delete_ocsp:
                LOG.info(
                    "Deleting any OCSP staple: \"%s\" if it exists.",
                    crt.filename
                )
                try:
                    os.remove("{}.ocsp".format(crt.filename))
                except IOError:
                    pass

    return _OCSPRenewer

# Create the objects for a threaded and a non-threaded CertFinder
OCSPRenewerThreaded = _ocsp_renewer_factory()
OCSPRenewer = _ocsp_renewer_factory(threaded=False)
