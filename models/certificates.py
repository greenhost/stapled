import os
import logging
import hashlib
import binascii
import urllib
import time
import requests
import certvalidator
import ocspbuilder
from asn1crypto import pem, x509
from oscrypto import asymmetric

LOG = logging.getLogger()

RETRY_COUNT = 3


class CertValidationError(Exception):
    pass


class OCSPRenewError(BaseException):
    pass


class CertFile(object):
    """
        Model for certificate files.
    """
    def __init__(self, filename):
        """
            Initialise the CertFile model object.
        """
        self.filename = filename
        self.hash = self.hashfile(filename)
        self.modtime = self.file_modification_time(filename)
        self.end_entity = None
        self.intermediates = []
        self.ocsp_staple = None
        self.ocsp_request = None
        self.ocsp_urls = []
        self.chain = []

    @staticmethod
    def file_modification_time(filename):
        return os.path.getmtime(filename)

    @staticmethod
    def hashfile(filename):
        """
            Return the SHA1 hash of the binary file contents.
        """
        sha1 = hashlib.sha1()
        try:
            with open(filename, 'rb') as f_obj:
                sha1.update(f_obj.read())
        except IOError as err:
            # Catch to log the error and re-raise to handle at the appropriate
            # level
            LOG.error("Can't access file %s", filename)
            raise err
        return sha1.hexdigest()

    def parse_crt_chain(self):
        """
            Extract the certificate (end_entity) and the chain (intermediates)
        """
        try:
            self._read_full_chain()
            self.chain = self._validate_cert()
        except TypeError:
            raise CertValidationError(
                "Can't validate the certificate because part of the "
                "certificate chain is missing in \"{}\"".format(self.filename)
            )

    def renew_ocsp_staple(self, url_index=0):
        """
            Renew the OCSP staple and save it to the correct file path
        """
        if not self.end_entity:
            raise CertValidationError(
                "Certificate is missing in \"{}\", can't validate "
                "without it.".format(self.filename)
            )
        if len(self.chain) < 1:
            raise CertValidationError(
                "Certificate chain is missing in \"{}\", can't validate "
                "without it.".format(self.filename)
            )
        url = self.ocsp_urls[url_index]
        host = urllib.parse.urlparse(url).hostname
        self.ocsp_request = self._build_ocsp_request(
            self.end_entity,
            self.chain[-2]
        )
        LOG.debug(
            # urllib.parse.quote_plus(
            binascii.b2a_base64(
                self.ocsp_request
            ).decode('ascii').replace("\n", "")
            # )
        )
        LOG.info(
            "Trying to get OCSP staple from url \"%s\"..",
            url
        )
        retry = RETRY_COUNT
        while retry > 0:
            try:

                request = requests.post(
                    url,
                    data=self.ocsp_request,
                    headers={
                        'Content-Type': 'application/ocsp-request',
                        'Accept': 'application/ocsp-response',
                        'Host': host
                    }
                )
                # Raise HTTP exception if any occurred
                request.raise_for_status()
                ocsp_staple = request.content
                LOG.debug(request.request.headers)
                if ocsp_staple == b'':
                    msg = "Received empty response from {} for {}".format(
                        url,
                        self.filename
                    )
                    LOG.warn(msg)
                    raise TypeError(msg)
                self.ocsp_staple = ocsp_staple

                # TODO: Check the staples validity!
                # TODO: Make a scheduler for renewal of staples
                # TODO: send merge request for header in ocsp fetching

                LOG.info(
                    "Received good response from OCSP server %s for %s",
                    url,
                    self.filename,
                )
                break
            except urllib.error.URLError as err:
                LOG.error("Connection problem: %s", err)
            except TypeError:
                LOG.warn(
                    "Received empty response from OCSP server %s for %s",
                    url,
                    self.filename
                )
            except requests.exceptions.HTTPError as err:
                LOG.warn(
                    "Received bad HTTP status code %s from OCSP server %s for "
                    " %s: %s",
                    request.status,
                    url,
                    self.filename,
                    err
                )

            retry = retry - 1
            if retry > 0:
                sleep_time = (RETRY_COUNT - retry) * 5
                LOG.info("Retrying in %d seconds..", sleep_time)
                time.sleep(sleep_time)
            else:
                if url_index + 1 < len(self.ocsp_urls):
                    self.renew_ocsp_staple(url_index+1)
                else:
                    raise OCSPRenewError(
                        "Couldn't renew OCSP staple for \"{}\"".format(
                            self.filename
                        )
                    )
        # If we got this far it means we have a staple in self.ocsp_staple
        # We would have had an exception otherwise. So let's verify that the
        # staple is actually working before serving it to clients.
        # To do this we run the validation again, this time self.ocsp_staple
        # will be taken into account because it is no longer None
        # If validation fails, it will raise an exception that should be
        # handled at another level.
        LOG.info("Validating staple..")
        self._validate_cert()
        # No exception was raised, so we can assume the staple is ok and write
        # it to disk.
        ocsp_filename = "{}.ocsp".format(self.filename)
        LOG.info(
            "Succesfully validated writing to file \"%s\"",
            ocsp_filename
        )
        with open(ocsp_filename, 'wb') as f_obj:
            f_obj.write(self.ocsp_staple)

    def _read_full_chain(self):
        with open(self.filename, 'rb') as f_obj:
            pem_obj = pem.unarmor(f_obj.read(), multiple=True)
        try:
            for type_name, _, der_bytes in pem_obj:
                if type_name == 'CERTIFICATE':
                    crt = x509.Certificate.load(der_bytes)
                    if crt.ca:
                        LOG.info("Found part of the chain..")
                        self.intermediates.append(crt)
                    else:
                        LOG.info("Found the end entity..")
                        self.end_entity = crt
                        self.ocsp_urls = crt.ocsp_urls
        except binascii.Error:
            LOG.error(
                "Certificate file contains errors \"%s\".",
                self.filename
            )
        if self.end_entity is None:
            LOG.error(
                "Can't find server certificate items for \"%s\".",
                self.filename
            )
        if len(self.intermediates) < 1:
            LOG.error(
                "Can't find the CA certificate chain items in \"%s\".",
                self.filename
            )

    def _validate_cert(self):
        try:
            if self.ocsp_staple is None:
                LOG.info("Validating without OSCP staple.")
                context = certvalidator.ValidationContext()
            else:
                LOG.info("Validating with OSCP staple.")
                context = certvalidator.ValidationContext(
                    ocsps=[self.ocsp_staple],
                    allow_fetching=True
                )
            validator = certvalidator.CertificateValidator(
                self.end_entity,
                self.intermediates,
                validation_context=context
            )
            chain = validator.validate_usage(
                key_usage=set(['digital_signature']),
                extended_key_usage=set(['server_auth']),
                extended_optional=True
            )
            LOG.info("Certificate chain for \"%s\" validated.", self.filename)
            return chain
        except certvalidator.errors.PathBuildingError:
            raise CertValidationError(
                "Failed to validate certificate path for \"{}\", will not "
                "try to parse it again.".format(self.filename)
            )
        except certvalidator.errors.PathValidationError:
            raise CertValidationError(
                "Failed to validate certificate path for \"{}\", will not "
                "try to parse it again.".format(self.filename)
            )
        except certvalidator.errors.RevokedError:
            raise CertValidationError(
                "Certificate \"{}\" was revoked, will not try to parse it "
                "again.".format(self.filename)
            )
        except certvalidator.errors.InvalidCertificateError:
            raise CertValidationError(
                "Certificate \"{}\" is invalid, will not try to parse it "
                "again.".format(self.filename)
            )

    @staticmethod
    def _build_ocsp_request(end_entity, ca_crt):
        """
            Generate an OCSP request to post to the OCSP server.
        """
        builder = ocspbuilder.OCSPRequestBuilder(
            asymmetric.load_certificate(end_entity),
            asymmetric.load_certificate(ca_crt)
        )
        builder.nonce = False
        #builder.hash_algo = 'sha256'
        #builder.key_hash_algo = 'sha256'
        ocsp_request = builder.build()
        return ocsp_request.dump(True)

    def __repr__(self):
        """
            When we refer to this object without calling a method or specifying
            an attribute we want to get the file name returned.
        """
        return self.filename
