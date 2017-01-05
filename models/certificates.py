import os
import logging
import hashlib
import base64
import urllib
import certvalidator
import ocspbuilder
from asn1crypto import pem, x509
from oscrypto import asymmetric

LOG = logging.getLogger()


class CertValidationError(BaseException):
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
        self.chain = None

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
        self._read_full_chain()
        self.chain = self._validate_cert()

    def renew_ocsp_staple(self, url_index=0):
        """
            Renew the OCSP staple and save it to the correct file path
        """
        self.ocsp_request = self._build_ocsp_request(
            self.end_entity,
            self.chain[-1]
        )
        LOG.info(
            "Trying to get OCSP staple from url \"%s\"..",
            self.ocsp_urls[url_index]
        )
        with open("{}.request".format(self.filename), 'wb') as fl:
            fl.write(self.ocsp_request)
        req = urllib.request.Request(
            url=self.ocsp_urls[url_index],
            data=self.ocsp_request,
            method='POST',
            headers={
                "Content-Type": "application/ocsp-request"
            }
        )
        with urllib.request.urlopen(req) as open_url:
            data = open_url.read()
        if 200 < open_url.status < 300:
            LOG.warn(
                "Tried the the OCSP url \"%s\" but the return status is bad.",
                self.ocsp_urls[url_index]
            )
            if len(self.ocsp_urls) >= url_index+1:
                self.renew_ocsp_staple(self, url_index=url_index+1)
            else:
                LOG.error(
                    "Exhausted OCSP urls, stopping OCSP renewal.",
                    self.ocsp_urls[url_index]
                )
        else:
            LOG.info("Successful OCSP staple request.")
            LOG.debug(data.decode('utf-8'))

    def _read_full_chain(self):
        with open(self.filename, 'rb') as f_obj:
            pem_obj = pem.unarmor(f_obj.read(), multiple=True)
        for type_name, _, der_bytes in pem_obj:
            if type_name == 'CERTIFICATE':
                cert = x509.Certificate.load(der_bytes)
                if cert.ca:
                    LOG.debug("Found part of the chain..")
                    self.intermediates.append(der_bytes)
                else:
                    LOG.debug("Found the end entity..")
                    self.end_entity = der_bytes
                    self.ocsp_urls = cert.ocsp_urls
        if self.end_entity is None:
            LOG.error(
                "Can't find server certificate items for \"%s\".",
                self.filename
            )
        if len(self.intermediates) < 1:
            LOG.error(
                "Can't find the CA certificate chain items.",
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
            LOG.debug("Certificate chain for \"%s\" validated.", self.filename)
            return chain
        except certvalidator.errors.PathValidationError:
            raise CertValidationError(
                "Failed to validate certificate path for \"{}\", will not "
                " try to parse it again.".format(self.filename)
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
        ocsp_request = builder.build()
        return ocsp_request.dump()

    def __repr__(self):
        """
            When we refer to this object without calling a method or specifying
            an attribute we want to get the file name returned.
        """
        return self.filename
