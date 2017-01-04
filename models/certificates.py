import os
import logging
import hashlib
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
        self.intermediates = None
        self.ocsp_staple = None
        self._validator = None

    @property
    def valid(self):
        """
            TODO: Implement some basic check to see if this could possibly be a
            valid certificate file.
        """
        return True

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
        end_entity, intermediates = self._read_full_chain()
        if self._validate_cert(end_entity, intermediates):
            self.end_entity = end_entity
            self.intermediates = intermediates
        else:
            raise CertValidationError

    def renew_ocsp_staple(self):
            """
                Renew the OCSP staple and save it to the correct file path
            """
            self._validate_cert_with_ocsp()

    def _read_full_chain(self):
        end_entity = None
        intermediates = []
        with open(self.filename, 'rb') as f_obj:
            pem_obj = pem.unarmor(f_obj.read(), multiple=True)
        for type_name, _, der_bytes in pem_obj:
            if type_name == 'CERTIFICATE':
                cert = x509.Certificate.load(der_bytes)
                if cert.ca:
                    LOG.debug("Found part of the chain..")
                    intermediates.append(der_bytes)
                else:
                    LOG.debug("Found the end entity..")
                    end_entity = der_bytes
        return end_entity, intermediates

    def _validate_cert(self, end_entity, intermediates):
        try:
            # Cache the validator for later use.
            self._validator = certvalidator.CertificateValidator(
                end_entity, intermediates
            )
            self._validator.validate_usage(
                key_usage=set(['digital_signature']),
                extended_key_usage=set(['server_auth']),
                extended_optional=True
            )
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
        LOG.debug("Certificate chain for \"%s\" validated.", self.filename)
        return True

    def _validate_cert_with_ocsp(self):
        """
            Check that the chain and the OCSP response validate together,
            to prevent the proxy from serving invalid OCSP responses.
        """
        try:
            # ocsps = [self.ocsp_staple]
            context = certvalidator.ValidationContext(
                # ocsps=ocsps,
                allow_fetching=True
            )
            validator = certvalidator.CertificateValidator(
                self.end_entity,
                self.intermediates,
                validation_context=context
            )
            validator.validate_usage(
                key_usage=set(['digital_signature']),
                extended_key_usage=set(['server_auth']),
                extended_optional=True
            )
            # How to get the OCSP staple out...
            for var in validator._path.pop():
                LOG.debug(var)

        except certvalidator.errors.PathValidationError:
            raise CertValidationError(
                "Failed to validate certificate together with the OCSP staple "
                "path for \"{}\", will not try to parse it again.".format(
                    self.filename
                )
            )
            return False
        except certvalidator.errors.RevokedError:
            raise CertValidationError(
                "Certificate \"{}\" was revoked, will not try to parse it "
                "again.".format(self.filename)
            )
            return False
        except certvalidator.errors.InvalidCertificateError:
            raise CertValidationError(
                "Certificate \"{}\" is invalid, will not try to parse it "
                "again.".format(self.filename)
            )
            return False
        LOG.debug(
            "Certificate chain for \"%s\" validated with OCSP.",
            self.filename
        )
        return True

    def __repr__(self):
        """
            When we refer to this object without calling a method or specifying
            an attribute we want to get the file name returned.
        """
        return self.filename
