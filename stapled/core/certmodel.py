"""
This module defines the :class:`stapled.core.certmodel.CertModel` class which is
used to keep track of certificates that are found by the
:class:`stapled.core.certfinder.CertFinderThread`, then parsed by the
:class:`stapled.core.certparser.CertParserThread`, an OCSP request is generated
by the :class:`stapled.core.staplerenewer.StapleRenewer`, a response from an
OCSP server is returned. All data generated and returned like the request and
the response are stored in the context.

The following logic is contained within the context class:

 - Parsing the certificate.
 - Validating parsed certificates and their chains.
 - Generating OCSP requests.
 - Sending OCSP requests.
 - Processing OCSP responses.
 - Validating OCSP responses with the respective certificate and its chain.
"""
import os
import logging
import binascii
import datetime
import certvalidator
import asn1crypto
from stapled.core.exceptions import CertFileAccessError
from stapled.core.exceptions import OCSPBadResponse
from stapled.core.exceptions import RenewalRequirementMissing
from stapled.core.exceptions import CertParsingError
from stapled.core.exceptions import CertValidationError
from stapled.util.ocsp import OCSPResponseParser
from stapled.util.functions import pretty_base64

LOG = logging.getLogger(__name__)


class CertModel(object):
    """
    Model for certificate files.
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self, filename, cert_path):
        """
        Initialise the CertModel model object, and read the certificate data
        from the passed filename.

        :raises stapled.core.exceptions.CertFileAccessError: When the certificate
            file can't be accessed.
        """
        self.filename = filename
        self.modtime = os.path.getmtime(filename)
        self.end_entity = None
        self.intermediates = []
        self.ocsp_staple = None
        self.ocsp_urls = []
        self.chain = []
        self.url_index = 0
        self.crt_data = None
        self.cert_path = cert_path
        try:
            with open(filename, 'rb') as f_obj:
                self.crt_data = f_obj.read()
        except (IOError, OSError) as exc:
            raise CertFileAccessError(
                "Can't access file %s, reason: %s", filename, exc)

    def parse_crt_file(self):
        """
        Parse certificate, wraps the
        :meth:`~stapled.core.certmodel.CertModel._read_full_chain()` and the
        :meth:`~stapled.core.certmodel.CertModel._validate_cert()` methods.
        Wicth extract the certificate (*end_entity*) and the chain
        intermediates*), and validates the certificate chain.
        """
        self._read_full_chain()
        self.chain = self._validate_cert()

    def recycle_staple(self, minimum_validity):
        """
        Try to find an existing staple that is still valid for more than the
        ``minimum_validity`` period. If it is not valid for longer than the
        ``minimum_validity`` period, but still valid, add it to the context but
        still ask for a new one by returning ``False``.

        If anything goes wrong during this process, ``False`` is returned
        without any error handling, we can always try to get a new staple.

        :return bool: False if a new staple should be requested, True if the
            current one is still valid for more than ``minimum_validity``
        """
        ocsp_file = "{}.ocsp".format(self.filename)
        if not os.path.exists(ocsp_file):
            LOG.debug(
                "File does not exist yet: %s, need to request a staple.",
                ocsp_file
            )
            return False

        try:
            LOG.debug("Seeing if %s is still valid..", ocsp_file)
            with open(ocsp_file, "rb") as file_handle:
                raw_staple = file_handle.read()
        except (IOError, OSError):
            # Can't access the staple file, game over.
            LOG.error("Can't access %s, let's schedule a renewal.", ocsp_file)
            return False
        # For some reason there are reports that haproxy will not accept staples
        # from with the `set ssl ocsp-response [data]` command if a staple file
        # did not already exist at start-up, an empty file seems to fix that.
        # https://www.mail-archive.com/haproxy@formilux.org/msg24750.html
        if not raw_staple:
            LOG.info("Staple %s is empty, schedule a renewal.", ocsp_file)
            return False
        # Parse the staple
        staple = asn1crypto.ocsp.OCSPResponse.load(raw_staple)
        staple = OCSPResponseParser(staple)
        now = datetime.datetime.now()
        until = staple.valid_until
        if staple.status != "good" or until <= now:
            LOG.debug("Staple has expired %s", self.filename)
            return False
        try:
            self._validate_cert(raw_staple)
            LOG.info(
                "Staple %s expires %s, we can still use it.",
                ocsp_file,
                staple.valid_until.strftime('%Y-%m-%d %H:%M:%S')
            )
        except CertValidationError:
            # Staple can't be validated, this is ok, we will just
            # ignore the existing staple and replace it by a new one
            # ASAP.
            return False

        # A valid staple file exists, let's asign it to the model.
        self.ocsp_staple = staple

        # Now check whether a renewal is still preferred due to it
        # almost expiring.
        sched_time = datetime.timedelta(seconds=minimum_validity)
        if until - sched_time < now:
            # It will expire soon
            return False
        # Existing staple is just fine, no action needed now, do still
        # schedule a regular renewal before expiry!
        return True

    def renew_ocsp_staple(self):
        """
        Renew the OCSP staple, validate it and save it to the file path of the
        certificate file (``certificate.pem.ocsp``).

        .. Note:: This method handles a lot of exceptions, some of then are
            non-fatal and might lead to retries. When they are fatal,
            one of the exceptions documented below is raised. Exceptions are
            handled by the :meth:`stapled.core.excepthandler.stapled_except_handle`
            context.

        .. Note:: There can be several OCSP URLs. When the first URL fails,
            the error handler will increase the ``url_index`` and schedule a
            new renewal until all URLS have been tried, then continues with
            retries from the first again.

        :raises RenewalRequirementMissing: A requirment for the renewal is
            missing.
        :raises OCSPBadResponse: Response is empty, invalid or the status is
            not "good".
        :raises urllib.error.URLError: An OCSP url can't be opened (Python3).
        :raises: urllib.error.URLError - when a URL/HTTP error
            occurs
        :raises:
            socket.error - when a socket error occurs

        .. TODO:: Send merge request to ocspbuider, for setting the hostname in
            the headers while fetching OCSP records. If accepted the request
            library won't be needed anymore.
        """
        if not self.end_entity:
            raise RenewalRequirementMissing(
                "Certificate is missing in \"{}\", can't validate "
                "without it.".format(self.filename)
            )
        if len(self.chain) < 1:
            raise RenewalRequirementMissing(
                "Certificate chain is missing in \"{}\", can't validate "
                "without it.".format(self.filename)
            )

        url = self.ocsp_urls[self.url_index]
        LOG.debug("Trying to get OCSP staple from url \"%s\"..", url)
        ocsp_staple = certvalidator.ocsp_client.fetch(
            self.end_entity,
            self.chain[-2],
            hash_algo=u'sha1',
            nonce=True,
            timeout=10
        )
        self.ocsp_staple = self._check_ocsp_response(ocsp_staple, url)

        # If we got this far it means we have a staple in self.ocsp_staple
        # We would have had an exception otherwise. So let's verify that the
        # staple is actually working before serving it to clients.
        # To do this we run the validation again, this time self.ocsp_staple
        # will be taken into account because it is no longer None
        # If validation fails, it will raise an exception that should be
        # handled at another level.
        LOG.debug("Validating staple..")
        self._validate_cert(self.ocsp_staple.raw)
        # No exception was raised, so we can assume the staple is ok and write
        # it to disk.
        ocsp_filename = "{}.ocsp".format(self.filename)
        LOG.info("Succesfully validated writing to file \"%s\"", ocsp_filename)
        with open(ocsp_filename, 'wb') as f_obj:
            f_obj.write(self.ocsp_staple.raw.dump())
        return True

    def _check_ocsp_response(self, ocsp_staple, url):
        """
        Check that the OCSP response says that the status is ``good``. Also
        sets :attr:`stapled.core.certmodel.CertModel.ocsp_staple.valid_until`.

        :raises OCSPBadResponse: If an empty response is received.
        """
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "Response data: \n%s",
                pretty_base64(ocsp_staple.dump(), line_len=75, prefix=" "*36)
            )
        if ocsp_staple == b'':
            raise OCSPBadResponse(
                "Received empty response from {} for {}".format(
                    url,
                    self.filename
                )
            )
        parsed_staple = OCSPResponseParser(ocsp_staple)
        status = parsed_staple.status
        if status == 'good':
            LOG.info(
                "Received good response from OCSP server %s for %s, "
                "valid until: %s",
                url,
                self.filename,
                parsed_staple.valid_until.strftime('%Y-%m-%d %H:%M:%S')
            )
            return parsed_staple
        elif status == 'revoked':
            raise OCSPBadResponse(
                "Certificate {} was revoked!".format(self.filename)
            )
        else:
            raise OCSPBadResponse(
                "Can't get status for {} from {}",
                self.filename,
                url
            )
        return None

    def _read_full_chain(self):
        """
        Parses binary data in :attr:`self.crt_data` and parses the content.
        The server certificate a.k.a. *end_entity* is put in
        :attr:`self.end_entity`, anything else that has a CA extension is added
        to :attr:`self.intermediates`.

        .. Note:: At this point it is not clear yet which of the intermediates
            is the root and which are actual intermediates.

        :raises CertParsingError: If the certificate file can't be read, it
            contains errors or parts of the chain are missing.
        """
        try:
            pem_obj = asn1crypto.pem.unarmor(self.crt_data, multiple=True)
            for type_name, _, der_bytes in pem_obj:
                if type_name == 'CERTIFICATE':
                    crt = asn1crypto.x509.Certificate.load(der_bytes)
                    if getattr(crt, 'ca'):
                        LOG.debug("Found part of the chain..")
                        self.intermediates.append(crt)
                    else:
                        LOG.debug("Found the end entity..")
                        self.end_entity = crt
                        self.ocsp_urls = getattr(crt, 'ocsp_urls')
        except (binascii.Error, ValueError):
            raise CertParsingError(
                "Certificate file contains errors \"{}\".".format(
                    self.filename
                )
            )
        if len(self.intermediates) < 1:
            raise CertParsingError(
                "Can't find the CA certificate chain items in \"{}\".".format(
                    self.filename
                ),
                log_level=logging.CRITICAL
            )
        if self.end_entity is None:
            # If we did find some CA stuff but not a server certicate, we
            # assume this is a CA root/intermediate file and don't log a
            # critical error.
            if self.intermediates:
                raise CertParsingError(
                    "Can't find server certificate items for \"{}\". "
                    "Assuming this is a root or intermediate "
                    "certificate.".format(
                        self.filename,
                    ),
                    log_level=logging.INFO
                )
            else:
                raise CertParsingError(
                    "Can't find server certificate items for \"{}\".".format(
                        self.filename,
                    ),
                    log_level=logging.CRITICAL
                )


    def _validate_cert(self, ocsp_staple=None):
        """
        Validates the certificate and its chain, including the OCSP staple if
        there is one in :attr:`self.ocsp_staple`.

        :param asn1crypto.core.Sequence ocsp_staple: Binary ocsp staple data.
        :return array: Validated certificate chain.
        :raises CertValidationError: If there is any problem with the
            certificate chain and/or the staple, e.g. certificate is revoked,
            chain is incomplete or invalid (i.e. wrong intermediate with
            server certificate), certificate is simply invalid, etc.

        .. Note:: At this point it becomes known what the role of the
            certiticates in the chain is. With the exception of the root, which
            is usually not kept with the intermediates and the certificate
            because ever client has its own copy of it.
        """
        try:
            if ocsp_staple is None:
                LOG.debug("Validating without OCSP staple.")
                context = certvalidator.ValidationContext()
            else:
                LOG.debug("Validating with OCSP staple.")
                context = certvalidator.ValidationContext(
                    ocsps=[ocsp_staple],
                    allow_fetching=False
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
            if ocsp_staple is None:
                LOG.debug(
                    "Certificate chain for \"%s\" validated.",
                    self.filename
                )
            else:
                LOG.info(
                    "Certificate chain and staple for \"%s\" validated.",
                    self.filename
                )
            return chain
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
        except (
                certvalidator.errors.PathBuildingError,
                certvalidator.errors.PathValidationError):
            raise CertValidationError(
                "Failed to validate certificate path for \"{}\", will not "
                "try to parse it again.".format(self.filename)
            )

    def __repr__(self):
        """
        We return the file name here because this way we can use it as a
        short-cut when we assign this object to something.
        """
        return self.filename

    def __str__(self):
        """
        Return a formatted string representation of the object containing:
        ``"<CertModel {}>".format("".join(self.filename))``
        so it's clear it's an object and which file it concerns.
        """
        return "<CertModel {}>".format("".join(self.filename))
