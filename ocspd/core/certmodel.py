# -*- coding: utf-8 -*-
"""
This module defines the :class:`ocspd.core.certmodel.CertModel` class which is
used to keep track of certificates that are found by the
:class:`ocspd.core.certfinder.CertFinderThread`, then parsed by the
:class:`ocspd.core.certparser.CertParserThread`, an OCSP request is generated
by the :class:`ocspd.core.ocsprenewer.OCSPRenewer`, a response from an OCSP
server is returned. All data generated and returned like the request and the
response are stored in the context.

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
import requests
import certvalidator
import ocspbuilder
import asn1crypto
from oscrypto import asymmetric
from ocspd.core.exceptions import CertFileAccessError
from ocspd.core.exceptions import OCSPBadResponse
from ocspd.core.exceptions import RenewalRequirementMissing
from ocspd.core.exceptions import CertParsingError
from ocspd.core.exceptions import CertValidationError
from ocspd.util.ocsp import OCSPResponseParser
from ocspd.util.functions import pretty_base64
from ocspd.util.cache import cache
from future.standard_library import hooks
with hooks():
    from urllib.parse import urlparse

LOG = logging.getLogger(__name__)


class CertModel(object):
    """
    Model for certificate files.
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self, filename):
        """
        Initialise the CertModel model object, and read the certificate data
        from the passed filename.

        :raises ocspd.core.exceptions.CertFileAccessError: When the certificate
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
        try:
            with open(filename, 'rb') as f_obj:
                self.crt_data = f_obj.read()
        except (IOError, OSError) as exc:
            raise CertFileAccessError(
                "Can't access file %s, reason: %s", filename, exc)

    def parse_crt_file(self):
        """
        Parse certificate, wraps the
        :meth:`~ocspd.core.certmodel.CertModel._read_full_chain()` and the
        :meth:`~ocspd.core.certmodel.CertModel._validate_cert()` methods.
        Wicth extract the certificate (*end_entity*) and the chain
        intermediates*), and validates the certificate chain.
        """
        LOG.info("Parsing file \"%s\"..", self.filename)
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
            LOG.info(
                "File does not exist yet: %s, need to request a staple.",
                ocsp_file
            )
            return False

        try:
            LOG.info("Seeing if %s is still valid..", ocsp_file)
            with open(ocsp_file, "rb") as file_handle:
                staple = file_handle.read()
        except (IOError, OSError):
            # Can't access the staple file, game over.
            LOG.error("Can't access %s, let's schedule a renewal.", ocsp_file)
            return False

        staple = OCSPResponseParser(staple)
        now = datetime.datetime.now()
        until = staple.valid_until
        if staple.status != "good" or until <= now:
            LOG.info("Staple has expired %s", self.filename)
            return False
        try:
            self._validate_cert(staple)
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
            handled by the :meth:`ocspd.core.excepthandler.ocsp_except_handle`
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
        :raises urllib2.URLError: An OCSP url can't be opened (Python2).
        :raises requests.Timeout: When data doesn't reach us within the
            expected time frame.
        :raises requests.exceptions.ConnectTimeout: A connection can't be
            established because the server doesn't reply within the expected
            time frame.
        :raises requests.exceptions.ReadTimeout: Data didn't reach us within
            the expected time frame.
        :raises requests.exceptions.TooManyRedirects: The OCSP server redirects
            us too many times.
        :raises requests.exceptions.HTTPError: A HTTP error code was returned.
        :raises requests.ConnectionError: A Connection error occurred.

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
        host = urlparse(url).hostname
        LOG.info("Trying to get OCSP staple from url \"%s\"..", url)
        request = requests.post(
            url,
            data=bytes(self.ocsp_request),
            # Set 'Host' header because Let's Encrypt server might not
            # react when it's absent
            headers={
                'Content-Type': 'application/ocsp-request',
                'Accept': 'application/ocsp-response',
                'Host': host
            },
            timeout=(10, 5)
        )
        # Raise HTTP exception if any occurred
        request.raise_for_status()

        ocsp_staple = request.content
        self.ocsp_staple = self._check_ocsp_response(ocsp_staple, url)

        # If we got this far it means we have a staple in self.ocsp_staple
        # We would have had an exception otherwise. So let's verify that the
        # staple is actually working before serving it to clients.
        # To do this we run the validation again, this time self.ocsp_staple
        # will be taken into account because it is no longer None
        # If validation fails, it will raise an exception that should be
        # handled at another level.
        LOG.info("Validating staple..")
        self._validate_cert(self.ocsp_staple)
        # No exception was raised, so we can assume the staple is ok and write
        # it to disk.
        ocsp_filename = "{}.ocsp".format(self.filename)
        LOG.info("Succesfully validated writing to file \"%s\"", ocsp_filename)
        with open(ocsp_filename, 'wb') as f_obj:
            f_obj.write(ocsp_staple)
        return True

    def _check_ocsp_response(self, ocsp_staple, url):
        """
        Check that the OCSP response says that the status is ``good``. Also
        sets :attr:`ocspd.core.certmodel.CertModel.ocsp_staple.valid_until`.

        :raises OCSPBadResponse: If an empty response is received.
        """
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "Response data: \n%s",
                pretty_base64(ocsp_staple, line_len=75, prefix=" "*36)
            )
        if ocsp_staple == b'':
            raise OCSPBadResponse(
                "Received empty response from {} for {}".format(
                    url,
                    self.filename
                )
            )
        ocsp_staple = OCSPResponseParser(ocsp_staple)
        status = ocsp_staple.status
        if status == 'good':
            LOG.info(
                "Received good response from OCSP server %s for %s, "
                "valid until: %s",
                url,
                self.filename,
                ocsp_staple.valid_until.strftime('%Y-%m-%d %H:%M:%S')
            )
            return ocsp_staple
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
                        LOG.info("Found part of the chain..")
                        self.intermediates.append(crt)
                    else:
                        LOG.info("Found the end entity..")
                        self.end_entity = crt
                        self.ocsp_urls = getattr(crt, 'ocsp_urls')
        except binascii.Error:
            raise CertParsingError(
                "Certificate file contains errors \"{}\".".format(
                    self.filename
                )
            )
        if self.end_entity is None:
            raise CertParsingError(
                "Can't find server certificate items for \"{}\".".format(
                    self.filename
                )
            )
        if len(self.intermediates) < 1:
            raise CertParsingError(
                "Can't find the CA certificate chain items in \"{}\".".format(
                    self.filename
                )
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
                LOG.info("Validating without OCSP staple.")
                context = certvalidator.ValidationContext()
            else:
                LOG.info("Validating with OCSP staple.")
                context = certvalidator.ValidationContext(
                    ocsps=[ocsp_staple.data],
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
            LOG.info("Certificate chain for \"%s\" validated.", self.filename)
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

    @property
    @cache(None)
    def ocsp_request(self):
        """
        Generate an OCSP request or return an already cached request.

        :return bytes: A binary representation of a
            :class:`asn1crypto.ocsp.OCSPRequest` which is in turn represented
            by a :class:`asn1crypto.core.Sequence`.
        """
        ocsp_request_builder = ocspbuilder.OCSPRequestBuilder(
            asymmetric.load_certificate(self.end_entity),
            asymmetric.load_certificate(self.chain[-2])
        )
        ocsp_request_builder.nonce = False
        ocsp_request = ocsp_request_builder.build().dump()
        # This data can be posted to the OCSP URI to debug further
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "Request data: \n%s",
                pretty_base64(ocsp_request, line_len=75, prefix=" "*36)
            )
        return ocsp_request

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
