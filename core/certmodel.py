"""
This module defines the :class:`core.certmodel.CertModel` class which is
used to keep track of certificates that were found, parsed and validated by the
:class:`core.certfinder.CertFinder`, which add the context to a scheduled so
the :class:`core.ocsprenewer.OCSPRenewer` can generate a request for an OCSP
staple, and get a response from an OCSP server. Both the request and the
response are then stored in the context.

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
import urllib
import time
import datetime
import requests
import certvalidator
import ocspbuilder
import asn1crypto
import ocspd
from oscrypto import asymmetric
from core.exceptions import CertValidationError
from core.exceptions import OCSPRenewError
from util.ocsp import OCSPResponseParser
from util.functions import pretty_base64
from util.functions import file_hexdigest
from util.cache import cache

LOG = logging.getLogger()


class CertModel(object):
    """
    Model for certificate files.
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self, filename):
        """
        Initialise the CertModel model object, extract the certificate
        (*end_entity*) and the chain (*intermediates*). Validates the
        certificate chain.

        :raises core.exceptions.CertValidationError: When the certificate
            chain is invalid.
        """
        self.filename = filename
        try:
            self.hash = file_hexdigest(filename)
        except IOError as err:
            # Catch to log the error and re-raise to handle at the appropriate
            # level
            LOG.error("Can't access file %s", filename)
            raise err

        self.modtime = os.path.getmtime(filename)
        self.end_entity = None
        self.intermediates = []
        self.ocsp_staple = None
        self.ocsp_urls = []
        self.chain = []
        try:
            self._read_full_chain()
            self.chain = self._validate_cert()
        except TypeError:
            raise CertValidationError(
                "Can't validate the certificate because part of the "
                "certificate chain is missing in \"{}\"".format(self.filename)
            )

    def recycle_staple(self, minimum_validity):
        """
        Try to find an existing staple that is still valid for more than the
        ``minimum_validity`` period. If it is not valid for longer than the
        ``minimum_validity`` period, but still valid, add it to the context but
        still ask for a new one by returning ``False``.

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
                staple = OCSPResponseParser(staple)
                now = datetime.datetime.now()
                until = staple.valid_until
                if staple.status != "good" or until <= now:
                    LOG.info("Staple has expired %s", self.filename)
                    return False
                self._validate_cert(staple)
                LOG.info(
                    "Staple %s expires %s, we can still use it.",
                    ocsp_file,
                    staple.valid_until.strftime('%Y-%m-%d %H:%M:%S')
                )
                before_sched_time = datetime.timedelta(
                    seconds=minimum_validity)
                self.ocsp_staple = staple
                if until - before_sched_time > now:
                    return True
                return False
        except IOError:
            LOG.error("Can't access %s, let's schedule a renewal.", ocsp_file)
            return False

    def renew_ocsp_staple(self, url_index=0):
        """
        Renew the OCSP staple, validate it and save it to the file path of the
        certificate file (``certificate.pem.ocsp``).

        .. Note:: This method handles a lot of exceptions, some of then are
            non-fatal and might lead to retries. When they are fatal, a log
            message of level :const:`logging.logLevel.ERROR` is written and an
            one of the exceptions documented below is raised. This makes error
            handling at higher levels easier.

        :param int url_index: There can be several OCSP URLs. When the
            first URL fails, this function calls itself with the index of
            the next.

        :raises CertValidationError: when there is no end_entity or certificate
            chain is missing.
        :raises OCSPRenewError: when the ocsp staple is an empty byte string,
            or when the certificate was revoked, or when all URLs fail.
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
        LOG.info(
            "Trying to get OCSP staple from url \"%s\"..",
            url
        )
        retry = ocspd.OCSP_REQUEST_RETRY_COUNT
        while retry > 0:
            try:
                # TODO: send merge request for header in ocsp fetching
                request = requests.post(
                    url,
                    data=self.ocsp_request,
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
            except urllib.error.URLError as err:
                LOG.error("Connection problem: %s", err)
            except (requests.Timeout,
                    requests.exceptions.ConnectTimeout,
                    requests.exceptions.ReadTimeout) as err:
                LOG.warning("Timeout error for %s: %s", self.filename, err)
            except requests.exceptions.TooManyRedirects as err:
                LOG.warning(
                    "Too many redirects for %s: %s", self.filename, err)
            except requests.exceptions.HTTPError as err:
                LOG.warning(
                    "Received bad HTTP status code %s from OCSP server %s for "
                    " %s: %s",
                    request.status,
                    url,
                    self.filename,
                    err
                )
            except (requests.ConnectionError,
                    requests.RequestException) as err:
                LOG.warning("Connection error for %s: %s", self.filename, err)

            ocsp_staple = request.content
            self.ocsp_staple = self._check_ocsp_response(ocsp_staple, url)
            if self.ocsp_staple:
                break  # out of retry loop

            retry = retry - 1
            if retry > 0:
                sleep_time = (ocspd.OCSP_REQUEST_RETRY_COUNT - retry) * 5
                LOG.info("Retrying in %d seconds..", sleep_time)
                time.sleep(sleep_time)
            else:
                if url_index + 1 < len(self.ocsp_urls):
                    return self.renew_ocsp_staple(url_index+1)
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
        self._validate_cert(self.ocsp_staple)
        # No exception was raised, so we can assume the staple is ok and write
        # it to disk.
        ocsp_filename = "{}.ocsp".format(self.filename)
        LOG.info(
            "Succesfully validated writing to file \"%s\"",
            ocsp_filename
        )
        with open(ocsp_filename, 'wb') as f_obj:
            f_obj.write(ocsp_staple)
        return True

    def _check_ocsp_response(self, ocsp_staple, url):
        """
            Check that the OCSP response says that the status is ``good``.
            Also sets :attr:`core.certmodel.CertModel.ocsp_staple.valid_until`.
        """
        if LOG.getEffectiveLevel() < 20:
            LOG.debug(
                "Response data: \n%s",
                pretty_base64(ocsp_staple, line_len=75, prefix="\t")
            )
        if ocsp_staple == b'':
            raise OCSPRenewError(
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
            raise OCSPRenewError(
                "Certificate {} was revoked!".format(self.filename)
            )
        else:
            LOG.info(
                "Can't get status for %s from %s",
                self.filename,
                url
            )
        return None

    def _read_full_chain(self):
        """
        Reads binary data from file in :attr:`self.filename` and parses the
        content. The server certificate a.k.a. *end_entity* is put in
        :attr:`self.end_entity`, anything else that has a CA extension is added
        to :attr:`self.intermediates`.

        .. Note:: At this point it is not clear yet which of the intermediates
            is the root and which are actual intermediates.

        If anything goes wrong the exceptions are handled and the call will
        fail silently, leading to exceptions being raised by any subsequent
        call to methods that require the values that this method should have
        set.
        """
        with open(self.filename, 'rb') as f_obj:
            pem_obj = asn1crypto.pem.unarmor(f_obj.read(), multiple=True)
        try:
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
    @cache
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
        if LOG.getEffectiveLevel() < 20:
            LOG.debug(
                "Request data: \n%s",
                pretty_base64(ocsp_request, line_len=75, prefix="\t")
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
