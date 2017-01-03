import os
import time
import logging
import hashlib

LOG = logging.getLogger()


class CertFile(object):
    """
        Model for certificate files.
    """
    def __init__(self, filename):
        """
            Initialise the CertFile model object.
        """
        self.filename = None
        self.hash = self.hashfile(filename)
        self.modtime = self.file_modification_time(filename)

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
        except IOError(exception):
            # Catch to log the error and re-raise to handle at the appropriate
            # level
            LOG.error("Can't access file %s", filename)
            raise exception
        return sha1.hexdigest()

    def __repr__(self):
        """
            When we refer to this object without calling a method or specifying
            an attribute we want to get the file name returned.
        """
        return self.filename


class ParsedCertFile(object):
    """
        Parses and holds parsed certificates.
    """

    def __init__(self, crt_file):
        """
            Initialise the parsed certificate model and parse the certificate.
            :param CertFile crt_file:
        """
        self.filename = crt_file
        LOG.info("Parsing cert file \"%s\".", crt_file)
        with open(crt_file, 'rb') as cert_obj:
            self.raw_data = cert_obj.read()
        LOG.debug("Trying to parse certificate: \"%s\"", crt_file)

        self.time_parsed = time.time()

        # TODO: fill in these variables
        self.ocsps_data = None
        self.parsed_data = None
        self.not_before = None
        self.not_after = None
        self.oscp_staple_not_after = None

    def set_ocsp_staple_data(self, ocsp_data):
        self._set_ocsp_staple_file(ocsp_data)

    def _set_ocsp_staple_file(self, ocsp_staple_data):
        with open("{}{}".format(self.filename, '.oscp'), 'wb') as ocsp_file:
            ocsp_file.write(ocsp_staple_data)
