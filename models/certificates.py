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
        self.filename = filename
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
        except IOError as err:
            # Catch to log the error and re-raise to handle at the appropriate
            # level
            LOG.error("Can't access file %s", filename)
            raise err
        return sha1.hexdigest()

    def __repr__(self):
        """
            When we refer to this object without calling a method or specifying
            an attribute we want to get the file name returned.
        """
        return self.filename

