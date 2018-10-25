# -*- coding: utf-8 -*-
"""
This module holds the application specific exceptions.
"""
from logging import CRITICAL


class OCSPBadResponse(Exception):
    """Raised when a OCSP staple is not valid."""

    pass


class RenewalRequirementMissing(Exception):
    """Raised when a OCSP renewal is run while not all requirements are met."""

    pass


class SocketError(Exception):
    """
    Raised by the :class:`StapleAdder` when it is impossible to connect to or
    use its socket.
    """

    pass


class StapleAdderBadResponse(Exception):
    """Raised when HAProxy does not respond with "OCSP Response updated"."""

    pass


class CertFileAccessError(Exception):
    """Raised when a file can't be accessed at all."""

    pass


class CertParsingError(Exception):
    """Raised when something went wrong while parsing the certificate file."""

    def __init__(self, msg, *args, **kwargs):
        """
        Add a critical flag to init.

        :param str msg: Exception message.
        :kwarg log_level: Python logging log level, default: logging.CRITICAL
        """
        self.log_level = kwargs.pop('log_level', CRITICAL)
        super(CertParsingError, self).__init__(msg, *args, **kwargs)


class CertValidationError(Exception):
    """
    Raised when validation the certificate chain fails.

    .. Note: This may or may not include an OCSP staple.
    """

    pass


class ArgumentError(Exception):
    """
    Raised when a command line argument has an invalid value.
    """
    pass
