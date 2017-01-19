"""
This module holds the application specific exceptions.
"""


class CertValidationError(Exception):
    """
    Gets raised when something went wrong while validating the certificate
    chain.

    .. Note: This may or may not include an OCSP staple.
    """
    pass


class OCSPRenewError(BaseException):
    """
    Gets raised when something went wrong while renewing the OCSP staple.
    """
    pass
