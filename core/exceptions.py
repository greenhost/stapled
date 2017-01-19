"""
This module holds the application specific exceptions.
"""


class OCSPBadResponse(Exception):
    """
    Gets raised when a OCSP staple is not valid.
    """
    pass


class RenewalRequirementMissing(Exception):
    """
    Gets raised when a OCSP renewal is run while not all requirements are met.
    """
    pass


class CertFileAccessError(Exception):
    """
    Gets raised when a file can't be accessed at all.
    """
    pass


class CertParsingError(Exception):
    """
    Gets raised when something went wrong while parsing the certificate file.
    """
    pass


class CertValidationError(Exception):
    """
    Gets raised when something went wrong while validating the certificate
    chain.

    .. Note: This may or may not include an OCSP staple.
    """
    pass
