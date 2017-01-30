# -*- coding: utf-8 -*-
"""
This class contains utilities for all things OCSP related.
"""
from builtins import str
import datetime
import asn1crypto


class OCSPResponseParser(object):
    """
    Simpler wrapper for OCSP responses, with shortcuts to most used data.
    """
    def __init__(self, ocsp_data=None):
        """
        Initialise an `asn1crypto.ocsp.OCSPResponse` object in self._response.
        Don't try to make this an extension of `asn1crypto.ocsp.OCSPResponse`
        because it will complain about missing arguments.
        """
        self.data = ocsp_data
        response = asn1crypto.ocsp.OCSPResponse.load(ocsp_data)
        self.response = getattr(response, 'response_data')
        # SingleResponse object should be in these keys
        self.tbsresponse = self.response['responses'][0]

    @property
    def status(self):
        """
        Short-cut for the ocsp staple status
        :returns str: "good", "revoked", "invalid" or "unknown"
        """
        return self.tbsresponse['cert_status'].name

    @property
    def valid_from_raw(self):
        """
        Short-cut for the raw valid_from field.
        :returns str: Date from which the staple is valid: YYYYMMDDHHmmssZ
        """
        return self.tbsresponse['this_update']

    @property
    def valid_until_raw(self):
        """
        Short-cut for the raw valid_until field.
        :returns str: Date until which the staple is valid: YYYYMMDDHHmmssZ
        """
        return self.tbsresponse['next_update']

    @property
    def valid_from(self):
        """
        Short-cut for the parsed valid_from field.
        :returns datetime.datetime: Date from which the staple is valid.
        """
        return datetime.datetime.strptime(
            str(self.tbsresponse['this_update']),
            "%Y%m%d%H%M%SZ"
        )

    @property
    def valid_until(self):
        """
        Short-cut for the parsed valid_until field.
        :returns datetime.datetime: Date until which the staple is valid.
        """
        return datetime.datetime.strptime(
            str(self.tbsresponse['next_update']),
            "%Y%m%d%H%M%SZ"
        )
