# -*- coding: utf-8 -*-
"""
Just a module containing some useful auxiliary functions.
"""

import binascii


def pretty_base64(data, line_len=79, prefix="", suffix="\n"):
    """
    Format data as a base64 blob with fixed line lengths and pre-/suffixes.
    Splits the base64 data into lines of ``line_len`` lines and can apply
    a prefix such as ``\n\t`` to align output.

    :param (bytes, bytearray) data: Data to format.
    :param int line_len: Maximum length of the returned lines.
    :return str: Formatted string.
    """
    b64_data = base64(data)
    b64_data = split_by_len(b64_data, line_len)
    b64_data = "".join(["{}{}{}".format(prefix, x, suffix) for x in b64_data])
    return b64_data.strip("\n")


def base64(data):
    """
    Get base64 string (1 line) from binary "data".

    :param (bytes, bytearray) data: Data to format.
    :raises TypeError: Raises an error if the data is not a bytearray of bytes
        instance
    :return str: Empty string if this failed, otherwise the base64 encoded
        string.
    """
    if isinstance(data, (bytearray, bytes)):
        b64_data = binascii.b2a_base64(data).decode('ascii')
    else:
        raise TypeError('Data passed to base64 function is of the wrong type')

    # Remove any new lines and carriage returns
    b64_data.replace("\n", "").replace("\r", "")
    return b64_data.strip("\n")


def split_by_len(string, length):
    """
    Split a string into an array of strings of max length ``len``.

    Last line will be whatever is remaining if there aren't exactly enough
    characters for all full lines.

    :param str string: String to split.
    :len int length: Max length of the lines.
    :return list: List of substrings of input string
    """
    return [string[i:i+length] for i in range(0, len(string), length)]
