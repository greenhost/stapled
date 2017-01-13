"""
Just a module containing some useful auxiliary functions.
"""

import binascii
import os
import hashlib

def pretty_base64(data, line_len=79, prefix="", suffix="\n"):
    """
    Format data as a base64 blob with fixed line lengths and pre-/suffixes.
    Splits the base64 data into lines of ``line_len`` lines and can apply
    a prefix such as ``\n\t`` to align output.

    :param (bytes, bytearray, str) data: Data to format.
    :param int line_len: Maximum length of the returned lines.
    :param (bytes, bytearray, str) data: Data to format.
    :param (bytes, bytearray, str) data: Data to format.
    :return str: Formatted string.
    """
    if isinstance(data, (bytearray, bytes)):
        b64_data = binascii.b2a_base64(data).decode('ascii')

    # Remove any new lines and carriage returns
    b64_data.replace("\n", "").replace("\r", "")
    b64_data = split_by_len(b64_data, line_len)
    b64_data = "".join(["{}{}{}".format(prefix, x, suffix) for x in b64_data])
    return b64_data.strip("\n")


def split_by_len(string, length):
    """
    Split a string into an array of strings of max length ``len``.

    Last line will be whatever is remaining if there aren't exactly enough
    characters for all full lines.

    :param str string: String to split.
    :len int length: Max length of the lines.
    """
    return [string[i:i+length] for i in range(0, len(string), length)]


def file_hexdigest(filename):
    """
    Return the SHA1 hash of the binary file contents.

    """
    sha1 = hashlib.sha1()
    with open(filename, 'rb') as f_obj:
        sha1.update(f_obj.read())
    return sha1.hexdigest()
