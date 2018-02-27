# -*- coding: utf-8 -*-
"""
Just a module containing some useful auxiliary functions.
"""

import binascii
import re
import os


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


def parse_haproxy_config(files):
    """
    Parse HAProxy config files and return a tuple of paths and sockets found.

    Parse the an array of HAProxy files and determine the paths to the
    certificate files and the path to the socket of the HAProxy instance.

    Looks for patterns of:

    .. code-block::

        stats socket [path] *

    e.g.:

    .. code-block::

        stats socket /run/haproxy/admin.sock mode 660 level admin

    And for lines that contain a pattern like:

    .. code-block::

        bind * crt [path(s)] *

    And finds ``crt-base`` in case the path in the bind directive is relative.

    .. code-block::

        crt-base

    Where applicable, if a path is a file, not a directory, it will be reduced
    to the nearest directory.

    If more than one socket is specified in the config file we will only use
    the first one.

    :param collections.Sequence files: A list of HAProxy files to parse.
    :return tuple: Tuple containing paths (list) and corresponding sockets.
    """
    PAT_SOCKET = re.compile(r'^\s*stats\s*socket\s*(?P<socks>.*?)\s?.*$')
    # Note multiple paths are possible.
    PAT_CRT = re.compile(r'^\s*bind.*?crt.*$')
    # paths can contain a-Z, 0-9, -, _, . and spaces escaped by \
    PAT_CRT = re.compile(
        r'crt\s*(([\'"]{1}([\w-.\\\\/ ]*)[\'"]{1})|(([\w-./]|\\\\ )*))'
    )
    PAT_CRT_BASE = re.compile(r'^\s*crt-base.*?crt\s*(?P<path>.*?)\s?$')

    find_words = {
        'stats': PAT_SOCKET,
        'crt': PAT_CRT,
        'crt-base': PAT_CRT_BASE
    }

    paths = []
    sockets = []

    for config_file in files:
        rel_path = os.path.dirname(config_file)
        # Make a dictionary with the keys of find_words corresponding with
        # empty arrays as placeholders.
        relevant_lines = dict([(word, []) for word in find_words.keys()])
        # Now locate the relevant lines in this file and keep the found
        # pattern matches.
        with open(config_file, 'r') as config:
            for line in config:
                for word, pattern in find_words.items():
                    if word in line:
                        match = pattern.match(line)
                        if match is not None:
                            relevant_lines[word].append(match)

        for word, matches in relevant_lines.items():
            # Find the socket for the config of a process, we only support one
            # socket per process, the first one found will be used.
            # The socket must be an existing file and it should be accesible
            # by the user that stapled is running as.
            if word == 'stats':
                match = matches[0]
                socket = match.group('socks').strip()
                if not os.path.isabs(socket):
                    socket = os.path.join(rel_path, socket)
                if not os.path.isfile(socket):
                    raise FileNotFoundError(
                        "Socket {} can't be found, does it exist?"
                    )
                if not os.access(socket, os.R_OK | os.W_OK):
                    raise PermissionError(
                        "Socket {} can't be opened, check permissions."
                    )
                sockets.append(socket)

            # In order to allow relative paths to the certificate paths we need
            # to first find out if there is a crt-base directive specified.
            # This is also one of the reasons why the finding and parsing of
            # lines isn't done at the same time.
            # crt-base can only be set once.
            base = ''
            if word == 'crt-base':
                match = matches[0]
                base = match.group('path').strip()

            # Find a certificate path, we take all paths as long as there is
            # only one path per bind directive, if the path is a file the
            # file name will be truncated to the dir name of the file.
            cert_paths = []
            if word == 'crt':
                for match in matches:
                    cert_paths = match.group('paths')

                    cert_path = match.group('paths').strip()
                    if not os.path.isabs(socket):
                        cert_path = os.path.join(base, cert_path)
                    cert_paths.append(cert_path)
        paths.append(cert_paths)
    return (paths, sockets)
