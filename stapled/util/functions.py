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


def unique(seq, preserve_order=True):
    """
    Return the unique values of a sequence in the type of the input sequence.

    Does not support sets and dicts, as they are already unique.

    :param list|tuple seq: Data to return unique values from.
    :param bool preserve_order: Preserve order of seq? (Default: True)
    :returns list|tuple: Whatever unique values you fed into ``seq``.
    """
    if preserve_order:
        return type(seq)(unique_generator(seq))

    if isinstance(seq, (set, dict)):
        # Should not do this, this is wasting CPU cycles.
        raise TypeError("{} types are always unique".format(type(seq)))

    # If order is not important we can do set() which is a C implementation
    # and it's super fast. Return a new sequence of the same type with
    # unique values
    return type(seq)(set(seq))


def unique_generator(seq):
    """
    Remove duplicates from an iterable sequence.

    Keep a list of values we see, check to see if an item was already seen.
    Optionally preserve order.

    Does not support sets and dicts, as they are already unique.

    :param list|tuple seq: Data to yield unique values from.
    :yields object: Whatever unique values you fed into ``seq``.
    """

    if isinstance(seq, (set, dict)):
        # Should not do this, this is wasting CPU cycles.
        raise TypeError("{} types are always unique".format(type(seq)))

    return __unique_generator(seq)


def __unique_generator(seq):
    """
    See unique_generator function documentation.
    """
    seen = set()
    seen_add = seen.add  # Speeds up, it skips __getattribute__ on seen.
    for element in seq:
        if element not in seen:
            yield element
            seen_add(element)


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

    :param collections.Sequence|str files: A list of strings or string with
        HAProxy config file path to parse.
    :return tuple: Tuple containing paths (list) and corresponding sockets.
    """
    PAT_SOCKET = re.compile(
        r'^\s*stats.*socket\s+(?P<socks>[\'"]{1}.*?[\'"]{1}|(\\ |[^\s])*)'
    )
    # Note multiple paths are possible.
    PAT_CRT = re.compile(r'^\s*bind.*?crt.*$')
    # paths can contain a-Z, 0-9, -, _, . and spaces escaped by \
    PAT_CRT = re.compile(r'bind.*crt\s+([^\s]|(?<!\\) )*')
    PAT_CRT_BASE = re.compile(
        r'^\s*crt-base\s+(?P<path>[\'"]{1}.*?[\'"]{1}|(\\ |[^\s])*)'
    )
    # Extract a crt directive, anything in quotes, valid paths, escaped spaces.
    PAT_EXTRACT_CRT = re.compile(
        r'^(?P<path>[\'"]{1}.*?[\'"]{1}|(\\ |[^\s])*)'
    )

    find_words = {
        'stats': PAT_SOCKET,
        'crt': PAT_CRT,
        'crt-base': PAT_CRT_BASE
    }

    paths = []
    sockets = []

    if not isinstance(files, (list, tuple, set)):
        files = [files]

    for config_file in files:
        rel_path = os.path.dirname(config_file)
        # Make a dictionary with the keys of find_words corresponding with
        # empty array as a place holder.
        relevant_lines = dict([(word, []) for word in find_words.keys()])
        # Now locate the relevant lines in this file and keep the found
        # pattern matches.
        with open(config_file, 'r') as config:
            for line in config:
                # Skip comment lines..
                if line.strip().startswith('#'):
                    continue
                for word, pattern in find_words.items():
                    if "{} ".format(word) in line:
                        match = pattern.match(line)
                        if match is not None:
                            # Sometimes we can use the already determined match
                            # but for the `bind [..] crt` lines there a simple
                            # match is not sufficient so we keep the line too.
                            keep = {'line': line, 'match': match}
                            relevant_lines[word].append(keep)

        # Assume we find no socket to prevent bad offsets
        socket = None
        # For relative paths a crt-base directive could be set but we have to
        # assume here it has not been set.
        base = ''
        # Multiple crt directives per line are possible as well as on multiple
        # lines to we reset the list at the beginning of analysing a file.
        crts = []
        # Iterate over the results and try to find out if a crt-base is set
        # `crt` directives depend on that value so we need to find it first.
        for word, matches in relevant_lines.items():
            # In order to allow relative paths to the certificate paths we need
            # to first find out if there is a crt-base directive specified.
            # This is also one of the reasons why the finding and parsing of
            # lines isn't done at the same time.
            # crt-base can only be set once.
            if word == 'crt-base' and matches:
                match = matches[0]['match']
                base = match.group('path').strip()

        for word, matches in relevant_lines.items():
            if not matches:
                # This is an empty list, assess the next one.
                continue
            # Find the socket for the config of a process, we only support one
            # socket per process, the first one found will be used.
            if word == 'stats':
                match = matches[0]['match']
                socket = match.group('socks').strip()
                if not os.path.isabs(socket):
                    socket = os.path.join(rel_path, socket)

            # Find a certificate path, we take all paths as long as there is
            # only one path per bind directive.
            if word == 'crt':
                # TODO: It is possible to add the crt argument more than once
                # for 1 bind directive, we need to find all paths in the crt
                # arguments. We need them for all bind directives and we need
                # to de-duplicate them.
                for match in matches:
                    line = match['line']
                    parts = line.split('crt ')[1:]
                    for part in parts:
                        crt = PAT_EXTRACT_CRT.match(part)
                        crt = crt.group('path').strip("\"'")
                        if not os.path.isabs(crt):
                            crt = os.path.join(base, crt)
                        crt = crt.replace("\ ", " ")
                        crts.append(crt)
        crts = unique(crts)
        paths.append(crts)
        sockets.append(socket)
    return (paths, sockets)
