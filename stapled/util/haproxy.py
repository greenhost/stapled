"""
This module holds a class that can parse HAProxy files.

The end result may not be 100% one-on-one compatible with HAProxy's own way of
parsing but it should come close.

Parse HAProxy config files and return tuples of cert paths and sockets.

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

And finds ``crt-base`` in case the path in the bind directive is
relative.

.. code-block::

    crt-base

Where applicable, if a path is a file, not a directory, it will be
reduced to the nearest directory.

If more than one socket is specified in the config file we will only
use the first one.
"""
import re
import os
from stapled.util.functions import unique


class HAProxyParser(object):
    """Parse a HAProxy config file and extract cert paths and socket paths."""

    #: Matches a path pattern, only `a-Z, 0-9, -_/\.`, quoted strings with the
    #: same pattern but allowing spaces too, and non-quoted patterns with the
    #: same content and escaped spaces, e.g.:
    #: - /etc/ssl/private
    #: - "/etc/ssl/let's encrypt"
    #: - '/etc/ssl/lets encrypt'
    #: - /etc/ssl/lets\ encrypt
    #: It follows the rules of the HAProxy configuration format, allowing
    #: strong and weak quoting, i.e.: backslashes are literal when in single
    #: quote, but are escape characters in double quotes.
    PATH_PATTERN = (
        r'('
        r'([\"])([\w.\\/ \-\']*)\2'  # Matches weakly quoted paths
        r'|([\'])([\w.\\/ \-\']*)\4'  # Matches strongly quotes paths
        r'|([\w.\-/\']|\\ )'  # Matches unquoted paths (escaped spaces too)
        r'*)'
    )

    #: Remove backslashes from escaped characters.
    PAT_UNESCAPE = re.compile(r'\\(.)')

    # We will try to find the following directives with the same path pattern
    # every time.
    # Don't change ``crt`` to ``bind``, it should match the ``server`` And
    # ``default-server`` directives too!
    FIND_WORDS = {
        'stats': re.compile(r'socket\s+' + PATH_PATTERN),
        'crt': re.compile(r'crt\s+' + PATH_PATTERN),
        'crt-base': re.compile(r'crt-base\s+' + PATH_PATTERN)
    }

    def __init__(self, conf_files):
        """
        Initialise ``self.config_files`` variable.

        :param collections.Sequence|str conf_files: A list of strings or string
             with HAProxy config file path to parse.
        """
        if isinstance(conf_files, str):
            self.conf_files = (conf_files,)
        else:
            self.conf_files = conf_files
        self._parse()

    def parse(self):
        """
        Initialise the parsing process.

        :return tuple: Tuple containing paths (list) and corresponding sockets.
        """
        return (self.cert_paths, self.socket_paths)

    def _parse(self):
        """Start the parsing process, populates the object."""
        self.cert_paths = []
        self.socket_paths = []
        for conf_file in self.conf_files:
            # Get relevant lines from all config files.
            relevant_lines = self._parse_relevant_lines(conf_file)
            # Parse all sockets from the relevant lines.
            self.socket_paths.append(
                self._parse_haproxy_sockets(relevant_lines['stats'])
            )
            # Find out if a crt-base is set. `crt` directives depend on that
            # value so we need to find it first. We assume crt-base can only be
            # set once.
            cert_base = self._parse_haproxy_cert_base(
                relevant_lines['crt-base']
            )
            self.cert_paths.append(
                self._parse_haproxy_cert_paths(
                    relevant_lines['crt'],
                    cert_base
                )
            )

    @classmethod
    def _parse_relevant_lines(cls, conf_file_path):
        """
        Parse config file, return dict of relevant lines per directive.

        Only the directives in ``FIND_WORDS`` are parsed.

        :param str conf_file_path: HAProxy config file path
        """
        # Make a dictionary with the keys of find_words corresponding with
        # empty array as a place holder.
        relevant_lines = dict([(word, []) for word in cls.FIND_WORDS.keys()])
        # Now locate the relevant lines in this file and keep the found
        # pattern matches.
        with open(conf_file_path, 'r') as config:
            for line in config:
                # Strip whitespaces
                line = line.strip(" \t")
                # Skip comment lines..
                if line.startswith('#'):
                    continue
                for word, pattern in cls.FIND_WORDS.items():
                    if "{} ".format(word) not in line:
                        continue
                    matches = pattern.findall(line)
                    if matches:
                        # We only need the first capturing group.
                        matches = [match[0].strip(" \t") for match in matches]
                        # We will only need the matched strings later on.
                        relevant_lines[word] += matches
        return relevant_lines

    @staticmethod
    def _parse_haproxy_sockets(socket_lines):
        """
        Find the sockets in the HAProxy configuration file.

        We assume all sockets should be informed of new staples for any of the
        cert paths we find. If paths are not absolute we assume they are
        relative to the config's directory.
        :param list socket_lines: Lines that concern sockets.
        :returns list: Socket paths.
        """
        # The list returned below may be empty (``[]``).
        # de-dupe and return the sockets
        return unique(socket_lines)

    @staticmethod
    def _parse_haproxy_cert_base(cert_base_lines):
        """
        Find out if there is a ``crt-base`` directive and what the value is.

        :param list cert_base_lines: Lines that concern crt-base directives.
        :returns str: A crt-base path if set, or an empty string.
        """
        cert_base = ''
        if cert_base_lines:
            cert_base = cert_base_lines[0]
        return cert_base

    @classmethod
    def _parse_haproxy_cert_paths(cls, cert_paths_lines, cert_base):
        """
        Find certificate paths in the relevant lines.

        We take all paths from all bind, server and default-server directives.

        :param list cert_paths_lines: Lines that concern cert paths.
        :param str cert_base: The directory that relative paths relate to.
        :returns list: Cert paths.
        """
        abs_cert_paths = []
        for path in cert_paths_lines:
            if path.startswith("'"):
                # Strong quoted, only remove quotes.
                path = path.strip("'")
            else:
                # Weak, or not quoted, remove quotes and unescape spaces.
                path = cls.PAT_UNESCAPE.sub("\\1", path.strip('"'))
            if not os.path.isabs(path):
                path = os.path.join(cert_base, path)
            abs_cert_paths.append(path)
            # de-dupe the cert paths
            abs_cert_paths = unique(abs_cert_paths)
        return abs_cert_paths


def parse_haproxy_config(conf_files):
    """For usage info see HAProxyParser.__init__ docstring."""
    return HAProxyParser(conf_files).parse()


# Carbon copy of the docstring of the init function of the HAProxyParser to
# parse_haproxy_config
parse_haproxy_config.__doc__ = HAProxyParser.__init__.__doc__
