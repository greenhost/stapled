# -*- coding: utf-8 -*-
"""
ANSI colourise the logging stream (works on LINUX/UNIX based systems).

*Constants for colours*:

:attr const BLACK: Black
:attr const RED: Red
:attr const GREEN: Green
:attr const YELLOW: Yellow
:attr const BLUE: Blue
:attr const CYAN: Cyan
:attr const WHITE: White
"""

import logging
import string
import re

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)


class ColourFormatter(logging.Formatter):
    """
    ANSI colourise the logging stream (works on LINUX/UNIX based systems).
    """

    FMT_PATTERN = re.compile(
        r'\{(?:(?P<escaped>\{)|'
        r'(?P<named>[_a-z][_a-z0-9]*)\}|'
        r'(?P<braced>[_a-z][_a-z0-9]*)\}|'
        r'(?P<invalid>))'
    )

    # pylint: disable=line-too-long
    def __init__(self, *args, **kwargs):
        """
        Initialise some variables for colourising.

        Make cache dict for formats, backup original format string, initialise
        the parent log formatter.

        :param tuple *args: Positional arguments that should be passed to the
            parent formatter.
        :param dict **kwargs: Keyword arguments that should be passed to the
            parent formatter. Two keywords are taken from this dict, see below.

        :keyword dict colours: A dictionary containing the colour schemes to be
            used by the logger, see below for more information.
        :keyword bool no_colour_nl: Tell the logger not to colour anything
            after a new line character.

        There is a default colour scheme with 2 colour indexes. You can use
        these colour schemes as follows:

        .. code-block:: python

            formatter = ColourFormatter(
                "{lvl}[%(levelname)s]{reset} {msg}(name)s %(message)s"
            )

        Note the `{lvl}` and `{msg}` variables are used as template strings in
        the format string. Also note there is a `{reset}` variable, use this
        before any *change* in colour, it is automatically added at the end of
        the string to prevent the terminal from printing coloured strings after
        the log line was printed.

        You can also make custom colour schemes and pass them as a keyword
        argument (`colours`) when instantiating a ColourFormatter object.

        The colours dictionary that can be passed to the
        :class:`~ColourFormatter` is formatted as follows.

        .. code-block:: python

            {
                'lvl': {
                    logging.DEBUG: (WHITE, BLUE, False),
                    logging.INFO: (BLACK, GREEN, False),
                    logging.WARNING: (BLACK, YELLOW, False),
                    logging.ERROR: (WHITE, RED, False),
                    logging.CRITICAL: (YELLOW, RED, True),
                },
                'msg': {
                    logging.DEBUG: (BLUE, None, False),
                    logging.INFO: (GREEN, None, False),
                    logging.WARNING: (YELLOW, None, False),
                    logging.ERROR: (RED, None, False),
                    logging.CRITICAL: (RED, None, True),
                }
            }

        The dictionary contains indexes followed by the log levels, followed by
        a tuple in the form of foreground colour, background coloUr, bold face.

        The colour schemes above are the default colours, they colour the
        `%(levelname)s` in colour scheme `lvl`, which adds background colours
        as well as foreground colours. The rest of message is can be formatted
        using the `msg` scheme, which does not add any background colours but
        does add foreground colours.

        The `lvl` and `msg` indexes specify colour schemes. You can make your
        own indexes, indexes can have arbitrary names but should be formatted
        be `a-zA-Z0-9-_` and start with `a-zA-Z`. To make use of your colour
        scheme you need to change your format string. Like this:

        .. code-block:: python

            import logging
            logger = logging.getLogger(__name__)
            logger.setLevel(level=logging.DEBUG)
            handler = logging.StreamHandler()
            handler.setFormatter(
                ColourFormatter(
                    "{lvl}[%(levelname)s]{reset} {msg}%(name)s %(message)s"
                )
            )
            logger.addHandler(handler)
            logger.debug("This is detailed information..")
            logger.info("This somewhat more useful..")
            logger.warning("This might be dangerous..")
            logger.error("Something might have gone a bit wrong")
            logger.critical("Woah! do something!!")

        .. code-block:: bash

            \\x1b[44;37m[DEBUG]\\x1b[0m \\x1b[34m__main__ This is detailed information..\\x1b[0m
            \\x1b[42;30m[INFO]\\x1b[0m \\x1b[32m__main__ This somewhat more useful..\\x1b[0m
            \\x1b[43;30m[WARNING]\\x1b[0m \\x1b[33m__main__ This might be dangerous..\\x1b[0m
            \\x1b[41;37m[ERROR]\\x1b[0m \\x1b[31m__main__ Something might have gone a bit wrong\\x1b[0m
            \\x1b[41;33;1m[CRITICAL]\\x1b[0m \\x1b[31;1m__main__ Woah! do something!!\\x1b[0m
        """
        # pylint: enable=line-too-long
        self._colour_fmts = {}
        self.colourbox = _Colourbox(**kwargs)
        self.no_colour_nl = kwargs.pop('no_colour_nl', False)
        if self.no_colour_nl:
            self.strip_ansi_colour = re.compile(r'\x1b\[([0-9]{1,2};?)*m')
        super(ColourFormatter, self).__init__(*args, **kwargs)
        if not self._fmt.endswith("{reset}"):
            self._fmt += "{reset}"
        self.format_str = self._fmt

    def format(self, record):
        """
        Override the normal format method to swap out the format string,
        then call the parent format method.

        :param object record: The log record.
        """
        self.colourbox.set_level(record.levelno)
        formatted = super(ColourFormatter, self).format(record)
        fmt = string.Template(formatted)
        fmt.pattern = self.FMT_PATTERN
        formatted = fmt.safe_substitute(self.colourbox)
        if self.no_colour_nl and '\n' in formatted:
            split = formatted.split('\n', 1)
            split[0] += "\x1b[0m\n"
            split[1] = self.strip_ansi_colour.sub('', split[1])
            formatted = ''.join(split)
        return formatted


class _Colourbox(object):
    """
        Helper class that is passed the colour scheme and returns forms an
        object that can be passed to the
        :method:`string.Template().safe_substitute` method to return colours
        per scheme.

        The scheme is set by setting the level with :method:`~set_level` before
        asking for the colours.
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, **kwargs):
        """
            Initialise the _Colourbox helper class.

            :params dict kwargs: Optional keyword arguments.

            :keyword dict colours: The colour scheme dictionary as documented
                in  :class:`~ColourFormatter`
        """
        # Log levels (foreground, background, bold)
        self.colours = kwargs.pop('colours', {
            'lvl': {
                logging.DEBUG: (WHITE, BLUE, False),
                logging.INFO: (BLACK, GREEN, False),
                logging.WARNING: (BLACK, YELLOW, False),
                logging.ERROR: (WHITE, RED, False),
                logging.CRITICAL: (YELLOW, RED, True),
            },
            'msg': {
                logging.DEBUG: (BLUE, None, False),
                logging.INFO: (GREEN, None, False),
                logging.WARNING: (YELLOW, None, False),
                logging.ERROR: (RED, None, False),
                logging.CRITICAL: (RED, None, True),
            }
        })
        self.level = logging.DEBUG

    def set_level(self, level=logging.DEBUG):
        """
            Set the log level of the ColourBox object.

            :param int level: The logging log level.
        """
        self.level = level

    def __getitem__(self, attr):
        """
            Return the colour for the attribute and the current level
            (e.g. `msg`).

            :param str attr: Attribute that specifies the colourscheme's index.
        """
        if attr == 'reset':
            return "\x1b[0m"
        elif attr in self.colours:
            foreground, background, bold = self.colours[attr][self.level]
            props = []
            if background is not None:
                props.append(str(background + 40))
            if foreground is not None:
                props.append(str(foreground + 30))
            if bold:
                props.append('1')
            if props:
                colour = "\x1b[%sm" % ';'.join(props)
                return colour
        return None
