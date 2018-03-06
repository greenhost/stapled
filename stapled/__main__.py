#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This is the module that parses your command line arguments and then starts
the OCSP Staple daemon, which searches your certificate paths and
requests staples for all certificates in them. They will then be saved as
``certificatename.pem.ocsp`` in the same paths that are being indexed.

Type ``stapled.py -h`` for all command line arguments.

This module parses the command line arguments and detaches the process
from the user's context if ``-d`` (daemon mode) is specified, then spawns a
bunch of threads for:

 - Finding certificates in the given paths.
 - Parsing certificate files and determining validity, then requesting a
   staple if valid.
 - Renewing staples for certificates from the queue. This process requires
   a connection to the CA of that issued the certificate and is blocking. It
   is therefore heavily threaded. This is also the only process you can
   select the amount of threads for with a command line argument.
 - Optionally, a thread for adding the gathered OCSP staples to a running
   HAProxy instance through a HAProxy socket.
 - Scheduling tasks: parsing, renewing, adding staples to HAProxy.

If the ``-d`` argument is specified, this module is responsible for starting
the application in daemonised mode, and disconnecting the process from the
user's process hierarchy node. In any case, it starts up the
:mod:`stapled.core.daemon`
module to bootstrap the application.
"""
import configargparse
import logging
import logging.handlers
import os
import daemon
import stapled
import stapled.core.daemon
import stapled.core.excepthandler
from stapled.util.haproxy import parse_haproxy_config
from stapled.colourlog import ColourFormatter
from stapled.version import __version__, __app_name__
from stapled.util.functions import unique

#: :attr:`logging.format` format string for log files and syslog
LOGFORMAT = (
    "%(asctime)s [%(levelname)s] %(threadName)+14s/%(name)-16.20s"
    "%(message)s"
)
#: :attr:`logging.format` format string for stdout
COLOUR_LOGFORMAT = (
    "{msg}%(asctime)s{reset} {lvl}[%(levelname)s]{reset} "
    "{msg}%(threadName)+14s/%(name)-16.20s %(message)s{reset}"
)

TIMESTAMP_FORMAT = "%b %d %H:%M:%S"

logger = logging.getLogger('stapled')


def get_cli_arg_parser():
    """
    Make a CLI argument parser and return it.

    It does not parse the arguments because a plain parser object is used for
    documentation purposes.

    :return: Argument parser with all of stapled's options configured
    :rtype: argparse.ArgumentParser
    """
    parser = configargparse.ArgParser(
        default_config_files=stapled.DEFAULT_CONFIG_FILE_LOCATIONS,
        description=(
            "Update OCSP staples from CA\'s and store the result so "
            "HAProxy can serve them to clients.\n"
        ),
        conflict_handler='resolve',
        epilog=(
            "The daemon will not serve OCSP responses, it can however "
            "inform HAPRoxy about the staples it creates using the "
            "``--haproxy-sockets.`` argument. Alternatively you can configure "
            "HAPRoxy or another proxy (e.g. nginx has support for serving "
            "OCSP staples) to serve the OCSP staples manually."
        ),
        prog=__app_name__
    )
    parser.add(
        '-c',
        '--config',
        required=False,
        is_config_file=True,
        help=(
            "Override the default config file locations "
            "(default={})".format(
                ", ".join(stapled.DEFAULT_CONFIG_FILE_LOCATIONS)
            )
        )
    )
    parser.add(
        '--minimum-validity',
        type=int,
        default=7200,
        help=(
            "If the staple is valid for less than this time in seconds an "
            "attempt will be made to get a new, valid staple (default: 7200)."
        )
    )
    parser.add(
        '-t',
        '--renewal-threads',
        type=int,
        default=2,
        help="Amount of threads to run for renewing staples. (default=2)"
    )
    parser.add(
        '--verbosity',
        type=int,
        default=0,
        help=(
            "Verbose output argument should be an integer between 0 and 4, "
            "can be overridden by the ``-v`` argument."
        )
    )
    parser.add(
        '-v',
        action='count',
        dest="verbose",
        help=(
            "Verbose output, repeat to increase verbosity, overrides the "
            "``verbosity`` argument if provided."
        )
    )
    parser.add(
        '-D',
        '--daemon',
        action='store_true',
        default=False,
        help=(
            "Daemonise the process, release from shell and process group, run "
            "under new process group."
        )
    )
    parser.add(
        '--interactive',
        '--no-daemon',
        action='store_false',
        dest='daemon',
        help=(
            "Disable daemon mode, overrides daemon mode if enabled in the "
            "config file, effectively starting interactive mode."
        )
    )
    parser.add(
        '--file-extensions',
        type=str,
        default=stapled.FILE_EXTENSIONS_DEFAULT,
        help=(
            "Files with which extensions should be scanned? Comma separated "
            "list (default: crt,pem,cer)."
        )
    )
    parser.add(
        '-r',
        '--refresh-interval',
        type=int,
        default=60,
        help="Minimum time to wait between parsing cert dirs and "
        "certificates (default=60)."
    )
    parser.add(
        '-l',
        '--logdir',
        type=str,
        nargs='?',
        default=None,
        const=stapled.LOG_DIR,
        help=("Enable logging to '{}'. It is possible to supply "
              "another directory. Traces of unexpected exceptions are placed "
              "here as well.".format(stapled.LOG_DIR))
    )
    parser.add(
        '--syslog',
        action='store_true',
        default=False,
        help="Output to syslog."
    )
    parser.add(
        '-q',
        '--quiet',
        action='store_true',
        help="Don't print messages to stdout."
    )
    parser.add(
        '-s',
        '--haproxy-sockets',
        type=str,
        nargs='+',
        help=(
            "Sockets to connect to HAProxy. Each directory you pass with "
            "the ``directory`` argument, should have its own haproxy socket. "
            "The order of the socket arguments should match the order of the "
            "directory arguments."
            "Example:"
            "I have a directory ``/etc/haproxy1`` with certificates, and a "
            "HAProxy that serves these certificates and has stats socket "
            "``/etc/haproxy1/haproxy.sock``. I have another directory "
            "``/etc/haproxy2`` with certificates and another haproxy instance "
            "that serves these and has stats socket "
            "``/etc/haproxy2/haproxy.sock``. I would then start stapled as "
            "follows:"
            "``./stapled /etc/haproxy1 /etc/haproxy2 -s /etc/haproxy1.sock "
            "/etc/haproxy2.sock``"
        )
    )
    parser.add(
        '--no-haproxy-sockets',
        action='store_false',
        dest='haproxy_sockets',
        help=(
            "Disable HAProxy sockets, overrides ``--haproxy-sockets`` if "
            "specified in the config file."
        )
    )
    parser.add(
        '--haproxy-config',
        type=str,
        nargs='+',
        default=[],
        help=(
            "Path(s) to HAProxy config files, they will be scanned for "
            "certificates, certificate directories and HAProxy admin sockets "
            "based on ``bind [..] crt [..]`` directives and ``stats [..] "
            "socket [..]`` directives, the ``crt-base`` directive is"
            "respected. Multiple config files may be specified separated by a "
            " space. See ``--haproxy-socket`` for more information."
        )
    )
    parser.add(
        '-p',
        '--cert-paths',
        default=[],
        type=str,
        nargs='+',
        help=(
            "Paths to certificates files or directories containing "
            "certificates used by HAProxy. Multiple paths may be specified "
            "separated by a space."
        )
    )
    parser.add(
        '-R',
        '--recursive',
        action='store_true',
        default=False,
        help="Recursively scan given paths."
    )
    parser.add(
        '--no-recycle',
        action='store_true',
        default=False,
        help="Don't re-use existing staples, force renewal."
    )
    parser.add(
        '-i',
        '--ignore',
        type=str,
        nargs='+',
        help=(
            "Ignore files matching this pattern. "
            "Multiple patterns may be specified separated by a space. "
            "You can put the pattern in quotes to let stapled evaluate it "
            "instead of letting your shell evaluate it. You can use globbing "
            "patterns with ``*`` or ``?``. If a pattern starts with ``/`` it "
            "will be considered absolute, if it does not start with a ``/``, "
            "the pattern will be compared to the last part of found files. "
            "e.g. the pattern ``cert/snakeoil.pem`` matches with path "
            "``/etc/ssl/cert/snakeoil.pem``. Don't define relative *paths* as "
            "patterns, paths are not patterns, e.g. ``../certs/*.pem`` will "
            "not cause pem files in a directory named ``certs``, one "
            "directory up from ``$PATH`` to be ignored. Instead your pattern "
            "will cause a warning and will be ignored."
        )
    )
    parser.add(
        '-V', '--version',
        action='version',
        version="%(app_name)s v%(version)s" % {
            'app_name': __app_name__, 'version': __version__
        },
        help="Show the version number and exit."
    )
    parser.add(
        '-d',
        '--directories',
        default=[],
        type=str,
        nargs='+',
        help=(
            "DEPRECATED, please see ``--cert-paths``."
        )
    )
    return parser


def init():
    """
    Initialise the application in interactive or daemon mode.

    Configures logging and log level, then calls
    :func:`stapled.core.daemon.run()` either in daemonised mode if the ``-d``
    argument was supplied, or in the current context if ``-d`` wasn't supplied.
    """
    parser = get_cli_arg_parser()
    args = parser.parse_args()
    log_file_handles = __init_logging(args)

    # Parse the cert_paths argument
    arg_cert_paths = __get_arg_cert_paths(args)
    # Parse haproxy_sockets argument.
    arg_sockets = __get_arg_haproxy_sockets(args)
    # Make a mapping from certificate paths to sockets in a dict.
    socket_mapping = dict(zip(arg_cert_paths, arg_sockets))

    # Parse HAProxy config files.
    conf_cert_paths, conf_sockets = parse_haproxy_config(args.haproxy_config)
    # Combine the socket and certificate paths of the arguments and config
    # files in the sockets dictionary.
    for i, paths in enumerate(conf_cert_paths):
        for path in paths:
            if path in socket_mapping:
                socket_mapping[path] = unique(
                    socket_mapping[path] + conf_sockets[i],
                    preserve_order=False
                )
            else:
                socket_mapping[path] = conf_sockets[i]

    logger.debug("Paths to socket mapping: %s", str(socket_mapping))

    # Determine if we need to start a stapleadder thread.
    if any(socket_mapping.values()):
        args.haproxy_sockets = socket_mapping
    else:
        args.haproxy_sockets = None

    # Now sockets' keys are the merged cert paths from arguments and haproxy
    # config files, de-duplicated.
    args.cert_paths = socket_mapping.keys()

    if stapled.LOCAL_LIB_MODE:
        logger.info("Running on local libs.")
    if args.daemon:
        logger.info("Daemonising now..")
        with daemon.DaemonContext(files_preserve=log_file_handles):
            stapled.core.daemon.Stapledaemon(args)
    else:
        logger.info("Running interactively..")
        stapled.core.daemon.Stapledaemon(args)


def __get_arg_haproxy_sockets(args):
    """
    Parse the haproxy_sockets argument.

    :param Namespace args: Argparser argument list.
    """
    if args.haproxy_sockets:
        if len(args.cert_paths) != len(args.haproxy_sockets):
            raise ValueError(
                "Number of sockets does not equal number of certificate paths."
            )
        # Get socket paths as an array or arrays of as absolute paths.
        return [[os.path.abspath(path)] for path in args.haproxy_sockets]
    # If no sockets are set we need to return an equal amount of empty arrays
    # to the amount of certificate paths.
    return [[]] * len(args.cert_paths)


def __get_arg_cert_paths(args):
    """
    Parse the cert_paths argument.

    :param Namespace args: Argparser argument list.
    """
    # Warn about deprecated arguments..
    if args.directories:
        logger.warn(
            "The directories argument is deprecated, please reconfigure "
            "stapled to --cert-paths instead."
        )
        if args.cert_paths:
            raise ValueError(
                "You mixed the deprecated --directories and the supported "
                "argument --cert-paths, this could lead to unforeseen "
                "consequences, please reconfigure stapled to --cert-paths only."
            )
        # Make stuff not break after an update.
        args.cert_paths = args.directories
    # Get certificate path arguments as absolute paths.
    return [os.path.abspath(path) for path in args.cert_paths]


def __init_logging(args):
    """
    Initialise the logging module.

    :param Namespace args: Argparser argument list.
    """
    log_file_handles = []
    verbose = args.verbose or args.verbosity
    log_level = max(min(50 - verbose * 10, 50), 10)
    logging.basicConfig()
    logger.propagate = False
    # Don't allow dependencies to log anything but fatal errors
    logging.getLogger("urllib3").setLevel(logging.FATAL)
    logger.setLevel(level=log_level)

    if not args.quiet and not args.daemon:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(
            ColourFormatter(COLOUR_LOGFORMAT, TIMESTAMP_FORMAT)
        )
        logger.addHandler(console_handler)
    if args.logdir:
        file_handler = logging.FileHandler(
            os.path.join(args.logdir, 'stapled.log'))
        file_handler.setLevel(log_level)
        file_handler.setFormatter(
            logging.Formatter(LOGFORMAT, TIMESTAMP_FORMAT)
        )
        logger.addHandler(file_handler)
        log_file_handles.append(file_handler.stream)
        stapled.core.excepthandler.LOG_DIR = args.logdir
    if args.syslog:
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
        syslog_handler.setLevel(log_level)
        syslog_handler.setFormatter(
            logging.Formatter(LOGFORMAT, TIMESTAMP_FORMAT)
        )
        logger.addHandler(syslog_handler)
    return log_file_handles


if __name__ == '__main__':
    try:
        init()
    except Exception as exc:
        logger = logging.getLogger('stapled')
        logger.critical(str(exc))
        raise exc
