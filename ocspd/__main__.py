#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This is the module that parses your command line arguments and then starts
the OCSP Staple daemon, which searches your certificate directories and
requests staples for all certificates in them. They will then be saved as
``certificatename.pem.ocsp`` in the same directories that are being indexed.

Type ``ocsp.py -h`` for all command line arguments.

This module parses the command line arguments and detaches the process
from the user's context if ``-d`` (daemon mode) is specified, then spawns a
bunch of threads for:

 - Finding certificates in the given directories.
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
:mod:`ocspd.core.daemon`
module to bootstrap the application.
"""
import configargparse
import logging
import logging.handlers
import os
import daemon
import ocspd
import ocspd.core.daemon
import ocspd.core.excepthandler
from ocspd.colourlog import ColourFormatter

#: :attr:`logging.format` format string for log files and syslog
LOGFORMAT = '[%(levelname)s] %(threadName)+10s/%(name)-16.20s %(message)s'
#: :attr:`logging.format` format string for stdout
COLOUR_LOGFORMAT = (
    '{lvl}[%(levelname)s]{reset} {msg}%(threadName)+10s/%(name)-16.20s '
    '%(message)s{reset}'
)


def get_cli_arg_parser():
    """
    Make a CLI argument parser and return it. It does not parse the arguments
    because a plain parser object is used for documentation purposes.

    :return: Argument parser with all of ocspd's options configured
    :rtype: argparse.ArgumentParser
    """
    parser = configargparse.ArgParser(
        default_config_files=ocspd.DEFAULT_CONFIG_FILE_LOCATIONS,
        description=(
            "Update OCSP staples from CA\'s and store the result so "
            "HAProxy can serve them to clients.\n"
        ),
        conflict_handler='resolve',
        epilog=(
            "The daemon will not serve OCSP responses, it can however "
            "inform HAPRoxy about the staples it creates using the "
            "``--haproxy-sockets.`` argument. Alternatively you can configure"
            "HAPRoxy or another proxy (e.g. nginx has support for serving "
            "OCSP staples) to serve the OCSP staples manually."
        )
    )
    parser.add(
        '-c',
        '--config',
        required=False,
        is_config_file=True,
        help=(
            "Override the default config file locations "
            "(default={})".format(
                ", ".join(ocspd.DEFAULT_CONFIG_FILE_LOCATIONS)
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
            "Verbose output argument should be an integer between 0 and 4, can"
            "be overridden by the ``-v`` argument."
        )
    )
    parser.add(
        '-v',
        action='count',
        dest="verbose",
        help=(
            "Verbose output, repeat to increase verbosity, overrides the "
            "``verbosity`` argument if provided "
        )
    )
    parser.add(
        '-D',
        '--daemon',
        action='store_true',
        help=(
            "Daemonise the process, release from shell and process group, run "
            "under new process group."
        )
    )
    parser.add(
        '--file-extensions',
        type=str,
        default=ocspd.FILE_EXTENSIONS_DEFAULT,
        help=(
            "Files with which extensions should be scanned? Comma separated "
            "list (default: crt,pem,cer)"
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
        const=ocspd.LOG_DIR,
        help=("Enable logging to '{}'. It is possible to supply "
              "another directory. Traces of unexpected exceptions are placed "
              "here as well.".format(ocspd.LOG_DIR))
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
        help="Don't print messages to stdout"
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
            "``/etc/haproxy2/haproxy.sock``. I would then start ocspd as "
            "follows:"
            "``./ocspd /etc/haproxy1 /etc/haproxy2 -s /etc/haproxy1.sock "
            "/etc/haproxy2.sock``"
        )
    )
    parser.add(
        '-d',
        '--directories',
        required=True,
        type=str,
        nargs='+',
        help=(
            "Directories containing the certificates used by HAProxy. "
            "Multiple directories may be specified separated by a space. "
        )
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
            "Multiple paths may be specified separated by a space. "
            "You can escape the pattern to let the daemon evaluate it "
            "instead of letting your shell evaluate it. You can use globbing "
            "patterns with ``*`` or ``?``. Relative paths are also allowed."
            "If the path starts with ``/`` it will be considered absolute if "
            "it does not, the pattern will be compared to the last part of "
            "found files."
        )
    )

    return parser


def init():
    """
    Configures logging and log level, then calls
    :func:`ocspd.core.daemon.run()` either in daemonised mode if the ``-d``
    argument was supplied, or in the current context if ``-d`` wasn't supplied.
    """
    log_file_handles = []
    parser = get_cli_arg_parser()
    args = parser.parse_args()
    args.directories = [os.path.abspath(d) for d in args.directories]
    verbose = args.verbose or args.verbosity
    log_level = max(min(50 - verbose * 10, 50), 10)
    logging.basicConfig()
    logger = logging.getLogger('ocspd')
    logger.propagate = False
    # Don't allow dependencies to log anything but fatal errors
    logging.getLogger("requests").setLevel(logging.FATAL)
    logging.getLogger("urllib3").setLevel(logging.FATAL)
    logger.setLevel(level=log_level)
    if not args.quiet and not args.daemon:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(ColourFormatter(COLOUR_LOGFORMAT))
        logger.addHandler(console_handler)
    if args.logdir:
        file_handler = logging.FileHandler(
            os.path.join(args.logdir, 'ocspd.log'))
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(LOGFORMAT))
        logger.addHandler(file_handler)
        log_file_handles.append(file_handler.stream)
        ocspd.core.excepthandler.LOG_DIR = args.logdir
    if args.syslog:
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
        syslog_handler.setLevel(log_level)
        syslog_handler.setFormatter(logging.Formatter(LOGFORMAT))
        logger.addHandler(syslog_handler)
    if args.daemon:
        logger.info("Daemonising now..")
        with daemon.DaemonContext(files_preserve=log_file_handles):
            ocspd.core.daemon.OCSPDaemon(args)
    else:
        logger.info("Running interactively..")
        ocspd.core.daemon.OCSPDaemon(args)

if __name__ == '__main__':
    init()
