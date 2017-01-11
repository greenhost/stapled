"""
This module bootstraps the ocspd process by starting threads for:

 - 1x :class:`core.certfinder.CertFinderThread`

        - Finds certificate files in the specified directories at regular
          intervals.
        - Queues new or changed certificates in the
          :any:`core.daemon.run.parse_queue` for parsing.
        - Removes deleted certificates from the central cache in
          :any:`core.daemon.run.contexts`.

 - 1x :class:`core.certparser.CertParserThreaded`

        - Parses certificates queued in :any:`core.daemon.run.contexts`.
        - Caches the parsed certificates in :any:`core.daemon.run.contexts`.
        - Add the parsed certificate to the :any:`core.daemon.run.renew_queue`
          for requesting or renewing the OCSP staple.

 - 2x (or more depending on the ``-t`` CLI argument)
   :class:`core.ocsprenewer.OCSPRenewerThreaded`

        - Gets renewal tasks from :any:`core.daemon.run.renew_queue`.
        - Validates the certificate chains.
        - Renews the OCSP staples.
        - Validates the certificate chains again but this time including the
          OCSP staple.
        - Writes the OCSP staple to disk.
        - Schedules a renewal at a configurable time before the expiration of
          the OCSP staple.

    The main reason for spawning multiple threads for this is that the request
    is a blocking action that also takes relatively long to complete. If any of
    these request stall for long, the entire daemon doesn't stop working until
    it is no longer stalled.

"""

import queue
import logging
from core import certfinder
from core import ocsprenewer
from core import certparser
from core import scheduler

LOG = logging.getLogger()

QUEUE_MAX_SIZE_PARSE = 0  # 0 = unlimited
QUEUE_MAX_SIZE_RENEW = 0  # 0 = unlimited
QUEUE_MAX_SIZE_SCHED = 0  # 0 = unlimited


def run(args):
    """
    Creates queues and spawns the threads documented above.
    Threads are not started as daemons so this will run indefinitely unless the
    entire process is halted or all threads are killed.

    :param argparse.Namespace args: Parsed CLI arguments
    """
    LOG.debug("Started with CLI args: %s", str(args))

    #: A queue of found/modified certificates that need to be parsed.
    parse_queue = queue.Queue(QUEUE_MAX_SIZE_PARSE)

    #: A queue of parsed certificates that can be used for ocsp requests.
    renew_queue = queue.Queue(QUEUE_MAX_SIZE_RENEW)

    #: A queue for actions that need to be run at a later point in time, e.g.
    #: renewal of ocsp staples
    sched_queue = queue.Queue(QUEUE_MAX_SIZE_SCHED)

    directories = args.directories
    file_extensions = args.file_extensions.replace(" ", "").split(",")
    renewal_threads = args.renewal_threads
    refresh_interval = args.refresh_interval
    ignore_list = []
    contexts = {}

    LOG.info(
        "Starting OCSP Stapling daemon, finding files of types: %s with "
        "%d threads.",
        ", ".join(file_extensions),
        renewal_threads
    )

    # Start ocsp response gathering threads
    threads_list = []
    for tid in range(0, renewal_threads):
        thread = ocsprenewer.OCSPRenewerThreaded(
            cli_args=args,
            renew_queue=renew_queue,
            ignore_list=ignore_list,
            contexts=contexts,
            sched_queue=sched_queue,
            tid=tid
        )
        threads_list.append(thread)

    # Start certificate parsing thread
    # For some reason you can't start multiple parser threads because of
    # some issue with an underlying crypto library that will start throwing
    # exceptions: TODO: figure out wtf..
    certparser.CertParserThreaded(
        cli_args=args,
        directories=directories,
        parse_queue=parse_queue,
        renew_queue=renew_queue,
        sched_queue=sched_queue
    )

    # Start certificate finding thread
    certfinder.CertFinderThreaded(
        cli_args=args,
        directories=directories,
        parse_queue=parse_queue,
        refresh_interval=refresh_interval,
        file_extensions=file_extensions,
        ignore_list=ignore_list,
        sched_queue=sched_queue,
        contexts=contexts
    )

    # Scheduler thread
    scheduler.SchedulerThreaded(
        cli_args=args,
        ignore_list=ignore_list,
        sched_queue=sched_queue,
        renew_queue=renew_queue,
    )
