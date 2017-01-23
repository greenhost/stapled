"""
This module bootstraps the ocspd process by starting threads for:

- 1x :class:`core.scheduling.SchedulerThread`

  Can be used to create action queues that where tasks can be added that are
  either added to the action queue immediately or at a set time in the future.

- 1x :class:`core.certfinder.CertFinderThread`

  - Finds certificate files in the specified directories at regular intervals.
  - Removes deleted certificates from the context cache in
    :attr:`core.daemon.run.models`.
  - Add the found certificate to the the parse action queue of the scheduler
    for parsing the certificate file.

- 1x :class:`core.certparser.CertParserThread`

  - Parses certificates and caches parsed certificates in
    :attr:`core.daemon.run.models`.
  - Add the parsed certificate to the the renew action queue of the scheduler
    for requesting or renewing the OCSP staple.

- 2x (or more depending on the ``-t`` CLI argument)
  :class:`core.ocsprenewer.OCSPRenewerThread`

  - Gets tasks from the scheduler in :attr:`self.scheduler` which is a
    :class:`core.scheduling.Scheduler` object passed by this module.
  - For each task:
     - Validates the certificate chains.
     - Renews the OCSP staples.
     - Validates the certificate chains again but this time including the OCSP
       staple.
     - Writes the OCSP staple to disk.
     - Schedules a renewal at a configurable time before the expiration of the
       OCSP staple.

  The main reason for spawning multiple threads for this is that the OCSP
  request is a blocking action that also takes relatively long to complete.
  If any of these request stall for long, the entire daemon doesn't stop
  working until it is no longer stalled.

- 1x :class:`core.ocspadder.OCSPAdder` **(optional)**

  Takes tasks ``haproxy-add`` from the scheduler and communicates OCSP staples
  updates to HAProxy through a HAProxy socket.

"""
import logging
from core import certfinder
from core import certparser
from core import ocsprenewer
from core import ocspadder
import scheduling

LOG = logging.getLogger(__name__)


def run(args):
    """
    Creates queues and spawns the threads documented above.
    Threads are not started as daemons so this will run indefinitely unless the
    entire process is halted or all threads are killed.

    :param argparse.Namespace args: Parsed CLI arguments
    """
    LOG.debug("Started with CLI args: %s", str(args))
    directories = args.directories
    sockets = args.haproxy_sockets
    socket_paths = None
    if sockets:
        if len(directories) != len(sockets):
            raise ValueError("#sockets does not equal #directories")
        # Make a mapping from directory to socket
        socket_paths = dict(zip(directories, sockets))
    file_extensions = args.file_extensions.replace(" ", "").split(",")
    renewal_threads = args.renewal_threads
    refresh_interval = args.refresh_interval
    model_cache = {}

    LOG.info(
        "Starting OCSP Stapling daemon, finding files of types: %s with "
        "%d threads.",
        ", ".join(file_extensions),
        renewal_threads
    )

    # Scheduler thread
    scheduler = scheduling.SchedulerThread(
        queues=["parse", "renew", "proxy-add"]
    )
    scheduler.daemon = False
    scheduler.name = "scheduler"
    scheduler.start()

    if socket_paths:
        proxy_adder = ocspadder.OCSPAdder(
            socket_paths=socket_paths,
            scheduler=scheduler
        )
        proxy_adder.name = 'proxy-adder'
        proxy_adder.start()

    # Start ocsp response gathering threads
    threads_list = []
    for tid in range(0, renewal_threads):
        thread = ocsprenewer.OCSPRenewerThread(
            minimum_validity=args.minimum_validity,
            scheduler=scheduler
        )
        thread.daemon = False
        thread.name = "renewer-{:02d}".format(tid)
        thread.start()
        threads_list.append(thread)

    # Start certificate parser thread
    parser = certparser.CertParserThread(
        models=model_cache,
        minimum_validity=args.minimum_validity,
        scheduler=scheduler
    )
    parser.daemon = False
    parser.name = "parser"
    parser.start()

    # Start certificate finding thread
    finder = certfinder.CertFinderThread(
        models=model_cache,
        directories=directories,
        refresh_interval=refresh_interval,
        file_extensions=file_extensions,
        scheduler=scheduler
    )
    finder.daemon = False
    finder.name = "finder"
    finder.start()
