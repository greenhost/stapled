"""
This module bootstraps the ocspd process by starting threads for:

  - 1x :class:`core.scheduling.SchedulerThread`

        Can be used to create action queues that where tasks can be added that
        are either added to the action queue immediately or at a set time in
        the future.

 - 1x :class:`core.certfinder.CertFinderThread`

        - Finds certificate files in the specified directories at regular
          intervals.
        - Removes deleted certificates from the object's cache in
          :any:`core.certfinder.CertFinder.contexts`.
        - Parses certificates queued in
          :any:`core.certfinder.CertFinder.contexts`.
        - Caches the parsed certificates in
          :any:`core.certfinder.CertFinder.contexts`.
        - Add the parsed certificate to the the renew action queue of the
          scheduler for requesting or renewing the OCSP staple.

 - 2x (or more depending on the ``-t`` CLI argument)
   :class:`core.ocsprenewer.OCSPRenewerThreaded`

        - Gets renewal tasks from renew action queue of the scheduler.
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
import logging
from core import certfinder
from core import ocsprenewer
from core import ocspadder
from core import scheduling

LOG = logging.getLogger()


def run(args):
    """
    Creates queues and spawns the threads documented above.
    Threads are not started as daemons so this will run indefinitely unless the
    entire process is halted or all threads are killed.

    :param argparse.Namespace args: Parsed CLI arguments
    """
    LOG.debug("Started with CLI args: %s", str(args))
    directories = args.directories
    file_extensions = args.file_extensions.replace(" ", "").split(",")
    renewal_threads = args.renewal_threads
    refresh_interval = args.refresh_interval

    LOG.info(
        "Starting OCSP Stapling daemon, finding files of types: %s with "
        "%d threads.",
        ", ".join(file_extensions),
        renewal_threads
    )

    # Scheduler thread
    scheduler = scheduling.SchedulerThread()
    scheduler.daemon = False
    scheduler.name = "scheduler"
    scheduler.add_queue("renew")
    scheduler.add_queue("proxy-add")
    scheduler.start()


    #TODO: Set socket path intelligently
    socket_path = '/var/run/haproxy-le-213.108.104.111.sock'
    proxy_adder = ocspadder.OCSPAdder(
        socket_path=socket_path,
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
        thread.name = "renewer-{}".format(tid)
        thread.start()
        threads_list.append(thread)

    # Start certificate finding thread
    finder = certfinder.CertFinderThread(
        directories=directories,
        refresh_interval=refresh_interval,
        file_extensions=file_extensions,
        scheduler=scheduler
    )
    finder.daemon = False
    finder.name = "finder"
    finder.start()
