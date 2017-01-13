import logging
from core import certfinder
from core import ocsprenewer
from core import scheduling

LOG = logging.getLogger()


def run(args):
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
    scheduler.start()

    # Start ocsp response gathering threads
    threads_list = []
    for tid in range(0, renewal_threads):
        thread = ocsprenewer.OCSPRenewerThread(scheduler=scheduler)
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
