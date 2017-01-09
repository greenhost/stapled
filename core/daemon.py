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
    LOG.debug("Started with CLI args: %s", str(args))
    parse_queue = queue.Queue(QUEUE_MAX_SIZE_PARSE)
    renew_queue = queue.Queue(QUEUE_MAX_SIZE_RENEW)
    sched_queue = queue.Queue(QUEUE_MAX_SIZE_RENEW)
    directories = args.directories
    file_extensions = args.file_extensions.replace(" ", "").split(",")
    renewal_threads = args.renewal_threads
    refresh_interval = args.refresh_interval
    ignore_list = []
    cert_list = {}

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
            cert_list=cert_list,
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
        cert_list=cert_list
    )

    # Scheduler thread
    scheduler.SchedulerThreaded(
        cli_args=args,
        ignore_list=ignore_list,
        sched_queue=sched_queue,
        renew_queue=renew_queue,
    )
