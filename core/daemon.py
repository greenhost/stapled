import queue
import logging
from core import certfinder
from core import ocsprenewer
from core import certparser
from core import scheduler
from ocspd import QUEUE_MAX_SIZE_PARSE
from ocspd import QUEUE_MAX_SIZE_RENEW
from ocspd import QUEUE_MAX_SIZE_SCHED

LOG = logging.getLogger()


def run(args):
    LOG.debug("Started with CLI args: %s", str(args))
    parse_queue = queue.Queue(QUEUE_MAX_SIZE_PARSE)
    renew_queue = queue.Queue(QUEUE_MAX_SIZE_RENEW)
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
        thread = ocsprenewer.OCSPRenewerThread(
            cli_args=args,
            contexts=contexts,
            renew_queue=renew_queue,
            sched_queue=sched_queue,
        )
        thread.daemon = False
        thread.name = "renewer-{}".format(tid)
        thread.start()
        threads_list.append(thread)

    # Start certificate parsing thread
    # For some reason you can't start multiple parser threads because of
    # some issue with an underlying crypto library that will start throwing
    # exceptions: TODO: figure out wtf..
    parser = certparser.CertParserThread(
        cli_args=args,
        parse_queue=parse_queue,
        renew_queue=renew_queue
    )
    parser.daemon = False
    parser.name = "parser"
    parser.start()

    # Start certificate finding thread
    finder = certfinder.CertFinderThread(
        cli_args=args,
        directories=directories,
        parse_queue=parse_queue,
        refresh_interval=refresh_interval,
        file_extensions=file_extensions,
        ignore_list=ignore_list,
        contexts=contexts
    )
    finder.daemon = False
    finder.name = "finder"
    finder.start()

    # Scheduler thread
    sched = scheduler.SchedulerThread(
        cli_args=args,
        ignore_list=ignore_list,
        sched_queue=sched_queue,
        renew_queue=renew_queue,
    )
    sched.daemon = False
    sched.name = "scheduler"
    sched.start()
