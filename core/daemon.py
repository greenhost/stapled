import queue
import logging
from core import certfinder, ocsprenewer, certparser

LOG = logging.getLogger()

QUEUE_MAX_SIZE_PARSE = 0  # 0 = unlimited
QUEUE_MAX_SIZE_RENEW = 0  # 0 = unlimited


class OCSPSDaemon(object):

    def __init__(self, args):
        LOG.debug("Started with CLI args: %s", str(args))
        self.parse_queue = queue.Queue(QUEUE_MAX_SIZE_PARSE)
        self.renew_queue = queue.Queue(QUEUE_MAX_SIZE_RENEW)
        self.directories = args.directories
        self.file_extensions = args.file_extensions.replace(" ", "").split(",")
        self.renewal_threads = args.renewal_threads
        self.refresh_interval = args.refresh_interval
        self.ignore_list = []
        self.cert_list = {}

        LOG.info(
            "Starting OCSP Stapling daemon, finding files of types: %s with "
            "%d threads.",
            ", ".join(self.file_extensions),
            self.renewal_threads
        )

        # Start ocsp response gathering threads
        self.threads_list = []
        for tid in range(0, self.renewal_threads):
            thread = ocsprenewer.OCSPRenewerThreaded(
                renew_queue=self.renew_queue,
                ignore_list=self.ignore_list,
                cert_list=self.cert_list,
                tid=tid
            )
            self.threads_list.append(thread)

        # Start certificate parsing thread
        # For some reason you can't start multiple parser threads because of
        # some issue with an underlying crypto library that will start throwing
        # exceptions: TODO: figure out wtf..
        self.parser_threads = certparser.CertParserThreaded(
            directories=self.directories,
            parse_queue=self.parse_queue,
            ignore_list=self.ignore_list,
            renew_queue=self.renew_queue
        )

        # Start certificate finding thread
        self.finder_thread = certfinder.CertFinderThreaded(
            directories=self.directories,
            parse_queue=self.parse_queue,
            refresh_interval=self.refresh_interval,
            file_extensions=self.file_extensions,
            ignore_list=self.ignore_list
        )
