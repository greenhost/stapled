"""
This module parses certificate in a queue so the data contained in the
certificate can be used to request OCSP responses.
"""

import threading
import logging
import os
from core.exceptions import CertValidationError
from core.scheduler import ScheduleContext
from core.scheduler import ScheduleAction

LOG = logging.getLogger()


class CertParserThread(threading.Thread):
    """
    This object takes tasks from a queue, the tasks contain certificate
    files that have to be pared to extract the certificate chain and the
    server certificate.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialise the thread's arguments and its parent
        :py:`threading.Thread`.

        Currently supported keyword arguments:

        :cli_args argparse.Namespace: The parsed CLI arguments namespace.
        :parse_queue Queue required: The queue to add found certs to for
            parsing.
        :renew_queue Queue required: The queue to add parsed certs to for
            OCSP staple renewal.
        :ignore_list array optional: List of files to ignore.
        """
        self.cli_args = kwargs.pop('cli_args', None)
        self.parse_queue = kwargs.pop('parse_queue', None)
        self.renew_queue = kwargs.pop('renew_queue', None)
        self.ignore_list = kwargs.pop('ignore_list', [])

        assert self.cli_args is not None, \
            "You need to pass a argparser.NameSpace with CLI arguments."
        assert self.parse_queue is not None, \
            "A parsing queue where found/changed certificates can be found."
        assert self.renew_queue is not None, \
            "A renew queue for parsed certificates should be passed."

        super(CertParserThread, self).__init__(*args, **kwargs)

    def run(self, *args, **kwargs):
        """
        Start the thread if threaded, otherwise just run the same process.
        """
        LOG.info("Started a parser thread.")
        while True:
            context = self.parse_queue.get()
            LOG.info("Parsing file \"%s\"..", context.filename)
            try:
                context.parse_crt_chain()
            except CertValidationError as err:
                self._handle_failed_validation(context, err)
            except KeyError as err:
                self._handle_failed_validation(
                    context,
                    "KeyError {}, processing file \"{}\"".format(
                        err, context.filename
                    )
                )
                return False
            self.parse_queue.task_done()
            self.renew_queue.put(context)

    def _handle_failed_validation(self, context, msg, delete_ocsp=True):
        LOG.critical(msg)
        # Unschedule any scheduled actions for context
        schedule_context = ScheduleContext(
            ScheduleAction(ScheduleAction.REMOVE),
            context
        )
        self.sched_queue.put(schedule_context)
        if delete_ocsp:
            LOG.info(
                "Deleting any OCSP staple: \"%s\" if it exists.",
                context.filename
            )
            try:
                os.remove("{}.ocsp".format(context.filename))
            except IOError:
                pass
