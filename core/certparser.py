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


def _cert_parser_factory(threaded=True):
    """
    Returns a threaded or non-threaded class (not an instance) of CertParser

    :param bool threaded: Should the returned class be threaded?
    :return class: _CertParser class threaded if threaded argument == True
    """

    if threaded:
        base_object = threading.Thread
    else:
        base_object = object

    class _CertParser(base_object):
        """
        This object takes tasks from a queue, the tasks contain certificate
        files that have to be pared to extract the certificate chain and the
        server certificate.
        """

        def __init__(self, *args, **kwargs):
            self.cli_args = kwargs.pop('cli_args', ())
            self.ignore_list = kwargs.pop('ignore_list', [])
            self.parse_queue = kwargs.pop('parse_queue', None)
            self.renew_queue = kwargs.pop('renew_queue', None)
            if base_object is threading.Thread:
                self.threaded = True
                super(_CertParser, self).__init__()
                # tid = kwargs.pop('tid', 0)
                # self.name = "ocsp-parser-{}".format(tid)
                self.name = "ocsp-parser"
                self.daemon = False
                self.start()
            else:
                self.threaded = False
                self.run(*args, **kwargs)

        def run(self, *args, **kwargs):
            """
            Start the thread if threaded, otherwise just run the same process.
            """
            if self.parse_queue is None:
                raise ValueError(
                    "You need to pass a queue where found certificates can be "
                    "retrieved from for parsing."
                )
            if self.renew_queue is None:
                raise ValueError(
                    "You need to pass a queue where parsed certificates can "
                    "be retrieved from for renewing."
                )
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

    return _CertParser

# Create the objects for a threaded and a non-threaded CertParser
CertParserThreaded = _cert_parser_factory()
CertParser = _cert_parser_factory(threaded=False)
