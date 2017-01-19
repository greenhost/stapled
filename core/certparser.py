"""
This module parses certificate in a queue so the data contained in the
certificate can be used to request OCSP responses. After parsing a new task
context is created for the :class:`core.oscprenewe.OCSPRenewer` which is then
scheduled to be executed ASAP.
"""

import threading
import logging
import datetime
from core.excepthandler import ocsp_except_handle
from core.taskcontext import OCSPTaskContext

LOG = logging.getLogger(__name__)


class CertParserThread(threading.Thread):
    """
    This object makes sure certificate files are parsed, after which a task
    context is created for the :class:`core.oscprenewe.OCSPRenewer` which is
    scheduled to be executed ASAP.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialise the thread's arguments and its parent
        :class:`threading.Thread`.

        Currently supported keyword arguments:

        :kwarg dict models: A dict to maintain a model cache **(required)**.
        :kwarg int minimum_validity: The amount of seconds the OCSP staple
            should be valid for before a renewal is scheduled **(required)**.
        :kwarg core.scheduling.SchedulerThread scheduler: The scheduler object
            where we can get tasks from and add new tasks to. **(required)**.
        """
        self.models = kwargs.pop('models', None)
        self.minimum_validity = kwargs.pop('minimum_validity', None)
        self.scheduler = kwargs.pop('scheduler', None)

        assert self.models is not None, \
            "You need to pass a dict to hold the certificate model cache."

        assert self.minimum_validity is not None, \
            "You need to pass the minimum_validity."

        assert self.scheduler is not None, \
            "Please pass a scheduler to get tasks from and add tasks to."

        super(CertParserThread, self).__init__(*args, **kwargs)

    def run(self):
        """
        Start the certificate parser thread.
        """

        LOG.info("Started a parser thread.")
        while True:
            context = self.scheduler.get_task("parse")
            with ocsp_except_handle(context):
                self.parse_certificate(context.model)
            # If the parsing action fails, the error handler will reschedule it
            # if it makes sense, if not a log message will be emitted that it
            # will be ignored, when the certificate file is changed the finder
            # will schedule it to be parsed again.
            self.scheduler.task_done("parse")

    def parse_certificate(self, model):
        """
        Parse certificate files and check whether an existing OCSP staple that
        is still valid exists. If so, use it, if not request a new OCSP staple.
        If the staple is valid but not valid for longer than the
        ``minimum_validity``, the staple is loaded but a new request is still
        scheduled.
        """
        LOG.info("Parsing certificate for file \"%s\"..", model)
        # Parse the certificate
        model.parse_crt_file()
        # If there is a valid existing staple, use it..
        if model.recycle_staple(self.minimum_validity):
            # There is a valid staple file, schedule a regular renewal
            until = model.ocsp_staple.valid_until
            sched_time = until - datetime.timedelta(
                seconds=self.minimum_validity)
        else:
            # No existing staple file or invalid, renew ASAP.
            sched_time = None

        # Schedule a renewal of the OCSP staple
        context = OCSPTaskContext("renew", model, sched_time)
        self.scheduler.add_task(context)
