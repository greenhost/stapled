# -*- coding: utf-8 -*-
"""
This module parses certificate in a queue so the data contained in the
certificate can be used to request OCSP responses. After parsing a new
:class:`ocspd.core.taskcontext.OCSPTaskContext` is created for the
:class:`ocspd.core.oscprenewe.OCSPRenewer` which is then scheduled to be
processed ASAP.
"""

import threading
import logging
import datetime
import queue
from ocspd.core.excepthandler import ocsp_except_handle
from ocspd.core.taskcontext import OCSPTaskContext

LOG = logging.getLogger(__name__)


class CertParserThread(threading.Thread):
    """
    This object makes sure certificate files are parsed, after which a task
    context is created for the :class:`ocspd.core.oscprenewer.OCSPRenewer`
    which is scheduled to be executed ASAP.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialise the thread with its parent :class:`threading.Thread` and its
        arguments.

        :kwarg dict models: A dict to maintain a model cache **(required)**.
        :kwarg int minimum_validity: The amount of seconds the OCSP staple
            should be valid for before a renewal is scheduled **(required)**.
        :kwarg ocspd.scheduling.SchedulerThread scheduler: The scheduler object
            where we can get parser tasks from and add renew tasks to.
            **(required)**.
        :kwarg bool no_recycle: Don't recycle existing staples (default=False)
        """
        self.stop = False
        self.models = kwargs.pop('models', None)
        self.minimum_validity = kwargs.pop('minimum_validity', None)
        self.scheduler = kwargs.pop('scheduler', None)
        self.no_recycle = kwargs.pop('no_recycle', False)

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
        while not self.stop:
            try:
                context = self.scheduler.get_task("parse", timeout=0.25)
                with ocsp_except_handle(context):
                    self.parse_certificate(context.model)
                # If the parsing action fails, the error handler will
                # reschedule it if it makes sense, if not a log message will be
                # emitted that it  will be ignored, when the certificate file
                # is changed the finder will schedule it to be parsed again.
                self.scheduler.task_done("parse")
            except queue.Empty:
                pass
        LOG.debug("Goodbye cruel world..")

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
        if not self.no_recycle and model.recycle_staple(self.minimum_validity):
            # There is a valid staple file, schedule a regular renewal
            until = model.ocsp_staple.valid_until
            sched_time = until - datetime.timedelta(
                seconds=self.minimum_validity)
        else:
            # No existing staple file or invalid, renew ASAP.
            sched_time = None

        # Schedule a renewal of the OCSP staple
        context = OCSPTaskContext(
            task_name="renew", model=model, sched_time=sched_time)
        self.scheduler.add_task(context)
