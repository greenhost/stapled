# -*- coding: utf-8 -*-
"""
This module takes renew task contexts from the scheduler which contain
certificate models that consist of parsed certificates. It then generates an
OCSP request and sends it to the OCSP server(s) that is/are found in the
certificate and saves both the request and the response in the model. It also
generates a file containing the respone (the OCSP staple) and creates a new
:class:`ocspd.core.taskcontext.OCSPTaskContext` to schedule a renewal before
the staple expires. Optionally creates a
:class:`ocspd.core.taskcontext.OCSPTaskContext` task context for the
:class:`ocspd.core.oscpadder.OCSPAdder` and schedules it to be run ASAP.
"""

import threading
import logging
import datetime
import queue
from ocspd.core.taskcontext import OCSPTaskContext
from ocspd.core.excepthandler import ocsp_except_handle

LOG = logging.getLogger(__name__)


class OCSPRenewerThread(threading.Thread):
    """
    This object requests OCSP responses for certificates, after which a new
    task context is created for the :class:`ocspd.core.oscprenewer.OCSPRenewer`
    which is scheduled to be executed before the new staple expires. Optionally
    a task is created for the :class:`ocspd.core.oscpadder.OCSPAdder` to tell
    HAProxy about the new staple.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialise the thread's arguments and its parent
        :class:`threading.Thread`.

        :kwarg int minimum_validity: The amount of seconds the OCSP staple is
            still valid for, before starting to attempt to request a new OCSP
            staple **(required)**.
        :kwarg ocspd.scheduling.SchedulerThread scheduler: The scheduler object
            where we can get tasks from and add new tasks to. **(required)**.
        """
        self.stop = False
        self.minimum_validity = kwargs.pop('minimum_validity', None)
        self.scheduler = kwargs.pop('scheduler', None)

        assert self.minimum_validity is not None, \
            "You need to pass the minimum_validity."

        assert self.scheduler is not None, \
            "Please pass a scheduler to get tasks from and add tasks to."

        super(OCSPRenewerThread, self).__init__(*args, **kwargs)

    def run(self):
        """
        Start the renewer thread.
        """
        LOG.info("Started a renewer thread.")
        while not self.stop:
            try:
                context = self.scheduler.get_task("renew", timeout=0.25)
                with ocsp_except_handle(context):
                    model = context.model
                    LOG.info("Renewing OCSP staple for \"%s\"..", model)
                    model.renew_ocsp_staple()
                    self.scheduler.task_done("renew")

                    # DEBUG scheduling, schedule 10 seconds in the future.
                    # self.schedule_renew(context, 10)
                    self.schedule_renew(model)

                    # Adds the proxy-add command to the scheduler to run ASAP.
                    # This updates the running HAProxy instance's OCSP staple
                    # by running `set ssl ocsp-response {}`
                    proxy_add_context = OCSPTaskContext(
                        task_name="proxy-add", model=model, sched_time=None)
                    self.scheduler.add_task(proxy_add_context)
            except queue.Empty:
                pass
        LOG.debug("Goodbye cruel world..")

    def schedule_renew(self, model, sched_time=None):
        """
        Schedule to renew this certificate's OCSP staple in ``sched_time``
        seconds.

        :param ocspd.core.certmodel.CertModel context: CertModel
            instance None to calculate it automatically.
        :param int shed_time: Amount of seconds to wait for renewal or None
            to calculate it automatically.
        :raises ValueError: If ``context.ocsp_staple.valid_until`` is None
        """
        if not sched_time:
            if model.ocsp_staple.valid_until is None:
                raise ValueError(
                    "context.ocsp_response.valid_until can't be None.")
            before_sched_time = datetime.timedelta(
                seconds=self.minimum_validity)
            valid_until = model.ocsp_staple.valid_until
            sched_time = valid_until - before_sched_time
        # Make a fresh task context to reset exception counters
        new_context = OCSPTaskContext(
            task_name="renew", model=model, sched_time=sched_time)
        self.scheduler.add_task(new_context)
