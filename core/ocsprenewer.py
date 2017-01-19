"""
This module takes renew task contexts from the scheduler which contain
certificate models that consist of parsed certificates. It then generates an
OCSP request and sends it to the OCSP server(s) that is/are found in the
certificate and saves both the request and the response in the model. It also
generates a file containing the respone (the OCSP staple) and creates a new
task context for the :class:`core.oscpadder.OCSPAdder` and schedules it to be
run ASAP.
"""

import threading
import logging
import datetime
from core.scheduling import ScheduledTaskContext
from core.excepthandler import ocsp_except_handle

LOG = logging.getLogger()


class OCSPRenewerThread(threading.Thread):
    """
    This object takes tasks from the renew_queue, the tasks contain certificate
    files that have to be pared to extract the certificate chain and the server
    certificate.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialise the thread's arguments and its parent
        :class:`threading.Thread`.

        Currently supported keyword arguments:

        :kwarg int minimum_validity: The amount of seconds the OCSP staple is
            still valid for, before starting to attempt to request a new OCSP
            staple **(required)**.
        :kwarg core.scheduling.SchedulerThread scheduler: The scheduler object
            where we can get tasks from and add new tasks to. **(required)**.
        """
        self.minimum_validity = kwargs.pop('minimum_validity', None)
        self.scheduler = kwargs.pop('scheduler', None)

        assert self.minimum_validity is not None, \
            "You need to pass the minimum_validity."

        assert self.scheduler is not None, \
            "Please pass a scheduler to get tasks from and add tasks to."

        super(OCSPRenewerThread, self).__init__(*args, **kwargs)

    def run(self):
        """
        Start the thread if threaded, otherwise just run the same process.
        """
        LOG.info("Started a renewer thread.")
        while True:
            context = self.scheduler.get_task("renew")
            with ocsp_except_handle(context):
                LOG.info("Renewing OCSP staple for \"%s\"..", context.model)
                context.model.renew_ocsp_staple()
                self.scheduler.task_done("renew")
                self.schedule_renew(context)
                # DEBUG scheduling, schedule 10 seconds in the future.
                # self.schedule_renew(context, 10)
                # Adds the proxy-add command to the scheduler to run ASAP.
                # This updates the running HAProxy instance's OCSP staple by
                # running `set ssl ocsp-response {}`
                proxy_add_context = ScheduledTaskContext(
                    "proxy-add",
                    None,
                    context.model.filename,
                    model=context.model
                )
                self.scheduler.add_task(proxy_add_context)

    def schedule_renew(self, context, sched_time=None):
        """
        Schedule to renew this certificate's OCSP staple in ``sched_time``
        seconds.

        :param core.certmodel.CertModel context: CertModel
            instance None to calculate it automatically.
        :param int shed_time: Amount of seconds to wait for renewal or None
            to calculate it automatically.
        :raises ValueError: If ``context.ocsp_staple.valid_until`` is None
        """
        if not sched_time:
            if context.model.ocsp_staple.valid_until is None:
                raise ValueError(
                    "context.ocsp_response.valid_until can't be None.")
            before_sched_time = datetime.timedelta(
                seconds=self.minimum_validity)
            valid_until = context.model.ocsp_staple.valid_until
            sched_time = valid_until - before_sched_time
        context.sched_time = sched_time
        self.scheduler.add_task(context)
