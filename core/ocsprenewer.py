"""
This module parses certificate in a queue so the data contained in the
certificate can be used to request OCSP responses.
"""

import threading
import logging
import datetime
import os
from core.exceptions import CertValidationError
from core.exceptions import OCSPRenewError

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
        """
        self.minimum_validity = kwargs.pop('minimum_validity', None)
        self.scheduler = kwargs.pop('scheduler', None)

        assert self.minimum_validity is not None, \
            "You need to pass the minimum_validity."

        assert self.scheduler is not None, \
            "Please pass a scheduler to get and add renew tasks from and to."

        super(OCSPRenewerThread, self).__init__(*args, **kwargs)

    def run(self):
        """
        Start the thread if threaded, otherwise just run the same process.
        """
        LOG.info("Started a parser thread.")
        while True:
            context = self.scheduler.get_task("renew")
            LOG.info("Renewing OCSP staple for file \"%s\"..", context)
            try:
                context.renew_ocsp_staple()
            except OCSPRenewError as err:
                self._handle_failed_validation(context, err)
            except CertValidationError as err:
                self._handle_failed_validation(context, err)

            self.scheduler.task_done("renew")
            self.schedule_renew(context)
            # Adds the proxy-add command to the scheduler to run right now.
            # This updates the running HAProxy instance's ocsp staple by
            # running ssl
            self.scheduler.add_task('proxy-add', context)
            # DEBUG scheduling, schedule 10 seconds in the future.
            # self.schedule_renew(
            #     context,
            #     datetime.datetime.now()+datetime.timedelta(seconds=10)
            # )

    def _handle_failed_validation(
            self, context, msg, delete_ocsp=True, ignore=False):
        LOG.critical(msg)
        if ignore:
            # Unschedule any scheduled actions for context
            self.scheduler.cancel_task(("renew", "proxy-add"), context)
        if delete_ocsp:
            LOG.info(
                "Deleting any OCSP staple: \"%s.ocsp\" if it exists.",
                context
            )
            try:
                os.remove("{}.ocsp".format(context))
            except IOError:
                LOG.debug(
                    "Can't delete OCSP staple, maybe it doesn't exist."
                )

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
            if context.ocsp_staple.valid_until is None:
                raise ValueError(
                    "context.ocsp_response.valid_until can't be None.")
            before_sched_time = datetime.timedelta(
                seconds=self.minimum_validity)
            sched_time = context.ocsp_staple.valid_until - before_sched_time

        self.scheduler.add_task("renew", context, sched_time)
