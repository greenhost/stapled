"""
This module parses certificate in a queue so the data contained in the
certificate can be used to request OCSP responses.
"""

import threading
import logging
import datetime
import os
from core.scheduling import ScheduleContext
from core.scheduling import ScheduleAction
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
        :py:`threading.Thread`.

        Currently supported keyword arguments:
        :cli_args argparse.Namespace: The parsed CLI arguments namespace.
        :contexts dict required: The cache of parsed certificates with OCSP
                data if it was already been requested by the
                :class:`core.ocsprenewer.OCSPRenewerThread`.
        :renew_queue Queue required: The queue where parsed certificates can be
            found for OCSP staple renewal.
        :sched_queue Queue required: The queue where cached certificate objects
            can be scheduled for OCSP renewal.
        """
        self.cli_args = kwargs.pop('cli_args', None)
        self.contexts = kwargs.pop('contexts', None)
        self.renew_queue = kwargs.pop('renew_queue', None)
        self.sched_queue = kwargs.pop('sched_queue', None)

        assert self.cli_args is not None, \
            "You need to pass a argparser.NameSpace with CLI arguments."
        assert self.contexts is not None, \
            "Contexts dict for keeping certificate contexts should be passed."
        assert self.renew_queue is not None, \
            "A renew queue for parsed certificates should be passed."
        assert self.sched_queue is not None, \
            "A queue for scheduling OCSP staple renewals should be passed."

        super(OCSPRenewerThread, self).__init__(*args, **kwargs)

    def run(self):
        """
        Start the thread if threaded, otherwise just run the same process.
        """
        if self.renew_queue is None:
            raise ValueError(
                "You need to pass a queue where parsed certificates can "
                "be retrieved from for renewing."
            )
        if self.sched_queue is None:
            raise ValueError(
                "You need to pass a queue where certificates can be added "
                "for scheduling the OCSP staple renewal."
            )
        if self.contexts is None:
            raise ValueError(
                "You need to pass a dict for certificate data to be kept."
            )
        LOG.info("Started a parser thread.")
        while True:
            context = self.renew_queue.get()
            LOG.info("Renewing OCSP staple for file \"%s\"..", context)
            try:
                context.renew_ocsp_staple()
            except OCSPRenewError as err:
                self._handle_failed_validation(context, err)
            except CertValidationError as err:
                self._handle_failed_validation(context, err)

            # Keep list of certificate contexts
            self.contexts[context.filename] = context
            self.renew_queue.task_done()

            self.schedule_renew(context)
            # DEBUG scheduling, schedule 10 seconds in the future.
            # self.schedule_renew(
            #     context,
            #     datetime.datetime.now()+datetime.timedelta(seconds=10)
            # )

    def _handle_failed_validation(
            self, context, msg, delete_ocsp=True, ignore=False):
        LOG.critical(msg)
        if ignore:
            # Unschedule any scheduled actions for context and ignore it
            context = ScheduleContext(
                ScheduleAction(ScheduleAction.REMOVE_AND_IGNORE),
                context
            )
            self.sched_queue.put(context)
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
        Schedule to renew this certificate's OCSP staple in `sched_time`
        seconds.

        :param models.certificates.CertContext context: CertContext
            instance None to calculate it automatically.
        :param int shed_time: Amount of seconds to wait for renewal or None
            to calculate it automatically.
        :raises ValueError: If context.valid_until is None
        """
        if not sched_time:
            if context.valid_until is None:
                raise ValueError("context.valid_until can't be None.")

            before_sched_time = datetime.timedelta(
                seconds=self.cli_args.minimum_validity)
            sched_time = context.valid_until - before_sched_time
        schedule_context = ScheduleContext(
            ScheduleAction(ScheduleAction.ADD),
            context,
            sched_time=sched_time
        )
        self.sched_queue.put(schedule_context)
