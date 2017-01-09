"""
This module parses certificate in a queue so the data contained in the
certificate can be used to request OCSP responses.
"""

import threading
import logging
import datetime
import os
from core.scheduler import ScheduleContext
from core.scheduler import ScheduleAction
from core.exceptions import CertValidationError
from core.exceptions import OCSPRenewError

LOG = logging.getLogger()


def _ocsp_renewer_factory(threaded=True):
    """
    Returns a threaded or non-threaded class (not an instance) of
        OCSPRenewer

    :param bool threaded: Should the returned class be threaded?
    :return class: OCSPRenewer class threaded if threaded argument == True
    """

    if threaded:
        base_object = threading.Thread
    else:
        base_object = object

    class _OCSPRenewer(base_object):
        """
        This object takes tasks from a queue, the tasks contain certificate
        files that have to be pared to extract the certificate chain and the
        server certificate.
        """

        def __init__(self, *args, **kwargs):
            self.cli_args = kwargs.pop('cli_args', ())
            self.renew_queue = kwargs.pop('renew_queue', None)
            self.contexts = kwargs.pop('contexts', None)
            self.sched_queue = kwargs.pop('sched_queue', None)
            if base_object is threading.Thread:
                self.threaded = True
                super(_OCSPRenewer, self).__init__()
                tid = kwargs.pop('tid', 0)
                self.name = "ocsp-renewer-{}".format(tid)
                self.daemon = False
                self.start()
            else:
                self.threaded = False
                self.run(*args, **kwargs)

        def run(self, *args, **kwargs):
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

    return _OCSPRenewer

# Create the objects for a threaded and a non-threaded OCSPRenewer
OCSPRenewerThreaded = _ocsp_renewer_factory()
OCSPRenewer = _ocsp_renewer_factory(threaded=False)
