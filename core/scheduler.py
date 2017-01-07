import threading
import logging
import enum
import sched
import datetime

LOG = logging.getLogger()


class Action(enum.Enum):
    """
        Enum of possible schedling actions for the scheduling context.
        :ADD: Add a certificate to the schedule for renewal.
        :REMOVE: Remove a certificate from the schedule and delete its data.
    """
    ADD = 0b0001
    REMOVE = 0b0010
    IGNORE = 0b0100
    REMOVE_AND_IGNORE = 0b0110


class Context(object):
    """
        Context that can be created and passed from any thread to the scheduler
        thread, given it has a reference to the `daemon.sched_queue` object.

        The certificate is referenced by file name because it is a unique value
        for the entry and a simple list of scheduled items can be kept indexed
        by file name.
    """
    def __init(actions, filename, sched_time=0):
        """
            Initialise a scheduler.Context to add to the `daemon.sched_queue`
            :param scheduler.Action action: ADD or REMOVE an object
            :param str filename: The certificate's file name.
        """
        self.action = action
        self.crt_object = crt_object
        self.time = sched_time


def _scheduler_factory(threaded=True):
    """
        Returns a threaded or non-threaded class (not an instance) of
            Scheduler

        :param bool threaded: Should the returned class be threaded?
        :return class: _Scheduler class threaded if threaded argument == True
    """

    if threaded:
        base_object = threading.Thread
    else:
        base_object = object

    class _Scheduler(base_object):
        """
            Renewal of OCSP staples can be scheduled with this object.
            It will also manage all the data going in and out of the
            certificate cache in `daemon.crt_list`. For example, if a
            certificate is deleted from the schedule, the cache will also be
            deleted.
        """
        def __init__(self, *args, **kwargs):
            """
                Initialise the Scheduler.
                :param tuple *args: Arguments for the Scheduler initialisation
                :param dict **kwargs: Keyword arguments for the Scheduler
                    initialisation
            """
            self.ignore_list = kwargs.pop('ignore_list', [])
            self.sched_queue = kwargs.pop('sched_queue', None)
            self.renew_queue = kwargs.pop('renew_queue', None)
            self.cert_list = kwargs.pop('cert_list', None)
            self.scheduled = {}
            self.scheduler = sched.scheduler()
            if base_object is threading.Thread:
                self.threaded = True
                super(_Scheduler, self).__init__()
                # tid = kwargs.pop('tid', 0)
                # self.name = "ocsp-parser-{}".format(tid)
                self.name = "ocsp-scheduler"
                self.daemon = False
                self.start()
            else:
                self.threaded = False
                self.run(*args, **kwargs)

        def run(self, *args, **kwargs):
            """
                Start the thread if threaded, otherwise just run the same
                process.
                :param tuple *args: Arguments for the Scheduler initialisation
                :param dict **kwargs: Keyword arguments for the Scheduler
                    initialisation
            """
            if self.renew_queue is None:
                raise ValueError(
                    "You need to pass a queue where cached certificates can "
                    "be pushed again for OCSP staple renewing."
                )
            if self.sched_queue is None:
                raise ValueError(
                    "You need to pass a queue where certificates can be added "
                    "for scheduling the OCSP staple renewal."
                )
            if self.cert_list is None:
                raise ValueError(
                    "You need to pass a dict for certificate data to be kept."
                )

            LOG.info("Started a scheduler thread.")
            while True:
                context = self.sched_queue.get()
                # The following is a series of OR operators for bitwise
                # comparison. This way we can assign an action to each bit in
                # the Action Enum.
                # I.e.: REMOVE_AND_IGNORE has value: # b0110
                # b0110 | b0100 == b0100 (IGNORE)
                # b0110 | b0010 == b0010 (REMOVE)
                # So both of these evaluate to true and runs the corresponding
                # actions
                mask = context.action

                if mask | Action.ADD == mask:
                    self._schedule_renewal(
                        context.filename, context.sched_time
                    )

                if mask | Action.REMOVE == mask:
                    self._unschedule_renewal(context.filename)

                if mask | Action.IGNORE == mask:
                    self.ignore_list.append(context.filename)

                self.sched_queue.task_done()

        def _schedule_renewal(self, filename, sched_time):
            """
                Run a scheduled action after sched_time seconds.
                :param str filename: Certificate filename.
                :param int sched_time: Amount of seconds to wait before adding
                    the certificate back to the renewal queue.
            """
            crt = self.cert_list[filename]
            if filename in self.scheduled:
                LOG.warn(
                    "OCSP staple for %s was already scheduled to be renewed, "
                    "unscheduling.",
                    filename
                )
                self._unschedule_renewal(filename)
            scheduled = self.scheduler.enter(
                sched_time,
                0,
                self.renew_queue.put,
                argument=(crt)
            )
            self.scheduled[filename] = scheduled
            abstime = datetime.datetime.now()
            abstime += datetime.timedelta(seconds=sched_time)
            LOG.info(
                "Scheduled a renewal for %s at %s",
                filename,
                abstime.strftime('%Y-%m-%d %H:%M:%S')
            )

        def _unschedule_renewal(filename):
            """
                Run a scheduled action after sched_time seconds.
                :param str filename: Certificate filename.
                :param int sched_time: Amount of seconds to wait before adding
                    the certificate back to the renewal queue.
            """
            try:
                scheduled = self.scheduled.pop(filename)
                self.scheduler.cancel(scheduled)
            except (KeyError, ValueError):
                LOG.warn("Can't unschedule, %s wasn't scheduled for renewal")

    return _Scheduler

# Create the objects for a threaded and a non-threaded Scheduler
SchedulerThreaded = _scheduler_factory()
Scheduler = _scheduler_factory(threaded=False)
