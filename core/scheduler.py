"""
This is a task specific (as opposed to general purpose) scheduler. It does best
effort scheduling and execution of expired items in the order they are added.
This also means that there is no guarantee the tasks will be executed on time
every time, in fact they will always be late, even if just by milliseconds. If
you need it to be done on time, you schedule it early, but remember that it
will still be best effort.

The way this scheduler is supposed to be used is to schedule OCSP staple
renewal requests *n* seconds before the last one expires, where *n* is usually
as few hours (2 default). If the action fails, it should be rescheduled to be
run again a few times between the first attempt and the expiration of the
current OCSP staple.

This module defines the following objects:

 - :scheduler:`Scheduler` - An object that is capable of scheduling and
    unscheduling actions defined by :scheduler:`ScheduleAction` with a
    :models:`CertContext` object and optional time, wrapped in
    :scheduler:`ScheduleContext`.

    ..Note: Only use :scheduler:`SchedulerThreaded` unless you are testing.

 - :scheduler:`SchedulerThreaded`
    A threaded :scheduler:`Scheduler` - which doesn't mean multi threading, it
    will just run in its own thread. This is the normal way to use this class.
 - :scheduler:`ScheduleContext`
    A context that takes a :scheduler:`ScheduleAction`, a :models:`CertContext`
    object and a time for scheduling a renewal.
 - :scheduler:`ScheduleAction`
    actions:
     - `ADD`: Add a scheduled renewal
     - `REMOVE`: Remove a scheduled renewal
     - `IGNORE`: Ignore this file in the future.
     - `REMOVE_AND_IGNORE`: Remove a scheduled renewal and ignore this file in
       the future

"""
import threading
import logging
import datetime
import queue
from enum import Enum, unique

LOG = logging.getLogger()


@unique
class ScheduleAction(Enum):
    """
    Enum of possible schedling actions for the scheduling context.

    Enum values ar bitmaps for allowing multiple actions to be chosen at once.
    I.e.: REMOVE_AND_IGNORE has value: # b0110
    b0110 | b0100 == b0100 (IGNORE)
    b0110 | b0010 == b0010 (REMOVE)
    So both of these evaluate to true and runs the corresponding actions

    :ADD: Add a certificate to the schedule for renewal.
    :REMOVE: Remove a certificate from the schedule and delete its data.
    """
    ADD = 0b0001
    REMOVE = 0b0010
    IGNORE = 0b0100
    REMOVE_AND_IGNORE = 0b0110


class ScheduleContext(object):
    """
    Context that can be created and passed from any thread to the scheduler
    thread, given it has a reference to the `daemon.sched_queue` object.
    """
    def __init__(self, actions, context, sched_time=None):
        """
        Initialise a scheduler.Context to add to the `daemon.sched_queue`
        :param scheduler.ScheduleAction action: ADD or REMOVE an object
        :param str context: A :models:`CertContext` object
        """
        self.actions = actions
        self.context = context
        if sched_time is None:
            raise ValueError(
                "Can't schedule an action without a scheduled time."
            )
        self.sched_time = sched_time


class SchedulerThread(threading.Thread):
    """
    Renewal of OCSP staples can be scheduled with this object. It will also
    manage all the data going in and out of the certificate cache in
    `daemon.crt_list`. For example, if a certificate is deleted from the
    schedule, the cache will also be deleted.
    """
    def __init__(self, *args, **kwargs):
        """
        Initialise the thread's arguments and its parent
        :py:`threading.Thread`.

        Currently supported keyword arguments:
        :cli_args argparse.Namespace: The parsed CLI arguments namespace.
        :renew_queue Queue required: The queue where parsed certificates can be
            added for OCSP staple renewal.
        :sched_queue Queue required: The queue where scheduled OCSP renewals
            can be found.
        :ignore_list array optional: List of files to ignore.
        """
        self.cli_args = kwargs.pop('cli_args', None)
        self.renew_queue = kwargs.pop('renew_queue', None)
        self.sched_queue = kwargs.pop('sched_queue', None)
        self.ignore_list = kwargs.pop('ignore_list', [])

        assert self.cli_args is not None, \
            "You need to pass a argparser.NameSpace with CLI arguments."
        assert self.renew_queue is not None, \
            "A renew queue for parsed certificates should be passed."
        assert self.sched_queue is not None, \
            "A queue for getting scheduled staple renewals should be passed."

        # Keeping the tasks both in normal and reverse order to allow quick
        # unscheduling
        # The schedule contains items indexed by time
        self.schedule = {}
        # The scheduled are a list of actions indexed by file name
        self.scheduled = {}

        super(SchedulerThread, self).__init__(*args, **kwargs)

    def run(self, *args, **kwargs):
        """
        Start the thread if threaded, otherwise just run the same process.
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

        LOG.info("Started a scheduler thread.")
        while True:
            try:
                context = self.sched_queue.get(block=True, timeout=.1)
                # The following is a series of OR operators for bitwise
                # comparison. This way we can assign an action to each bit
                # in the Action Enum.
                # I.e.: REMOVE_AND_IGNORE has value: # b0110
                # b0110 | b0100 == b0100 (IGNORE)
                # b0110 | b0010 == b0010 (REMOVE)
                # So both of these evaluate to true and runs the
                # corresponding actions
                mask = context.actions.value

                if mask | ScheduleAction.ADD.value == mask:
                    self._schedule_renewal(
                        context.context, context.sched_time
                    )

                if mask | ScheduleAction.REMOVE.value == mask:
                    self._unschedule_renewal(context.context)

                if mask | ScheduleAction.IGNORE.value == mask:
                    self.ignore_list.append(context.context)

                self.sched_queue.task_done()
            except queue.Empty:
                pass
            self.run_tasks()

    def run_tasks(self, all_tasks=False):
        """
        Runs all scheduled tasks that have a scheduled time < now.

        :param bool all_tasks: Ignore scheduling times, just run all.
        """
        now = datetime.datetime.now()
        # Take a copy of all sched_time keys
        if all_tasks:
            todo = [x for x in self.schedule]
        else:
            # Only scheduled before or at now, default
            todo = [x for x in self.schedule if x <= now]
        for sched_time in todo:
            contexts = self.schedule.pop(sched_time)
            # actions is a list so 2 actions can be scheduled
            # simultaneously
            for context in contexts:
                LOG.info(
                    "Adding %s back to the renew queue.", context.filename
                )
                # Remove from reverse indexed dict
                del self.scheduled[context.filename]
                self.renew_queue.put(context)
                late = datetime.datetime.now() - sched_time
                if late.seconds < 1:
                    late = ''
                elif 1 < late.seconds < 59:  # between 1 and 59 seconds
                    late = " {} seconds late".format(late.seconds)
                else:
                    late = " {} late".format(
                        late.strftime('%Y-%m-%d %H:%M:%S')
                    )
                LOG.debug(
                    "Queued refresh for %s at %s%s",
                    context.filename,
                    now.strftime('%Y-%m-%d %H:%M:%S'),
                    late
                )

    def _schedule_renewal(self, context, sched_time):
        """
        Run scheduled actions after sched_time seconds.
        :param str context: A :models:`CertContext` object
        :param int sched_time: Amount of seconds to wait before adding
            the certificate back to the renewal queue
        """
        if context.filename in self.scheduled:
            LOG.warn(
                "OCSP staple for %s was already scheduled to be renewed, "
                "unscheduling.",
                context.filename
            )
            self._unschedule_renewal(context.filename)

        # Schedule task
        self.scheduled[context.filename] = sched_time
        if sched_time in self.schedule:
            self.schedule[sched_time].append(context)
        else:
            self.schedule[sched_time] = [context]

        LOG.info(
            "Scheduled a renewal for %s at %s",
            context.filename,
            sched_time.strftime('%Y-%m-%d %H:%M:%S')
        )

    def _unschedule_renewal(self, context):
        """
        Run scheduled actions after sched_time seconds.
        :param str context: A :models:`CertContext` object
        :param int sched_time: Amount of seconds to wait before adding
            the certificate back to the renewal queue
        """
        try:
            # Find out when it was scheduled
            sched_time = self.scheduled.pop(context.filename)
            # There can be more than one action scheduled in the same time
            # slot so we need to filter out any value that is not our
            # target and leave it
            slot = self.schedule[sched_time]
            slot[:] = [x for x in slot if x is not context]
        except KeyError:
            LOG.warn("Can't unschedule, %s wasn't scheduled for renewal")
