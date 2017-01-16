"""
This is a general purpose scheduler. It does best effort scheduling and
execution of expired items in the order they are added. This also means that
there is no guarantee the tasks will be executed on time every time, in fact
they will always be late, even if just by milliseconds. If you need it to be
done on time, you schedule it early, but remember that it will still be best
effort.

The way this scheduler is supposed to be used is to add a scheduling queue,
then you can add tasks to the queue to either be put in a task queue ASAP or
at or an absolute time in the future. The queue should be consumed by a worker
thread.

This module defines the following objects:

 - :scheduler:`SchedulerThread` - An object that is capable of scheduling and
    unscheduling actions that you can define with, you should add contexts to
    the schedule with an optional time. The context should to have a proper
    ``__repr__()`` defined since the scheduler relies on it to be a unique
    identifier.
"""
import threading
import logging
import datetime
import queue
import time

LOG = logging.getLogger()


class SchedulerThread(threading.Thread):
    """
    This object can be used to schedule actions for contexts.

    The context can be whatever you define as long as the ``__repr__()`` will
    return something that is unique among your actions. When the scheduled time
    has passed, the context will be added back to the action queue, where it
    can be consumed by a worker thread. When a task is scheduled you can choose
    to have it added to the action queue ASAP or at a specified absolute point
    in time. If you add it at a time in the past, it will be added to the
    action queue the first time the scheduler checks expired actions times.
    """
    def __init__(self, *args, **kwargs):
        """
        Initialise the thread's arguments and its parent
        :py:`threading.Thread`.

        Currently supported keyword arguments:
        :renew_queue Queue required: The queue where parsed certificates can be
            added for OCSP staple renewal.
        :sched_queue Queue required: The queue where scheduled OCSP renewals
            can be found.
        :ignore_list array optional: List of files to ignore.
        """
        self._queues = {}

        # Keeping the tasks both in normal and reverse order to allow quick
        # unscheduling
        # The schedule contains items indexed by time
        self.schedule = {}
        # The scheduled are a list of actions indexed by file name
        self.scheduled = {}

        super(SchedulerThread, self).__init__(*args, **kwargs)

    def add_queue(self, action, max_size=0):
        """
        Add a scheduled queue to the scheduler.
        :param str action: A unique name that is used by worker threads
        :param int max_size: Maximum queue depth, default=0 (unlimited)
        """
        assert action not in self._queues, "This queue already exists."
        self._queues[action] = queue.Queue(max_size)

    def add_task(self, actions, context, sched_time=None):
        """
        Add a task to be executed either ASAP, or at a specific time

        :param tuple | str: An action corresponding to an existing queue
        :param :mod:`certmodel.CertModel` context: Certificate context
        :param datetime.datetime sched_time: Absolute time to execute the task
        :raises Queue.Full: If the underlying action queue is full
        """
        if isinstance(actions, str):
            actions = tuple(actions)

        if not sched_time:
            for action in actions:
                self._queue_action(action, context)
        else:
            pass

    def _queue_action(self, action, context):
        try:
            self._queues[action].put(context)
        except KeyError as key:
            raise KeyError("Queue for action {} might not exist.", key)

    def _schedule_task(self, action, context, sched_time):
        """
        Run scheduled actions after sched_time seconds.
        :param object context: A context that will be added to the queue at the
            set time
        :param int sched_time: Amount of seconds to wait before adding
            the certificate back to the renewal queue
        """
        key = (action, repr(context))
        if key in self.scheduled:
            LOG.warning(
                "Task %s: %s was already scheduled, unscheduling.",
                action, context
            )
            self._unschedule_renewal(key)

        # Schedule task
        self.scheduled[key] = sched_time
        if sched_time in self.schedule:
            self.schedule[sched_time].append((action, context))
        else:
            self.schedule[sched_time] = [(action, context)]

        LOG.info(
            "Scheduled %s: %s at %s",
            action, context, sched_time.strftime('%Y-%m-%d %H:%M:%S'))

    def _unschedule_task(self, action, context):
        """
        Run scheduled actions after sched_time seconds.
        :param object context: A context that will be removed from the queue
        """
        try:
            # Find out when it was scheduled
            sched_time = self.scheduled.pop((action, repr(context)))
            # There can be more than one action scheduled in the same time
            # slot so we need to filter out any value that is not our target
            # and leave it
            slot = self.schedule[sched_time]
            slot[:] = [x for x in slot if x != (action, context)]
        except KeyError:
            LOG.warning(
                "Can't unschedule, %s wasn't scheduled for %s",
                context, action)

    def get_task(self, action, blocking=True, timeout=None):
        """
        Initialise a scheduler.Context to add to the `daemon.sched_queue`

        NOTE: Not sure in which context this will run, might break if this
            halts the thread!

        :param str action: Action name that refers to a scheduler queue.
        :param bool blocking: Wait until there is something to return from the
            queue
        """
        return self._queues[action].get(blocking, timeout)

    def run(self):
        """
        Start the certificate finder thread.
        """
        while True:
            LOG.info("Started a scheduler thread.")
            self._run()
            time.sleep(1)

    def run_all(self):
        self._run(True)

    def _run(self, all_tasks=False):
        """
        Runs all scheduled tasks that have a scheduled time < now.
        """
        now = datetime.datetime.now()
        # Take a copy of all sched_time keys
        if all_tasks:
            todo = list(self.schedule)
        else:
            # Only scheduled before or at now, default
            todo = [x for x in self.schedule if x <= now]
        for sched_time in todo:
            items = self.schedule.pop(sched_time)
            for action, context in items:
                LOG.info("Adding %s to the %s queue.", context, action)
                # Remove from reverse indexed dict
                del self.scheduled[(action, repr(context))]

                self._queue_action(action, context)
                late = datetime.datetime.now() - sched_time
                if late.seconds < 1:
                    late = ''
                elif 1 < late.seconds < 59:  # between 1 and 59 seconds
                    late = " {} seconds late".format(late.seconds)
                else:
                    late = " {} late".format(
                        late.strftime('%H:%M:%S')
                    )
                LOG.debug(
                    "Queued %s for %s at %s%s",
                    action,
                    context,
                    now.strftime('%Y-%m-%d %H:%M:%S'),
                    late
                )
