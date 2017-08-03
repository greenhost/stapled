# -*- coding: utf-8 -*-
"""
This is a general purpose scheduler. It does best effort scheduling and
execution of expired items in the order they are added. This also means that
there is no guarantee the tasks will be executed on time every time, in fact
they will always be late, even if just by milliseconds. If you need it to be
done on time, you schedule it early, but remember that it will still be best
effort.

The way this scheduler is supposed to be used is to add a scheduling queue,
then you can add tasks to the queue to either be put in a task queue ASAP, or
at or an absolute time in the future. The queue should be consumed by a worker
thread.

This module defines the following objects:

 - :class:`ocspd.scheduling.ScheduledTaskContext`
    A context that wraps around any data you want to pass to the scheduler and
    which will be added to the task queue when the schedule time expires.
 - :class:`ocspd.scheduling.SchedulerThread`
    An object that is capable of scheduling and unscheduling tasks that you
    can define with :class:`ocspd.scheduling.ScheduledTaskContext`.
"""
import threading
import logging
import datetime
from queue import Queue
import time
from collections import defaultdict

LOG = logging.getLogger(__name__)


class ScheduledTaskContext(object):
    """
    A context for scheduled tasks, this context can be updated with an
    exception count for the last exception, so it can be re-scheduled if it is
    the appropriate action.
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, task_name, subject, sched_time=None, **attributes):
        """
        Initialise a :class:`~ocspd.scheduling.ScheduledTaskContext` with a
        task name, subject and optional scheduled time. Any remaining keyword
        arguments are set as attributes of the task context.

        :param str task: A task corresponding to an existing queue in the
            target scheduler.
        :param datetime.datetime|int sched_time: Absolute time
            (datetime.datetime object) or relative time in seconds (int) to
            schedule the task.
        :param obj subject: A subject for the context instance this can be
            whatever object you want to pass along to the worker.
        :param kwargs attributes: Any additional data you want to assign to
            the context, avoid using names already defined in the context:
            ``scheduler``, ``task``, ``subject``, ``sched_time``,
            ``reschedule``.
        """
        #: This attribute will be set automatically when the context is passed
        #: to a scheduler.
        self.scheduler = None
        self.task_name = task_name
        self.subject = subject
        self.sched_time = sched_time
        for attr, value in attributes.items():
            if hasattr(ScheduledTaskContext, attr):
                raise AttributeError(
                    "Can't set \"{}\" it's a reserved attribute name.".format(
                        attr)
                )
            self.__setattr__(attr, value)

    def reschedule(self, sched_time=None):
        """
        Reschedule this context itself.

        :param datetime.datetime sched_time: When should this context be added
            back to the task queue
        """
        try:
            self.sched_time = sched_time
            self.scheduler.add_task(self)
        except AttributeError:
            raise AttributeError(
                "This context was never added to a queue before.")

    def __repr__(self):
        return "<ScheduledTaskContext {}: {}>".format(
            self.task_name, self.subject)


class SchedulerThread(threading.Thread):
    """
    This object can be used to schedule tasks for contexts.

    The context should be a :class:`~scheduler.ScheduledTaskContext` or an
    extension of it.. When the scheduled time has *passed*, the context will be
    added back to the internal task queue(s), where it can be consumed by a
    worker thread.
    When a task is scheduled you can choose to have it added to the task queue
    ASAP or at a specified absolute or relative point in time. If you add it
    with an absolute time in the past, or a negative relative number, it will
    be added to the task queue the first time the scheduler checks expired
    tasks schedule times. If you want to run a task ASAP, you probably don't
    that, you should pass ``sched_time=None`` instead, it will bypass the
    scheduling mechanism and place your task directly into the worker queue.
    """
    def __init__(self, *args, **kwargs):
        """
        Initialise the thread's arguments and its parent
        :class:`threading.Thread`.

        :kwarg iterable queues: A list, tuple or any iterable that returns
            strings that should be the names of queues.
        :kwarg int|float sleep: The sleep time in seconds between checking the
            expired items in the queue (default=1)
        :raises KeyError: If the queue name is already taken (only when queues
            kwarg is used).
        """
        self.stop = False
        self._queues = {}

        #: The schedule contains items indexed by time.
        self.schedule = defaultdict(lambda: [])
        #: Keeping the tasks in reverse order helps for faster unscheduling.
        self.scheduled_by_context = {}
        #: Keeping the tasks per queue name helps faster queue deletion.
        self.scheduled_by_queue = {}
        #: To allow removing by subject we keep the scheduled tasks by subject.
        self.scheduled_by_subject = defaultdict(lambda: [])

        queues = kwargs.pop('queues', None)
        if queues:
            for queue_ in queues:
                self.add_queue(queue_)

        self.sleep = kwargs.pop('sleep', 1)

        super(SchedulerThread, self).__init__(*args, **kwargs)

    def add_queue(self, name, max_size=0):
        """
        Add a scheduled queue to the scheduler.

        :param str name: A unique name for the queue.
        :param int max_size: Maximum queue depth, [default=0 (unlimited)].
        :raises KeyError: If the queue name is already taken.
        """
        if name in self._queues:
            raise KeyError("A queue with name %s already exists.", name)
        self._queues[name] = Queue(max_size)
        self.scheduled_by_queue[name] = []

    def remove_queue(self, name):
        """
        Remove a scheduled queue from the scheduler.

        :param str name: The name of the existing queue.
        :raises KeyError: If the queue doesn't exist.
        """
        try:
            for ctx in self.scheduled_by_queue[name]:
                sched_time = self.scheduled_by_context.pop(ctx)
                self.schedule[sched_time].remove(ctx)
                del self.scheduled_by_subject[ctx.subject]
            del self.scheduled_by_queue[name]
            del self._queues[name]
        except KeyError:
            raise KeyError("A queue with name %s doesn't exist.", name)

    def add_task(self, ctx):
        """
        Add a :class:`~scheduler.ScheduledTaskContext` to be added to the task
        queue either ASAP, or at a specific time.

        If the context is not unique, the scheduled task will be cancelled
        before scheduling the new task.

        :param ScheduledTaskContext ctx: A context containing data for a
            worker thread.
        :raises queue.Queue.Full: If the underlying task queue is full.
        :raises TypeError: If the passed context is not a
            :class:`~scheduler.ScheduledTaskContext`
        :raises KeyError: If the task queue doesn't exist.
        """
        if not isinstance(ctx, ScheduledTaskContext):
            raise TypeError(
                "Passed context is not an instance of ScheduledTaskContext")
        if ctx.task_name not in self._queues:
            raise KeyError(
                "Queue with task name {} doesn't exist.", ctx.task_name)

        ctx.scheduler = self
        if not ctx.sched_time:
            # Run scheduled tasks ASAP by adding it to the queue.
            self._queues[ctx.task_name].put(ctx)
            return

        if isinstance(ctx.sched_time, int):
            # Convert relative time in seconds to absolute time
            ctx.sched_time = datetime.datetime.now() + \
                datetime.timedelta(seconds=ctx.sched_time)

        if ctx in self.scheduled_by_context:
            LOG.warning("Task %s was already scheduled, unscheduling.", ctx)
            self.cancel_task(ctx)
        # Run scheduled tasks after ctx.sched_time seconds.
        self.scheduled_by_context[ctx] = ctx.sched_time
        self.scheduled_by_queue[ctx.task_name].append(ctx)
        self.schedule[ctx.sched_time].append(ctx)
        self.scheduled_by_subject[ctx.subject].append(ctx)
        LOG.info(
            "Scheduled %s at %s",
            ctx, ctx.sched_time.strftime('%Y-%m-%d %H:%M:%S'))

    def cancel_task(self, ctx):
        """
        Remove a task from the scheduler.

        .. Note:: Tasks that were already queued for a worker to process can't
            be canceled anymore.

        :param ScheduledTaskContext ctx: A context containing data for a
            worker thread.
        :return bool: True for successfully cancelled task or False.
        """
        try:
            # Find out when it was scheduled
            sched_time = self.scheduled_by_context.pop(ctx)
            # There can be more than one task scheduled in the same time
            # slot so we need to filter out any value that is not our target
            # and leave it
            self.schedule[sched_time].remove(ctx)
            self.scheduled_by_queue[ctx.task_name].remove(ctx)
            self.scheduled_by_subject[ctx.subject].remove(ctx)
            return True
        except KeyError:
            LOG.warning("Can't unschedule, %s wasn't scheduled.", ctx)
            return False

    def get_task(self, task_name, blocking=True, timeout=None):
        """
        Get a task context from the task queue ``task``.

        :param str task_name: Task name that refers to an existsing scheduler
            queue.
        :param bool blocking: Wait until there is something to return from the
            queue.
        :raises Queue.Empty: If the underlying task queue is empty and
            blocking is False or the timout expires.
        :raises KeyError: If the task queue does not exist.
        """
        if task_name not in self._queues:
            raise KeyError("Queue with task name {} doesn't exist.", task_name)
        return self._queues[task_name].get(blocking, timeout)

    def task_done(self, task_name):
        """
        Mark a task done on a queue, this up the queue's counter of completed
        tasks.

        :param str task_name: The task queue name.
        :raises KeyError: If the task queue does not exist.
        """
        if task_name not in self._queues:
            raise KeyError("Queue with task name {} doesn't exist.", task_name)
        return self._queues[task_name].task_done()

    def run(self):
        """
        Start the scheduler thread.
        """
        LOG.info("Started a scheduler thread.")
        while not self.stop:
            self._run()
            time.sleep(self.sleep)
        LOG.debug("Goodbye cruel world..")

    def run_all(self):
        """
        Run all tasks currently queued regardless schedule time.
        """
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
            for ctx in items:
                LOG.info("Adding %s to the %s queue.", ctx, ctx.task_name)
                # Remove from reverse indexed dict
                del self.scheduled_by_context[ctx]
                self.scheduled_by_queue[ctx.task_name].remove(ctx)
                self.scheduled_by_subject[ctx.subject].remove(ctx)
                self._queues[ctx.task_name].put(ctx)
                late = datetime.datetime.now() - sched_time
                if late.seconds < 1:
                    late = ''
                elif 1 < late.seconds < 59:  # between 1 and 59 seconds
                    late = " {} seconds late".format(late.seconds)
                else:
                    late = " {} late".format(late)
                LOG.debug(
                    "Queued %s at %s%s",
                    ctx, now.strftime('%Y-%m-%d %H:%M:%S'), late)

    def cancel_by_subject(self, subject):
        """
        Cancel scheduled tasks by the task's context's subject.

        This comes down to: delete anything from the scheduler that relates to
        my object `X`.

        :param obj subject: The object you want all scheduled tasks cancelled
            for.
        """
        ctxs = self.scheduled_by_subject[subject]
        for ctx in ctxs:
            self.cancel_task(ctx)
