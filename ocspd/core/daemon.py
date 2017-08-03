# -*- coding: utf-8 -*-
"""
This module bootstraps the ocspd process by starting threads for:

- 1x :class:`ocspd.scheduling.SchedulerThread`

  Can be used to create action queues that where tasks can be added that are
  either added to the action queue immediately or at a set time in the future.

- 1x :class:`ocspd.core.certfinder.CertFinderThread`

  - Finds certificate files in the specified directories at regular intervals.
  - Removes deleted certificates from the context cache in
    :attr:`ocspd.core.daemon.run.models`.
  - Add the found certificate to the the parse action queue of the scheduler
    for parsing the certificate file.

- 1x :class:`ocspd.core.certparser.CertParserThread`

  - Parses certificates and caches parsed certificates in
    :attr:`ocspd.core.daemon.run.models`.
  - Add the parsed certificate to the the renew action queue of the scheduler
    for requesting or renewing the OCSP staple.

- 2x (or more depending on the ``-t`` CLI argument)
  :class:`ocspd.core.ocsprenewer.OCSPRenewerThread`

  - Gets tasks from the scheduler in :attr:`self.scheduler` which is a
    :class:`ocspd.scheduling.Scheduler` object passed by this module.
  - For each task:
     - Validates the certificate chains.
     - Renews the OCSP staples.
     - Validates the certificate chains again but this time including the OCSP
       staple.
     - Writes the OCSP staple to disk.
     - Schedules a renewal at a configurable time before the expiration of the
       OCSP staple.

  The main reason for spawning multiple threads for this is that the OCSP
  request is a blocking action that also takes relatively long to complete.
  If any of these request stall for long, the entire daemon doesn't stop
  working until it is no longer stalled.

- 1x :class:`ocspd.core.ocspadder.OCSPAdder` **(optional)**

  Takes tasks ``haproxy-add`` from the scheduler and communicates OCSP staples
  updates to HAProxy through a HAProxy socket.

"""
import logging
import time
import threading
import signal
from ocspd.core.certfinder import CertFinderThread
from ocspd.core.certparser import CertParserThread
from ocspd.core.ocsprenewer import OCSPRenewerThread
from ocspd.core.ocspadder import OCSPAdder
from ocspd.scheduling import SchedulerThread
from ocspd import MAX_RESTART_THREADS

LOG = logging.getLogger(__name__)


class OCSPDaemon(object):

    def __init__(self, args):
        """
        Creates queues and spawns the threads documented above.
        Threads are not started as daemons so this will run indefinitely unless
        the entire process is halted or all threads are killed.

        :param argparse.Namespace args: Parsed CLI arguments
        """
        LOG.debug("Started with CLI args: %s", str(args))
        self.directories = args.directories
        self.sockets = args.haproxy_sockets
        self.socket_paths = None
        if self.sockets:
            if len(self.directories) != len(self.sockets):
                raise ValueError("#sockets does not equal #directories")
            # Make a mapping from directory to socket
            self.socket_paths = dict(zip(self.directories, self.sockets))
        self.file_extensions = args.file_extensions.replace(" ", "").split(",")
        self.renewal_threads = args.renewal_threads
        self.refresh_interval = args.refresh_interval
        self.minimum_validity = args.minimum_validity
        self.no_recycle = args.no_recycle
        self.model_cache = {}
        self.all_threads = []
        self.stop = False

        # Listen to SIGINT and SIGTERM
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

        LOG.info(
            "Starting OCSP Stapling daemon, finding files of types: %s with "
            "%d threads.",
            ", ".join(self.file_extensions),
            self.renewal_threads
        )

        # Scheduler thread
        self.scheduler = self.start_scheduler_thread()

        # Start proxy adder thread if sockets were supplied
        if self.socket_paths:
            self.start_ocsp_adder_thread()

        # Start ocsp response gathering threads
        threads_list = []
        for tid in range(0, self.renewal_threads):
            threads_list.append(self.start_renewer_thread(tid))

        # Start certificate parser thread
        self.parser = self.start_parser_thread()
        # Start certificate finding thread
        self.finder = self.start_finder_thread()

        self.monitor_threads()

    def exit_gracefully(self, signum, _frame):
        """
        Sets self.stop so the main thread stops
        """
        LOG.info("Exiting with signal number %d", signum)
        self.stop = True

    def start_scheduler_thread(self):
        """
        Spawns a scheduler thread with the appropriate keyword arguments.
        """
        return self.__spawn_thread(
            name="scheduler",
            thread_object=SchedulerThread,
            queues=["parse", "renew", "proxy-add"]
        )

    def start_ocsp_adder_thread(self):
        """
        Spawns a OCSP Proxy adder thread with the appropriate keyword
        arguments.
        """
        return self.__spawn_thread(
            name="proxy-adder",
            thread_object=OCSPAdder,
            socket_paths=self.socket_paths,
            scheduler=self.scheduler
        )

    def start_finder_thread(self):
        """
        Spawns a finder thread with the appropriate keyword arguments.
        """
        return self.__spawn_thread(
            name="finder",
            thread_object=CertFinderThread,
            models=self.model_cache,
            directories=self.directories,
            refresh_interval=self.refresh_interval,
            file_extensions=self.file_extensions,
            scheduler=self.scheduler
        )

    def start_renewer_thread(self, tid):
        """
        Spawns an OCSP renewer thread with the appropriate keyword arguments.
        """
        return self.__spawn_thread(
            name="renewer-{:02d}".format(tid),
            thread_object=OCSPRenewerThread,
            minimum_validity=self.minimum_validity,
            scheduler=self.scheduler
        )

    def start_parser_thread(self):
        """
        Spawns a parser thread with the appropriate keyword arguments.
        """
        return self.__spawn_thread(
            name="parser",
            thread_object=CertParserThread,
            models=self.model_cache,
            minimum_validity=self.minimum_validity,
            no_recycle=self.no_recycle,
            scheduler=self.scheduler
        )

    def monitor_threads(self):
        """
        Check if any threads have died, respawn them until the
        MAX_RESTART_THREADS limit is reached. Wait for a KeyBoardInterrupt,
        when it comes, tell all threads to stop and wait for them to stop.
        """
        while not self.stop:
            restart = []
            # Find crashed threads
            for key, thread in enumerate(self.all_threads):
                if not thread['thread'].is_alive():
                    restart.append(key)
            # Respawn crashed threads
            for key in restart:
                thread = self.all_threads.pop(key)
                if thread['restarted'] < MAX_RESTART_THREADS:
                    LOG.error(
                        "Thread: %s, type: %s was found dead, spawning a "
                        "new one now..",
                        thread['name'],
                        thread['object']
                    )
                    self.__spawn_thread(
                        name=thread['name'],
                        thread_object=thread['object'],
                        restarted=thread['restarted']+1,
                        **thread['kwargs']
                    )
                else:
                    LOG.critical(
                        "Thread: %s, type: %s was found dead, it died %s "
                        "times already, will not respawn again.",
                        thread['name'],
                        thread['object'],
                        thread['restarted']
                    )
            time.sleep(0.25)

        # This code is executed when self.stop is True
        LOG.info("Stopping all threads..")
        for thread in self.all_threads:
            thread['thread'].stop = True
        for thread in threading.enumerate():
            LOG.info("Waiting for thread %s to stop..", thread.name)
            try:
                thread.join()
            except RuntimeError:
                pass  # cannot join current thread
        LOG.info("Stopping daemon thread")

    def __spawn_thread(self, name, thread_object, restarted=0, **kwargs):
        """
        Spawns threads based on obejects and registers them in a dictionary.
        Also remembers how the thread was started.

        :param str name: Name of the thread
        :param class thread_object: Object to spawn (must extend
            threading.Thread)
        :param str name: How many times a
        :param str name: Name of the thread
        """
        thread_obj = thread_object(**kwargs)
        thread_obj.daemon = False
        thread_obj.name = name
        thread_obj.start()
        # Remember running threads and how to create them.
        self.all_threads.append({
            'object': thread_object,
            'kwargs': kwargs,
            'thread': thread_obj,
            'name': name,
            'restarted': restarted
        })
        return thread_obj
