# -*- coding: utf-8 -*-
"""
This module bootstraps the stapled process by starting threads for:

- 1x :class:`stapled.scheduling.SchedulerThread`

  Can be used to create action queues that where tasks can be added that are
  either added to the action queue immediately or at a set time in the future.

- 1x :class:`stapled.core.certfinder.CertFinderThread`

  - Finds certificate files in the specified certificate paths at regular
    intervals.
  - Removes deleted certificates from the context cache in
    :attr:`stapled.core.daemon.run.models`.
  - Add the found certificate to the the parse action queue of the scheduler
    for parsing the certificate file.

- 1x :class:`stapled.core.certparser.CertParserThread`

  - Parses certificates and caches parsed certificates in
    :attr:`stapled.core.daemon.run.models`.
  - Add the parsed certificate to the the renew action queue of the scheduler
    for requesting or renewing the OCSP staple.

- 2x (or more depending on the ``-t`` CLI argument)
  :class:`stapled.core.staplerenewer.StapleRenewerThread`

  - Gets tasks from the scheduler in :attr:`self.scheduler` which is a
    :class:`stapled.scheduling.Scheduler` object passed by this module.
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

- 1x :class:`stapled.core.stapleadder.StapleAdder` **(optional)**

  Takes tasks ``haproxy-add`` from the scheduler and communicates OCSP staples
  updates to HAProxy through a HAProxy socket.

"""
import logging
import time
import threading
import signal
import re
from stapled.core.certfinder import CertFinderThread
from stapled.core.certparser import CertParserThread
from stapled.core.staplerenewer import StapleRenewerThread
from stapled.core.stapleadder import StapleAdder
from stapled.scheduling import SchedulerThread
from stapled import MAX_RESTART_THREADS

LOG = logging.getLogger(__name__)


class Stapledaemon(object):

    def __init__(self, **kwargs):
        """
        Creates queues and spawns the threads documented above.
        Threads are not started as daemons so this will run indefinitely unless
        the entire process is halted or all threads are killed.

        :param **dict kwargs: Parsed CLI arguments and configurations.
        :kwarg list cert_paths: A list of certificate paths to scan for
            certificates.
        :kwarg dict|NoneType haproxy_socket_mapping: A mapping of certificate
            directories and corresponding HAProxy sockets or None.
        :kwarg list file_extensions: List of file extensions to search for
            certificates.
        :kwarg int renewal_threads: Amount of staple renewal threads.
        :kwarg int refresh_interval: Interval between re-indexing of
            certificate paths.
        :kwarg int minimum_validity: Minimum validity of stapled before
            renewing.
        :kwarg bool recursive: Recursively scan certificate directories.
        :kwarg list ignore: List of paths to ignore during indexing of
            certificate directories.
        """
        LOG.debug("Started with CLI args: %s", str(kwargs))
        self.cert_paths = kwargs.pop('cert_paths', None)
        self.haproxy_socket_mapping = kwargs.pop(
            'haproxy_socket_mapping', None
        )
        self.haproxy_socket_keepalive = kwargs.pop('haproxy_socket_keepalive')
        self.file_extensions = kwargs.pop('file_extensions')
        self.file_extensions = self.file_extensions.replace(" ", "").split(",")
        self.renewal_threads = kwargs.pop('renewal_threads')
        self.refresh_interval = kwargs.pop('refresh_interval')
        self.minimum_validity = kwargs.pop('minimum_validity')
        self.recursive = kwargs.pop('recursive')
        self.no_recycle = kwargs.pop('no_recycle')

        self.ignore = []
        rel_path_re = re.compile(r'^\.+\/')
        ignore = kwargs.pop('ignore', None)
        if ignore is not None:
            # Filter out patterns that look like relative paths, e.g.:
            # ./cert.pem and ../certs/*.crt, i.e. starts with one or more
            # ``.`` followed by ``/``.
            for pattern in ignore:
                if rel_path_re.match(pattern) is not None:
                    LOG.warn(
                        "Pattern %s seems to be a relative path, rather than a"
                        "pattern, ignoring this pattern.",
                        pattern
                    )
                else:
                    self.ignore.append(pattern)

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
        if self.haproxy_socket_mapping:
            self.start_staple_adder_thread()

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
        """Set self.stop so the main thread stops."""
        LOG.info("Exiting with signal number %d", signum)
        self.stop = True

    def start_scheduler_thread(self):
        """Spawn a scheduler thread with the appropriate keyword arguments."""
        return self.__spawn_thread(
            name="scheduler",
            thread_object=SchedulerThread,
            queues=["parse", "renew", "proxy-add"]
        )

    def start_staple_adder_thread(self):
        """Spawns a StapleAdder thread."""
        return self.__spawn_thread(
            name="proxy-adder",
            thread_object=StapleAdder,
            haproxy_socket_mapping=self.haproxy_socket_mapping,
            haproxy_socket_keepalive=self.haproxy_socket_keepalive,
            scheduler=self.scheduler
        )

    def start_finder_thread(self):
        """Spawn a finder thread."""
        return self.__spawn_thread(
            name="finder",
            thread_object=CertFinderThread,
            models=self.model_cache,
            cert_paths=self.cert_paths,
            refresh_interval=self.refresh_interval,
            file_extensions=self.file_extensions,
            scheduler=self.scheduler,
            ignore=self.ignore,
            recursive=self.recursive
        )

    def start_renewer_thread(self, tid):
        """Spawn a Staple renewer thread."""
        return self.__spawn_thread(
            name="renewer-{:02d}".format(tid),
            thread_object=StapleRenewerThread,
            minimum_validity=self.minimum_validity,
            scheduler=self.scheduler
        )

    def start_parser_thread(self):
        """Spawn a parser thread ."""
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
        Monitor and manage threads.

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
                        restarted=thread['restarted'] + 1,
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
