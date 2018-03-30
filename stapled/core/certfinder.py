# -*- coding: utf-8 -*-
"""
This module locates certificate files in the supplied paths and parses
them. It then keeps track of the following:

- If cert is found for the first time (thus also when the daemon is started),
  the cert is added to the :attr:`stapled.core.certfinder.CertFinder.scheduler`
  so the :class:`~stapled.core.certparser.CertParserThread` can parse the
  certificate. The file modification time is recorded so file changes can be
  detected.

- If a cert is found a second time, the modification time is compared to the
  recorded modification time. If it differs, if it differs, the file is added
  to the scheduler for parsing again, any scheduled actions for the old file
  are cancelled.

- When certificates are deleted from the paths, the entries are removed
  from the cache in :attr:`stapled.core.daemon.run.models`. Any scheduled
  actions for deleted files are cancelled.

The cache of parsed files is volatile so every time the process is killed
files need to be indexed again (thus files are considered "new").
"""

import threading
import time
import logging
import fnmatch
import os
import stapled
import errno
from stapled.core.excepthandler import stapled_except_handle
from stapled.core.taskcontext import StapleTaskContext
from stapled.core.certmodel import CertModel
from stapled.util.cache import cache

LOG = logging.getLogger(__name__)


class CertFinderThread(threading.Thread):
    """
    This searches paths for certificate files.
    When found, models are created for the certificate files, which are wrapped
    in a :class:`stapled.core.taskcontext.StapleTaskContext` which are then
    scheduled to be processed by the
    :class:`stapled.core.certparser.CertParserThread` ASAP.

    Pass ``refresh_interval=None`` if you want to run it only once (e.g. for
    testing)
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self, *args, **kwargs):
        """
        Initialise the thread with its parent :class:`threading.Thread` and its
        arguments.

        :kwarg dict models: A dict to maintain a model cache **(required)**.
        :kwarg iter cert_paths: The paths to index **(required)**.
        :kwarg stapled.scheduling.SchedulerThread scheduler: The scheduler
            object where we add new parse tasks to. **(required)**.
        :kwarg int refresh_interval: The minimum amount of time (s)
            between search runs, defaults to 10 seconds. Set to None to run
            only once **(optional)**.
        :kwarg array file_extensions: An array containing the file extensions
            of file types to check for certificate content **(optional)**.
        """
        self.stop = False
        self.models = kwargs.pop('models', None)
        self.cert_paths = kwargs.pop('cert_paths', None)
        self.scheduler = kwargs.pop('scheduler', None)
        self.refresh_interval = kwargs.pop(
            'refresh_interval', stapled.DEFAULT_REFRESH_INTERVAL
        )
        self.file_extensions = kwargs.pop(
            'file_extensions', stapled.FILE_EXTENSIONS_DEFAULT
        )
        self.last_refresh = None
        self.ignore = kwargs.pop('ignore', []) or []
        self.recursive = kwargs.pop('recursive', False)

        assert self.models is not None, \
            "You need to pass a dict to hold the certificate model cache."

        assert self.cert_paths is not None, \
            "At least one path should be passed for indexing."

        assert self.scheduler is not None, \
            "Please pass a scheduler to get tasks from and add tasks to."

        super(CertFinderThread, self).__init__(*args, **kwargs)

    def run(self):
        """Start the certificate finder thread."""
        LOG.info("Scanning paths: '%s'", "', '".join(self.cert_paths))
        while not self.stop:
            # Catch any exceptions within this context to protect the thread.
            with stapled_except_handle():
                self.refresh()
                if self.refresh_interval is None:
                    # Stop refreshing if it is not wanted.
                    break
                # Schedule the next refresh run..
                since_last = time.time() - self.last_refresh
                # Check if the last refresh took longer than the interval..
                if since_last > self.refresh_interval:
                    # It did so start right now..
                    LOG.info(
                        "Starting a new refresh immediately because the last "
                        "refresh took %0.3f seconds while the minimum "
                        "interval is %d seconds.",
                        since_last,
                        self.refresh_interval
                    )
                else:
                    # Wait the remaining time before refreshing again..
                    LOG.info(
                        "Scheduling a new refresh in %0.2f seconds because "
                        "the last refresh took %0.2f seconds while the "
                        "minimum interval is %d seconds.",
                        self.refresh_interval - since_last,
                        since_last,
                        self.refresh_interval
                    )
                    sleep_time = self.refresh_interval - since_last
                    while sleep_time > 0:
                        if self.stop:
                            break
                        time.sleep(1)
                        sleep_time = sleep_time - 1
        LOG.debug("Goodbye cruel world..")

    def refresh(self):
        """
        Wrap up the internal :meth:`CertFinder._update_cached_certs()` and
        :meth:`CertFinder._find_new_certs()` functions.

        ..  Note:: This method is automatically called by
            :meth:`CertFinder.run()`
        """
        self.last_refresh = time.time()
        LOG.info("Starting a refresh run.")
        self._update_cached_certs()
        self._find_new_certs(self.cert_paths)

    def _find_new_certs(self, paths, force_cert_path=None):
        """
        Locate new files, schedule them for parsing.

        :param list|tuple paths: Paths to scan for certificates.
        :param str|Nonetype force_cert_path: Parent path as specified in the
            CLI arguments. Necessary to link certificates found in `paths` to
            any configured sockets.
        :raises stapled.core.exceptions.CertFileAccessError: When the
            certificate file can't be accessed.
        """
        for path in paths:
            if force_cert_path:
                # Keep this value so we know in which directory it was found.
                # Only keep the highest level, equal to what was supplied as
                # an argument or in config.
                cert_path = force_cert_path
            else:
                cert_path = path

            try:
                LOG.debug("Scanning path: %s", path)
                dirs = []
                try:
                    dirs = os.listdir(path)
                except (OSError, IOError) as exc:
                    # If a path is actually a file we can still use it..
                    if exc.errno == errno.ENOTDIR and os.path.isfile(path):
                        LOG.debug("%s may be a single file", path)
                        # This will allow us to use our usual iteration.
                        dirs = [os.path.basename(path)]
                        path = os.path.dirname(path)
                    else:
                        raise exc
                for entry in dirs:
                    entry = os.path.join(path, entry)
                    if os.path.isdir(entry):
                        if self.recursive:
                            LOG.debug("Recursing path %s", entry)
                            self._find_new_certs([entry], cert_path)
                        continue
                    ext = os.path.splitext(entry)[1].lstrip(".")
                    if ext not in self.file_extensions:
                        continue
                    if entry in self.models:
                        continue
                    if self.check_ignore(entry):
                        LOG.debug(
                            "Ignoring file %s, because it's on the ignore "
                            "list.",
                            entry
                        )
                        continue
                    model = CertModel(entry, cert_path=cert_path)
                    # Remember the model so we can compare the file later to
                    # see if it changed.
                    self.models[entry] = model
                    # Schedule the certificate for parsing.
                    context = StapleTaskContext(
                        task_name="parse",
                        model=model,
                        sched_time=None
                    )
                    self.scheduler.add_task(context)
            except (IOError, OSError) as exc:
                # If the directory is unreadable this gets printed at every
                # refresh until the directory is readable. We catch this here
                # so any readable directory can still be scanned.
                LOG.critical(
                    "Can't read path: %s, reason: %s.",
                    path, exc
                )

    def _del_model(self, filename):
        """
        Delete model from :attr:`stapled.core.daemon.run.models`.

        This is done in a thread-safe manner, if another thread deleted it,
        we should ignore the KeyError making this function omnipotent.

        :param str filename: The filename of the model to forget about.
        """
        try:
            del self.models[filename]
        except KeyError:
            pass

    def _update_cached_certs(self):
        """
        Check for deleted or changed certificate files.

        Loop through the list of files that were already found and check
        whether they were deleted or changed.

        If a file was modified since it was last seen, the file is added to the
        scheduler to get the new certificate data parsed.

        Deleted files are removed from the model cache in
        :attr:`stapled.core.daemon.run.models`. Any scheduled tasks for the
        model's task context are cancelled.

        :raises stapled.core.exceptions.CertFileAccessError: When the
            certificate file can't be accessed.
        """
        deleted = []
        changed = []
        for filename, model in self.models.items():
            if not os.path.exists(filename):
                deleted.append(filename)
            elif os.path.getmtime(filename) > model.modtime:
                changed.append(filename)

        # Purge certs that no longer exist in the cert dirs
        for filename in deleted:
            # Cancel any scheduled tasks for the model.
            self.scheduler.cancel_by_subject(self.models[filename])
            # Remove the model from cache
            self._del_model(filename)
            LOG.info(
                "File %s was deleted, removing it from the cache.", filename)

        # Re-add files that have changed, we will make a new model so the model
        # is an accurate representation of what is in the cerificate file on
        # disk, this is just to prevent any stale data being used in the
        # process. Making the new model and scheduling a parse will make go
        # through all the steps to get the certificate stapled ASAP again.
        for filename in changed:
            # Cancel any scheduled tasks for the model.
            self.scheduler.cancel_by_subject(self.models[filename])
            # Before deleting the model from cache take relevant information
            # that will be lost
            cert_path = self.models[filename].cert_path
            # Remove the model from cache.
            self._del_model(filename)
            # Make a new model.
            LOG.info("File %s changed, parsing it again.", filename)
            new_model = CertModel(filename, cert_path)
            context = StapleTaskContext(
                task_name="parse", model=new_model, sched_time=None)
            self.scheduler.add_task(context)

    @cache(10000)
    def check_ignore(self, path):
        """
        Check if a file path matches any pattern in the ignore list.

        :param str path: Path to match a pattern in ``self.ignore``.
        """
        for pattern in self.ignore:
            # Strip spaces, check if length still greater than 0
            pattern = pattern.strip()
            if len(pattern) == 0:
                continue
            # If pattern starts with / it is absolute, do nothing, if not, add
            # ``**`` to make fnmatch match any parent directory.
            if pattern[0] != '/':
                pattern = "**{}".format(pattern)
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
