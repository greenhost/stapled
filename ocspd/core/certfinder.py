# -*- coding: utf-8 -*-
"""
This module locates certificate files in the supplied directories and parses
them. It then keeps track of the following:

- If cert is found for the first time (thus also when the daemon is started),
  the cert is added to the :attr:`ocspd.core.certfinder.CertFinder.scheduler`
  so the :class:`~ocspd.core.certparser.CertParserThread` can parse the
  certificate. The file modification time is recorded so file changes can be
  detected.

- If a cert is found a second time, the modification time is compared to the
  recorded modification time. If it differs, if it differs, the file is added
  to the scheduler for parsing again, any scheduled actions for the old file
  are cancelled.

- When certificates are deleted from the directories, the entries are removed
  from the cache in :attr:`ocspd.core.daemon.run.models`. Any scheduled actions
  for deleted files are cancelled.

The cache of parsed files is volatile so every time the process is killed
files need to be indexed again (thus files are considered "new").
"""

import threading
import time
import logging
import re
import os
import ocspd
from ocspd.core.excepthandler import ocsp_except_handle
from ocspd.core.taskcontext import OCSPTaskContext
from ocspd.core.certmodel import CertModel
from ocspd.util.cache import cache

LOG = logging.getLogger(__name__)


class CertFinderThread(threading.Thread):
    """
    This searches directories for certificate files.
    When found, models are created for the certificate files, which are wrapped
    in a :class:`ocspd.core.taskcontext.OCSPTaskContext` which are then
    scheduled to be processed by the
    :class:`ocspd.core.certparser.CertParserThread` ASAP.

    Pass ``refresh_interval=None`` if you want to run it only once (e.g. for
    testing)
    """
    # pylint: disable=too-many-instance-attributes
    def __init__(self, *args, **kwargs):
        """
        Initialise the thread with its parent :class:`threading.Thread` and its
        arguments.

        :kwarg dict models: A dict to maintain a model cache **(required)**.
        :kwarg iter directories: The directories to index **(required)**.
        :kwarg ocspd.scheduling.SchedulerThread scheduler: The scheduler object
            where we add new parse tasks to. **(required)**.
        :kwarg int refresh_interval: The minimum amount of time (s)
            between search runs, defaults to 10 seconds. Set to None to run
            only once **(optional)**.
        :kwarg array file_extensions: An array containing the file extensions
            of file types to check for certificate content **(optional)**.
        """
        self.stop = False
        self.models = kwargs.pop('models', None)
        self.directories = kwargs.pop('directories', None)
        self.scheduler = kwargs.pop('scheduler', None)
        self.refresh_interval = kwargs.pop(
            'refresh_interval', ocspd.DEFAULT_REFRESH_INTERVAL
        )
        self.file_extensions = kwargs.pop(
            'file_extensions', ocspd.FILE_EXTENSIONS_DEFAULT
        )
        self.last_refresh = None
        self.ignore = kwargs.pop('ignore', [])

        assert self.models is not None, \
            "You need to pass a dict to hold the certificate model cache."

        assert self.directories is not None, \
            "At least one directory should be passed for indexing."

        assert self.scheduler is not None, \
            "Please pass a scheduler to get tasks from and add tasks to."

        super(CertFinderThread, self).__init__(*args, **kwargs)

    def run(self):
        """
        Start the certificate finder thread.
        """

        LOG.info("Scanning directories: %s", ", ".join(self.directories))

        while not self.stop:
            # Catch any exceptions within this context to protect the thread.
            with ocsp_except_handle():
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
        Wraps up the internal :meth:`CertFinder._update_cached_certs()` and
        :meth:`CertFinder._find_new_certs()` functions.

        ..  Note:: This method is automatically called by
            :meth:`CertFinder.run()`
        """
        self.last_refresh = time.time()
        LOG.info("Updating current cache..")
        self._update_cached_certs()
        LOG.info("Adding new certificates to cache..")
        self._find_new_certs()

    def _find_new_certs(self):
        """
        Locate new files, schedule them for parsing.

        :raises ocspd.core.exceptions.CertFileAccessError: When the certificate
            file can't be accessed.
        """
        for path in self.directories:
            try:
                LOG.info("Scanning directory: %s", path)
                for filename in os.listdir(path):
                    ext = os.path.splitext(filename)[1].lstrip(".")
                    if ext not in self.file_extensions:
                        continue
                    filename = os.path.join(path, filename)
                    if filename in self.models:
                        continue
                    if self.check_ignore(filename):
                        LOG.debug(
                            "Ignoring file %s, because it's on the ignore "
                            "list.",
                            filename
                        )
                        continue
                    model = CertModel(filename)
                    # Remember the model so we can compare the file later to
                    # see if it changed.
                    self.models[filename] = model
                    # Schedule the certificate for parsing.
                    context = OCSPTaskContext(
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
                    "Can't read directory: %s, reason: %s.",
                    path, exc
                )

    def _del_model(self, filename):
        """
        Delete model from :attr:`ocspd.core.daemon.run.models` in a thread-safe
        manner, if another thread deleted it, we should ignore the KeyError
        making this function omnipotent.

        :param str filename: The filename of the model to forget about.
        """
        try:
            del self.models[filename]
        except KeyError:
            pass

    def _update_cached_certs(self):
        """
        Loop through the list of files that were already found and check
        whether they were deleted or changed.

        If a file was modified since it was last seen, the file is added to the
        scheduler to get the new certificate data parsed.

        Deleted files are removed from the model cache in
        :attr:`ocspd.core.daemon.run.models`. Any scheduled tasks for the
        model's task context are cancelled.

        :raises ocspd.core.exceptions.CertFileAccessError: When the certificate
            file can't be accessed.
        """
        deleted = []
        changed = []
        for filename, model in self.models.items():
            if not os.path.exists(filename):
                deleted.append(filename)
            elif os.path.getmtime(filename) > model.modtime:
                changed.append(filename)

        # purge certs that no longer exist in the cert dirs
        for filename in deleted:
            # Cancel any scheduled tasks for the model.
            self.scheduler.cancel_by_subject(self.models[filename])
            # Remove the model from cache
            self._del_model(filename)
            LOG.info(
                "File %s was deleted, removing it from the cache.", filename)

        # re-add files that have changed
        for filename in changed:
            # Cancel any scheduled tasks for the model.
            self.scheduler.cancel_by_subject(self.models[filename])
            # Remove the model from cache.
            self._del_model(filename)
            # Make a new model.
            LOG.info("File %s changed, parsing it again.", filename)
            new_model = CertModel(filename)
            context = OCSPTaskContext(
                task_name="parse", model=new_model, sched_time=None)
            self.scheduler.add_task(context)

    @cache(10000)
    def check_ignore(self, path):
        """
        Check if a file path matches any pattern in the ignore list.

        :param str path: Path to a file to match.
        """
        for pattern in self.ignore:
            regex = self.compile_pattern(pattern)
            if regex.match(path):
                return True
        return False

    @staticmethod
    @cache(100)
    def compile_pattern(pattern):
        """
        Compile a glob pattern and return a compiled regex object.

        :param str pattern: Glob pattern.
        """
        # Absolute or relative path
        if not pattern.startswith(os.sep) or pattern.startswith("*"):
            begin_regex = "^.*"  # relative
        else:
            begin_regex = "^{}".format(os.sep)  # absolute

        if pattern.endswith(os.sep) or pattern.endswith("*"):
            end_regex = ".*$"  # anything below this path matches
        else:
            end_regex = "$"  # only exactly this file name matches

        pattern = pattern.lstrip("*{}".format(os.sep))
        pattern = pattern.rstrip("*")

        # Escape some characters
        middle_regex = re.escape(pattern)
        # Question marks replace any 1 character
        middle_regex = middle_regex.replace("\?", ".")
        # Double stars replace anything including "/" lazily
        middle_regex = middle_regex.replace("\*\*", ".*?/?".format(os.sep))
        # Single star replaces anthing but "/"
        middle_regex = middle_regex.replace("\*", "[^{}]*".format(os.sep))

        regex = "{}{}{}".format(
            begin_regex,
            middle_regex,
            end_regex
        )
        return re.compile(regex, re.IGNORECASE)
