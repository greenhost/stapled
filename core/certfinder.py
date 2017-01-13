"""
This module locates certificate files in the given directory. It then keeps
track of the following:

  - If cert is found for the first time (thus also when the daemon is started),
    the cert is added to a queue to be analysed. The following is then
    recorded:
     - File modification time.
     - Hash of the file.
  - If a cert is found a second time, the modification time is compared to the
    recorded modification time. If it differs, the hash is compared too, if it
    too differs, the file is added to the queue for parsing again.

  - When certificates are deleted from the directories, the entries are removed
    from the central cache in :any:`core.daemon.run.contexts`.

    The cache of parsed files is volatile so every time the process is killed
    files need to be indexed again (thus files are considered "new").
"""

import threading
import time
import logging
import os
from core.certcontext import CertContext
from core.exceptions import CertValidationError

from ocspd import FILE_EXTENSIONS_DEFAULT

LOG = logging.getLogger()


class CertFinderThread(threading.Thread):
    """
    Returns a threaded or non-threaded class (not an instance) of CertFinder

    If this class is run in threaded mode, it will start a threading.Timer to
    re-run self.refresh after n seconds (10 seconds by default), if it is not
    threaded, it will sleep(n) instead.

    Pass `refresh_interval=None` if you want to run it only once (e.g. for
    testing)
    """
    # pylint: disable=too-many-instance-attributes

    def __init__(self, *args, **kwargs):
        """
            Initialise the thread's arguments and its parent
            :py:`threading.Thread`.

            Currently supported keyword arguments:

            :directories iterator required: The directories to index.
            :refresh_interval int optional: The minimum amount of time (s)
                between indexing runs, defaults to 10 seconds. Set to None
                to run only once.
            :file_extensions array optional: An array containing the file
                extensions of files to check for certificate content.
        """
        self.contexts = {}
        self.directories = kwargs.pop('directories', None)
        self.scheduler = kwargs.pop('scheduler', None)
        self.refresh_interval = kwargs.pop('refresh_interval', 10)
        self.file_extensions = kwargs.pop(
            'file_extensions', FILE_EXTENSIONS_DEFAULT
        )
        self.last_refresh = None

        assert self.directories is not None, \
            "At least one directory should be passed for indexing."

        assert self.scheduler is not None, \
            "Please pass a scheduler to add tasks to."

        super(CertFinderThread, self).__init__(*args, **kwargs)

    def run(self):
        """
        Start the certificate finder thread.
        """

        LOG.info("Scanning directories: %s", ", ".join(self.directories))
        self.refresh()
        while True:
            if self.refresh_interval is None:
                # Stop refreshing if it is not wanted.
                return

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
                self.refresh()
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
                time.sleep(self.refresh_interval - since_last)
                self.refresh()

    def _find_new_certs(self):
        """

        New files are added to the `parse_queue` for further
        processing.
        """
        try:
            for path in self.directories:
                LOG.info("Scanning directory: %s", path)
                for filename in os.listdir(path):
                    ext = os.path.splitext(filename)[1].lstrip(".")
                    if ext in self.file_extensions:
                        filename = os.path.join(path, filename)
                        if filename not in self.contexts:
                            context = CertContext(filename)
                            self.contexts[filename] = context
                            if self.parse_crt(context):
                                self.renew_queue.put(context)
        except OSError as err:
            LOG.critical(
                "Can't read directory: %s, reason: %s.",
                path, err
            )

    def _update_cached_certs(self):
        """
        Loop through the list of files that were already found and check
        whether they were deleted or changed.

        Changed files are added to the `parse_queue` for further
        processing. This makes sure only changed files are processed by the
        CPU intensive processes.

        Deleted files are removed from the found files list.
        """
        for filename, context in self.contexts.items():
            # purge certs that no longer exist in the cert dirs
            if not os.path.exists(filename):
                if filename in self.contexts:
                    del self.contexts[filename]
                LOG.info(
                    "File \"%s\" was deleted, removing it from the list.",
                    filename
                )
            elif os.path.getmtime(filename) > context.modtime:
                # purge and re-add files that have changed
                new_context = CertContext(filename)
                if new_context.hash != context.hash:
                    LOG.info(
                        "File \"%s\" was changed, adding it to the "
                        "parsing queue.",
                        filename
                    )
                    if filename in self.contexts:
                        del self.contexts[filename]
                if self.parse_crt(new_context):
                    self.renew_queue.put(new_context)

    def refresh(self):
        """
        Wraps up the internal `self._update_cached_certs()` and
        `self._find_new_certs()` functions.
        """
        self.last_refresh = time.time()
        LOG.info("Updating current cache..")
        self._update_cached_certs()
        LOG.info("Adding new certificates to cache..")
        self._find_new_certs()

    def parse_crt(self, context):
        LOG.info("Parsing file \"%s\"..", context.filename)
        try:
            context.parse_crt_chain()
            return True
        except CertValidationError as err:
            self._handle_failed_validation(context, err)
        # except KeyError as err:
        #     self._handle_failed_validation(
        #         context,
        #         "KeyError {}, processing file \"{}\"".format(
        #             err, context.filename
        #         )
        #     )
        return False

    def _handle_failed_validation(self, context, msg, delete_ocsp=True):
        LOG.critical(msg)
        # Unschedule any scheduled actions for context
        schedule_context = ScheduleContext(
            ScheduleAction(ScheduleAction.REMOVE),
            context
        )
        ScheduleAction(ScheduleAction.REMOVE_AND_IGNORE)
        self.sched_queue.put(schedule_context)
        if delete_ocsp:
            LOG.info(
                "Deleting any OCSP staple: \"%s\" if it exists.",
                context.filename
            )
            try:
                os.remove("{}.ocsp".format(context.filename))
            except IOError:
                pass
