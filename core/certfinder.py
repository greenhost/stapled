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
from ocsp import FILE_EXTENSIONS_DEFAULT

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

    def __init__(self, *args, **kwargs):
        """
            Initialise the thread's arguments and its parent
            :py:`threading.Thread`.

            Currently supported keyword arguments:

            :cli_args argparse.Namespace: The parsed CLI arguments namespace.
            :contexts dict required: The cache of parsed certificates with OCSP
                data if it was already been requested by the
                :class:`core.ocsprenewer.OCSPRenewerThread`.
            :directories iterator required: The directories to index.
            :parse_queue Queue required: The queue to add found certs to
                for parsing.
            :refresh_interval int optional: The minimum amount of time (s)
                between indexing runs, defaults to 10 seconds. Set to None
                to run only once.
            :file_extensions array optional: An array containing the file
                extensions of files to check for certificate content.
            :ignore_list array optional: List of files to ignore.
        """
        self.cli_args = kwargs.pop('cli_args', None)
        self.contexts = kwargs.pop('contexts', None)
        self.directories = kwargs.pop('directories', None)
        self.parse_queue = kwargs.pop('parse_queue', None)
        self.refresh_interval = kwargs.pop('refresh_interval', 10)
        self.file_extensions = kwargs.pop(
            'file_extensions', FILE_EXTENSIONS_DEFAULT
        )
        self.ignore_list = kwargs.pop('ignore_list', [])
        self.last_refresh = None

        assert self.cli_args is not None, \
            "You need to pass a argparser.NameSpace with CLI arguments."
        assert self.contexts is not None, \
            "Contexts dict for keeping certificate contexts should be passed."
        assert self.directories is not None, \
            "At least one directory should be passed for indexing."
        assert self.parse_queue is not None, \
            "A parsing queue where found certificates should be passed."

        super(CertFinderThread, self).__init__(*args, **kwargs)

    def run(self, *args, **kwargs):
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
                        if filename not in self.contexts and \
                                filename not in self.ignore_list:
                            context = CertContext(filename)
                            self.contexts[filename] = context
                            self.parse_queue.put(context)
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
        for filename, cert_file in self.contexts.items():
            # purge certs that no longer exist in the cert dirs
            if not os.path.exists(filename):
                if filename in self.cert_list:
                    del self.cert_list[filename]
                LOG.info(
                    "File \"%s\" was deleted, removing it from the list.",
                    filename
                )
                continue
            # purge and re-add files that have changed
            if os.path.getmtime(filename) > cert_file.modtime:
                new_cert = CertContext(filename)
                if new_cert.hash != cert_file.hash:
                    LOG.info(
                        "File \"%s\" was changed, adding it to the "
                        "parsing queue.",
                        filename
                    )
                    if filename in self.cert_list:
                        del self.cert_list[filename]
                    self.parse_queue.put(new_cert)
                    continue

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
