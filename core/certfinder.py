"""
    This module locates certificate files in the given directory.
    It then keeps track of the following:

      - If cert is found for the first time (thus also when the daemon is
        started), the cert is added to a queue to be analysed. The following is
        then recorded:
         - File modification time.
         - Hash of the file.
      - If a cert is found a second time, the modification time is compared to
        the recorded modification time. If it differs, the hash is compared, if
        it too differs, the file is added to the queue for analysis.
"""

import threading
import time
import logging
import os
from models.certificates import CertFile

LOG = logging.getLogger()

FILE_EXTENSIONS_DEFAULT = 'crt,pem,cer'


def _cert_finder_factory(threaded=True):
    """
        Returns a threaded or non-threaded class (not an instance) of
            CertFinder

        :param bool threaded: Should the returned class be threaded?
        :return class: _CertFinder class threaded if threaded argument == True
    """

    if threaded:
        base_object = threading.Thread
    else:
        base_object = object

    class _CertFinder(base_object):
        """
            This object can be used to index directories and search for
            certificate files. When found they will be added to the supplied
            queue for further processing.

            If this class is run in threaded mode, it will start a
            threading.Timer to re-run self.refresh after n seconds (10 seconds
            by default), if it is not threaded, it will sleep(n) instead.

            Pass `refresh_interval=None` if you want to run it only once (e.g.
            for testing)
        """

        def __init__(self, *args, **kwargs):
            """
                The object can either be started threaded or non-threaded.
                If it is running in threaded mode we need to initialise the
                super class first.
                :param tuple *args: Any positional arguments passed to the
                    threaded object
                :param dict **kwargs: Any keyword arguments passed to the
                    threaded object

                Currently supported keyword arguments:

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
            self.last_refresh = None
            self.files = {}
            self.directories = kwargs.pop('directories', None)
            self.parse_queue = kwargs.pop('parse_queue', None)
            self.ignore_list = kwargs.pop('ignore_list', [])
            self.cert_list = kwargs.pop('cert_list', None)
            self.refresh_interval = kwargs.pop('refresh_interval', 10)
            self.file_extensions = kwargs.pop(
                'file_extensions', FILE_EXTENSIONS_DEFAULT
            )
            if base_object is threading.Thread:
                super(_CertFinder, self).__init__()
                self.threaded = True
                tid = kwargs.pop('tid', 0)
                # self.name = "cert-finder-{}".format(tid)
                self.name = "cert-finder"
                self.daemon = False
                self.start()
            else:
                self.threaded = False
                self.run(*args, **kwargs)

        def run(self, *args, **kwargs):
            """
                Start the thread if threaded, otherwise just run the same
                process.
            """
            if self.directories is None:
                raise ValueError(
                    "At least one directory should be passed for indexing."
                )
            if self.parse_queue is None:
                raise ValueError(
                    "You need to pass a queue where found certificates can be "
                    "queued for parsing."
                )
            if self.cert_list is None:
                raise ValueError(
                    "You need to pass a dict for certificate data to be kept."
                )
            LOG.info("Scanning directories: %s", ", ".join(self.directories))
            while True:
                self.refresh()
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
                Locate certificates that were not found before.
                The list of files is volatile so every time the process is
                killed files need to be indexed again (thus files are
                considered new).

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
                            if filename not in self.files and \
                                    filename not in self.ignore_list:
                                new_cert = CertFile(filename)
                                self.files[filename] = new_cert
                                self.parse_queue.put(new_cert)
            except OSError as err:
                LOG.error(
                    "Can't read directory: %s, reason: %s.",
                    path, err
                )

        def _update_cached_certs(self):
            """
                Loop through the list of files that were already found and
                check whether they were deleted or changed.

                Changed files are added to the `parse_queue` for further
                processing. This makes sure only changed files are processed
                by the CPU intensive processes.

                Deleted files are removed from the found files list.
            """
            for filename, cert_file in self.files.items():
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
                    new_cert = CertFile(filename)
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
                Wraps up the internal `self._find_new_certs()` and
                `self._find_new_certs()` functions and sets a next iteration of
                itself if wanted.
            """

            self.last_refresh = time.time()
            LOG.info("Updating current cache..")
            self._update_cached_certs()
            LOG.info("Adding new certificates to cache..")
            self._find_new_certs()

            LOG.debug(
                "Queue info: %s items in parse queue.",
                self.parse_queue.qsize()
            )

    return _CertFinder

# Create the objects for a threaded and a non-threaded CertFinder
CertFinderThreaded = _cert_finder_factory()
CertFinder = _cert_finder_factory(threaded=False)
