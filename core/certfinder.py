"""
This module locates certificate files in the supplied directories and parses
them. It then keeps track of the following:

  - If cert is found for the first time (thus also when the daemon is started),
    the cert is added to the :attr:`core.certfinder.CertFinder.scheduler`
    so an OCSP request can be done by one of the
    :class:`core.ocsprenewer.OCSPRenewerThread` instances. The following is
    then recorded:

     - File modification time.
     - Hash of the file.

  - If a cert is found a second time, the modification time is compared to the
    recorded modification time. If it differs, the hash is compared too, if it
    too differs, the file is added to the scheduler for renewal again, removing
    any scheduled actions for the old file in the process.

  - When certificates are deleted from the directories, the entries are removed
    from the cache in :attr:`core.certfinder.CertContext.contexts`.

    The cache of parsed files is volatile so every time the process is killed
    files need to be indexed again (thus files are considered "new").
"""

import threading
import time
import logging
import os
import datetime
import ocspd
from core.certmodel import CertModel
from core.exceptions import CertValidationError


LOG = logging.getLogger()


class CertFinderThread(threading.Thread):
    """
    This object can be used to index directories and search for certificate
    files. When found they will be added to the supplied scheduler so the
    :class:`core.ocsprenewer.OCSPRenewerThread` instances can request an OCSP
    staple for them.

    Pass ``refresh_interval=None`` if you want to run it only once (e.g. for
    testing)
    """

    def __init__(self, *args, **kwargs):
        """
        Initialise the thread's arguments and its parent
        :class:`threading.Thread`.

        Currently supported keyword arguments:

        :kwarg iter directories: The directories to index **(required)**.
        :kwarg int refresh_interval: The minimum amount of time (s)
            between indexing runs, defaults to 10 seconds. Set to None to run
            only once **(optional)**.
        :kwarg array file_extensions: An array containing the file extensions
            of files to check for certificate content **(optional)**.
        """
        self.contexts = {}
        self.minimum_validity = kwargs.pop('minimum_validity', None)
        self.directories = kwargs.pop('directories', None)
        self.scheduler = kwargs.pop('scheduler', None)
        self.refresh_interval = kwargs.pop('refresh_interval', 10)
        self.file_extensions = kwargs.pop(
            'file_extensions', ocspd.FILE_EXTENSIONS_DEFAULT
        )
        self.last_refresh = None

        assert self.minimum_validity is not None, \
            "You need to pass the minimum_validity."

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

        if self.refresh_interval is None:
            # Stop refreshing if it is not wanted.
            return

        while True:
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
        Locate new files and add parse them, if they are valid, schedule an
        OCSP renewal action.
        """
        try:
            for path in self.directories:
                LOG.info("Scanning directory: %s", path)
                for filename in os.listdir(path):
                    ext = os.path.splitext(filename)[1].lstrip(".")
                    if ext not in self.file_extensions:
                        continue
                    filename = os.path.join(path, filename)
                    if filename in self.contexts:
                        continue
                    # Parse the certificate
                    self._parse_crt_file(filename)
        except OSError as err:
            LOG.critical(
                "Can't read directory: %s, reason: %s.",
                path, err
            )

    def _parse_crt_file(self, filename):
        """
        Parse certificate and check if there is an existing OCSP staple that is
        still valid. If so, use it, if not request a new OCSP staple. If the
        staple is valid but not valid for longer than the ``minimum_validity``,
        the staple is loaded but a new request is still scheduled.
        :param str filename: Path to the certificate file.
        """
        try:
            LOG.info("Parsing file \"%s\"..", filename)
            context = CertModel(filename)
        except CertValidationError as err:
            self._handle_failed_validation(context, err)
        # This is for certvalidator, which is currently not in
        # use.
        # except KeyError as err:
        #     self._handle_failed_validation(
        #         context,
        #         "KeyError {}, processing file \"{}\"".format(
        #             err, context.filename
        #         )
        #     )
        self.contexts[filename] = context

        if context.recycle_staple(self.minimum_validity):
            try:
                until = context.ocsp_staple.valid_until
                sched_time = until - datetime.timedelta(
                    seconds=self.minimum_validity)
            except CertValidationError:
                sched_time = None
        else:
            sched_time = None

        self.scheduler.add_task("renew", context, sched_time)

    def _update_cached_certs(self):
        """
        Loop through the list of files that were already found and check
        whether they were deleted or changed.

        If a file was modified since it was last seen, a SHA1 hash value of
        the old file is compared with a SHA1 hash of the new file. Only if the
        hash is different, the changed file is added to the scheduler to get a
        new OCSP staple. This makes sure only changed files are processed by
        the CPU intensive processes.

        Deleted files are removed from the context cache in
        :attr:`core.certfinder.CertFinder.contexts`.
        """
        def del_context(filename):
            """
                Delete context in a thread safe manner, if another thread
                deleted it, we should ignore the KeyError.
            """
            try:
                del self.contexts[filename]
            except KeyError:
                pass

        for filename, context in self.contexts.items():
            # purge certs that no longer exist in the cert dirs
            if not os.path.exists(filename):
                del_context(filename)
                LOG.info(
                    "File \"%s\" was deleted, removing it from the list.",
                    filename
                )
            elif os.path.getmtime(filename) > context.modtime:
                # purge and re-add files that have changed
                LOG.info("File \"%s\" changed, parsing it again.", filename)
                try:
                    new_context = CertModel(filename)
                except CertValidationError as err:
                    self._handle_failed_validation(context, err)
                # This is for certvalidator, which is currently not in
                # use.
                # except KeyError as err:
                #     self._handle_failed_validation(
                #         context,
                #         "KeyError {}, processing file \"{}\"".format(
                #             err, context.filename
                #         )
                #     )
                if new_context.hash != context.hash:
                    del_context(filename)
                    self.scheduler.add_task("renew", new_context)
                else:
                    LOG.info(
                        "Ignoring change in \"%s\" hash didn't change",
                        filename
                    )

    def _handle_failed_validation(self, context, msg, delete_ocsp=True):
        LOG.critical(msg)
        # Unschedule any scheduled actions for context
        self.scheduler.cancel_task(("renew", "proxy-add"), context)
        if delete_ocsp:
            LOG.info(
                "Deleting any OCSP staple: \"%s\" if it exists.",
                context.filename
            )
            try:
                os.remove("{}.ocsp".format(context.filename))
            except IOError:
                pass
