# -*- coding: utf-8 -*-
"""
This module defines a context in which we can run actions that are likely to
fail because they have intricate dependencies e.g. network connections,
file access, parsing certificates and validating their chains, etc., without
stopping execution of the application. Additionally it will log these errors
and depending on the nature of the error reschedule the task at a time that
seems reasonable, i.e.: we can reasonably expect the issue to be resolved by
that time.

It is generally considered bad practice to catch all remaining exceptions,
however this is a daemon. We can't afford it to get stuck or crashed. So in the
interest of staying alive, if an exception is not caught specifically, the
handler will catch it, generate a stack trace and save if in a file in the
current working directory. A log entry will be created explaining that there
was an exception, inform about the location of the stack trace dump and that
the context will be dropped. It will also kindly request the administrator to
contact the developers so the exception can be caught in a future release which
will probably increase stability and might result in a retry rather than just
dropping the context.

Dropping the context effectively means that a retry won't occur and since the
context will have no more references, it will be garbage collected.
There is however still a reference to the certificate model in
:attr:`core.daemon.run.models`. With no scheduled actions it will
just sit idle, until the finder detects that it is either removed – which will
cause the entry in :attr:`core.daemon.run.models` to be deleted, or
it is changed. If the certificate file is changed the finder will schedule
schedule a parsing action for it and it will be picked up again. Hopefully the
issue that caused the uncaught exception will be resolved, if not, if will be
caught again and the cycle continues.
"""

from contextlib import contextmanager
import datetime
import logging
import os
import traceback
import configargparse
import requests.exceptions
from ocspd.core.exceptions import OCSPBadResponse
from ocspd.core.exceptions import RenewalRequirementMissing
from ocspd.core.exceptions import CertFileAccessError
from ocspd.core.exceptions import CertParsingError
from ocspd.core.exceptions import CertValidationError
from ocspd.core.exceptions import OCSPAdderBadResponse
from ocspd.core.exceptions import SocketError
from future.standard_library import hooks
with hooks():
    from urllib.error import URLError
try:
    _ = BrokenPipeError
except NameError:
    import socket
    BrokenPipeError = socket.error

LOG = logging.getLogger(__name__)

#: This is a global variable that is overridden by ocspd.__main__ with
#: the command line argument: ``--logdir``
LOG_DIR = "/var/log/ocspd/"

STACK_TRACE_FILENAME = "ocspd_exception{:%Y%m%d-%H%M%s%f}.trace"


@contextmanager
def ocsp_except_handle(ctx=None):
    """
    Handle lots of potential errors and reschedule failed action contexts.
    """
    # pylint: disable=too-many-branches,too-many-statements
    try:
        yield  # do the "with ocsp_except_handle(ctx):" code block
    except (CertFileAccessError, OCSPAdderBadResponse) as exc:
        # Can't access the certificate file or the response from HAPRoxy was
        # not "OCSP Response updated", we can try again a bit later..
        err_count = ctx.set_last_exception(str(exc))
        if err_count < 4:
            LOG.error(exc)
            ctx.reschedule(60 * err_count)  # every err_count minutes
        elif err_count < 7:
            LOG.error(exc)
            ctx.reschedule(3600)  # every hour
        else:
            LOG.critical("%s, giving up..", exc)
    except (SocketError, BrokenPipeError) as exc:
        # This is a fatal exception that can occur during initialisation of a
        # OCSPAdder or when an OCSPAdder uses a socket that consistently has a
        # broken pipe
        LOG.critical(exc)
    except (RenewalRequirementMissing,
            CertValidationError,
            CertParsingError) as exc:
        # Can't parse or validate the certificate file, or a requirement for
        # OCSP renewal is missing.
        # We can't do anything until the certificate file is changed which
        # means we should not reschedule, when the certificate file changes,
        # the certfinder will add it to the parsing queue anyway..
        if isinstance(exc, CertValidationError):
            # If the certificate validation failed, we probably better not
            # serve the staple because it may make the server unavailable,
            # while not serving it only makes things slightly slower.
            delete_ocsp_for_context(ctx)
        LOG.critical(exc)
    except OCSPBadResponse as exc:
        # The OCSP response is empty, invalid or the status is not "good", we
        # can try again, maybe there's server side problem.
        err_count = ctx.set_last_exception(str(exc))
        if err_count < 4:
            LOG.error(exc)
            ctx.reschedule(60 * err_count)  # every err_count minutes
        elif err_count < 7:
            LOG.error(exc)
            ctx.reschedule(3600)  # every hour
        else:
            LOG.critical(exc)
            ctx.reschedule(43200)  # twice a day
    except (requests.Timeout,
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            URLError,
            requests.exceptions.TooManyRedirects,
            requests.exceptions.HTTPError,
            requests.ConnectionError,
            requests.RequestException) as exc:
        if isinstance(exc, URLError):
            LOG.error(
                "Can't open URL: %s, reason: %s",
                ctx.model.ocsp_urls[ctx.model.url_index],
                exc.reason
            )
        elif isinstance(exc, requests.exceptions.TooManyRedirects):
            LOG.error(
                "Too many redirects for %s: %s", ctx.model.filename, exc)
        elif isinstance(exc, requests.exceptions.HTTPError):
            LOG.error(
                "Received bad HTTP status code %s from OCSP server %s for "
                " %s: %s",
                exc.response.status_code,
                ctx.model.ocsp_urls[ctx.model.url_index],
                ctx.model.filename,
                exc
            )
        elif isinstance(exc, (
                requests.ConnectionError,
                requests.RequestException
            )
                       ):
            LOG.error(
                "Failed to connect to: %s, for %s",
                ctx.model.ocsp_urls[ctx.model.url_index],
                ctx.model.filename
            )
        else:
            LOG.error("Timeout error for %s: %s", ctx.model.filename, exc)

        # Iterate over the available OCSP URLs while rescheduling
        len_ocsp_urls = len(ctx.model.ocsp_urls)
        ctx.model.url_index += 1
        if ctx.model.url_index >= len_ocsp_urls:
            ctx.model.url_index = 0

        # Reschedule every 10 seconds (3x), then every hour (3x),
        # then twice a day, *per* URL so if we have 3 urls we will run:
        #  - every 10 seconds (9x), 3 per url
        #  - every hour (9x), 3 per url
        #  - twice a day per url
        err_count = ctx.set_last_exception(str(exc))
        if err_count < (3*len_ocsp_urls)+1:
            ctx.reschedule(10)  # every err_count minutes
        elif err_count < (6*len_ocsp_urls)+1:
            ctx.reschedule(3600)  # every hour
        else:
            ctx.reschedule(43200 // len_ocsp_urls)  # twice a day per url
        LOG.debug(
            "This exception %d in a row, context.model.ocsp_urls has %d "
            "entries",
            err_count, len_ocsp_urls
        )
    # the show must go on..
    except Exception as exc:  # pylint: disable=broad-except
        dump_stack_trace(ctx, exc)


def delete_ocsp_for_context(ctx):
    """
    When something bad happens, sometimes it is good to delete a related bad
    OCSP file so it can't be served any more.

    .. TODO:: Check that HAProxy doesn't cache this, it probably does, we need
        to be able to tell it not to remember it.
    """
    LOG.info("Deleting any OCSP staple: \"%s.ocsp\" if it exists.", ctx.model)
    try:
        ocsp_file = "{}.ocsp".format(ctx.model.filename)
        os.remove(ocsp_file)
    except (IOError, OSError):
        LOG.debug(
            "Can't delete OCSP staple %s, maybe it doesn't exist.",
            ocsp_file
        )


def dump_stack_trace(ctx, exc):
    """
    Examine the last exception and dump a stack trace to a file, if it fails
    due to an IOError or OSError, log that it failed so the a sysadmin
    may make the directory writeable.
    """
    trace_file = STACK_TRACE_FILENAME.format(datetime.datetime.now())
    trace_file = os.path.join(LOG_DIR, trace_file)
    try:
        with open(trace_file, "w") as file_handle:
            traceback.print_exc(file=file_handle)
        LOG.critical(
            "Prevented thread from being killed by uncaught exception: %s\n"
            "Context %s will be dropped as a result of the exception.\n"
            "A stack trace has been saved in %s\n"
            "Please report this error to the developers so the exception can "
            "be handled in a future release, thank you!",
            exc,
            ctx,
            trace_file
        )
    except (IOError, OSError) as trace_exc:
        LOG.critical(
            "Prevented thread from being killed by uncaught exception: %s\n"
            "Context %s will be dropped as a result of the exception.\n"
            "Couldn't dump stack trace to: %s reason: %s\n"
            "Please report this error to the developers so the exception can "
            "be handled in a future release, thank you!",
            exc,
            ctx,
            trace_file,
            trace_exc
        )
