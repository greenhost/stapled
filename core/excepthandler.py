#!/usr/bin/env python3
"""
This module defines a context in which we can run actions that are likely to
fail because they have intricate dependencies e.g. network connections,
file access, parsing certificates and validating their chains, etc., without
stopping execution of the application. Additionally it will log these errors
and depending on the nature of the error reschedule the task at a time that
seems reasonable, i.e.: we can reasonably expect the issue to be resolved by
that time.
"""

from contextlib import contextmanager
import datetime
import logging
import os
import traceback
from core.exceptions import CertValidationError
from core.exceptions import OCSPRenewError

LOG = logging.getLogger()
STACK_TRACE_FILENAME = "ocspd_exception{:%Y%m%d-%H%M%s%f}.trace"


@contextmanager
def ocsp_except_handle(ctx):
    """
    Handle lots of potential errors and reschedule failed action contexts.
    """
    # pylint: disable=broad-except
    try:
        yield # do the "with" code block
    except OCSPRenewError as exc:
        pass
    except CertValidationError as exc:
        pass
    except Exception as exc:
        trace_file = STACK_TRACE_FILENAME.format(datetime.datetime.now())
        trace_file = os.path.join(os.getcwd(), trace_file)
        try:
            with open(trace_file, "w") as file_handle:
                traceback.print_exc(file=file_handle)
            LOG.critical(
                "Prevented thread from being killed by an uncaught exception: "
                "%s\nA stack trace has been saved in %s",
                exc, trace_file
            )
        except (IOError, PermissionError) as exc:
            LOG.critical("Couldn't dump stack trace: %s", exc)




#action_ctx.reschedule(3600)

#def _handle_failed_validation(self, context, msg, delete_ocsp=True, ignore=False):
#        LOG.critical(msg)
#        if ignore:
#            # Unschedule any scheduled actions for context
#            self.scheduler.cancel_task(("renew", "proxy-add"), context)
#        if delete_ocsp:
#            LOG.info(
#                "Deleting any OCSP staple: \"%s.ocsp\" if it exists.",
#                context
#            )
#            try:
#                os.remove("{}.ocsp".format(context))
#            except IOError:
#                LOG.debug(
#                    "Can't delete OCSP staple, maybe it doesn't exist."
#                )
