#!/usr/bin/env python3
"""
This module defines a context in which we can run actions that are likely to
fail because they have intricate dependencies e.g. network connections,
file access, parsing certificates and validating their chains, etc., without
stopping execution of the application. Additionally it will log these errors
and depending on the nature of the error reschedule the action at a time that
seems reasonable, i.e.: we can reasonably expect the issue to be resolved by
that time.
"""

from contextlib import contextmanager
import datetime
from core.exceptions import CertValidationError
from core.exceptions import OCSPRenewError



@contextmanager
def ocsp_except_handle(action_ctx):
    """
    Handle lots of potential errors and reschedule failed action contexts.
    """
    # Initialise things here..
    try:
        yield # do the "with" code block
        return
    except:
        raise
        #action_ctx.reschedule(3600)


# except OCSPRenewError as err:
#     self._handle_failed_validation(context, err)
# except CertValidationError as err:
#     self._handle_failed_validation(context, err)
#def _handle_failed_validation(
#            self, context, msg, delete_ocsp=True, ignore=False):
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
