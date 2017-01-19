Exception handling
==================

During the OCSP renewal proces lots of things could go wrong, some errors are
recoverable, others can be ignored, still others could be cause by temporary
issues e.g.: a service interruption of the OCSP server in question. So
extensive error handling is done to keep the daemons threads running.

The following is an overview of what can be expected when exceptions occur.

+--------------------------------------+---------------+------------------------------------------+---------------------------------------------------------------------------+
| Exception                            | Source        | Raised when?                             | Action                                                                    |
+======================================+===============+==========================================+===========================================================================+
| IOError/OSError                      | certfinder    | Directory can't be read.                 | Ignore, certfinder will try at every refresh.                             |
+--------------------------------------+---------------+------------------------------------------+---------------------------------------------------------------------------+
| CertFileAccessError                  | certfinder    | Certificate file can't be read.          | Schedule retry 3x *n*\*60s, then 3x, every hour, then ignore. [1]_        |
+--------------------------------------+---------------+------------------------------------------+---------------------------------------------------------------------------+
| CertParsingError                     | certparser    | Can't access the certificate file,       | Ignore, certfinder will try at every refresh.                             |
|                                      |               | doesn't parse or part of the chain       |                                                                           |
|                                      |               | is missing.                              |                                                                           |
+--------------------------------------+---------------+------------------------------------------+---------------------------------------------------------------------------+
| OCSPBadResponse                      | ocsprenewer   | The response is empty, invalid or the    | Schedule retry 3x *n*\*60s, then 3x, every hour, then twice a day.        |
|                                      |               | status is not "good".                    | indefinately. If it's not a server issue, wait for the file to change [1]_|
+--------------------------------------+---------------+------------------------------------------+---------------------------------------------------------------------------+
| urllib.error.URLError                | ocsprenewer   | An OCSP url can't be opened.             | We can try again later, maybe there is a server side issue.               |
+--------------------------------------+               +------------------------------------------+ Some certificates contain multiple URL's so we will try each one with     |
| requests.exceptions.Timeout          |               | Data didn't reach us within the expected | 10 seconds intervals and then start from the first again.                 |
+--------------------------------------+               | time frame.                              | Schedule retry 3x *n*\*60s, then 3x, every hour, then then twice a day.   |
| requests.exceptions.ReadTimeout      |               |                                          |                                                                           |
+--------------------------------------+               +------------------------------------------+                                                                           |
| requests.exceptions.ConnectTimeout   |               | A connection can't be established        |                                                                           |
|                                      |               | because the server doesn't reply within  |                                                                           |
|                                      |               | the expected time frame.                 |                                                                           |
+--------------------------------------+               +------------------------------------------+                                                                           |
| requests.exceptions.TooManyRedirects |               | When the OCSP server redirects us too    |                                                                           |
|                                      |               | many times. Limit is quite high so       |                                                                           |
|                                      |               | probably something is wrong with the     |                                                                           |
|                                      |               | OCSP server.                             |                                                                           |
+--------------------------------------+               +------------------------------------------+                                                                           |
| requests.exceptions.HTTPError        |               | A HTTP error code was returned, this can |                                                                           |
|                                      |               | be a 4xx or 5xx status code.             |                                                                           |
+--------------------------------------+               +------------------------------------------+                                                                           |
| requests.exceptions.ConnectionError  |               | A connection to the OCSP server can't be |                                                                           |
|                                      |               | established.                             |                                                                           |
+--------------------------------------+---------------+------------------------------------------+---------------------------------------------------------------------------+

.. [1] When the certificate file is changed, `certfinder` will add the file back to the parsing queue.

core.exceptions
---------------

.. automodule:: core.exceptions
   :members:

core.excepthandler
------------------

.. automodule:: core.excepthandler
    :members:
