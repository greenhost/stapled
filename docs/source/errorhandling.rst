Exception handling
==================

+--------------------------+---------------+------------------------------------------+---------------------------------------------------------------------------+
| Exception                | Source        | Raised when?                             | Action                                                                    |
+==========================+===============+==========================================+===========================================================================+
| IOError/OSError          | certfinder    | Directory can't be read.                 | Ignore, certfinder will try at every refresh.                             |
| CertFileAccessError      | certfinder    | Certificate file can't be read.          | Schedule retry 3x *n*\*5s, then 3x every hour, the ignore. [1]_           |
+--------------------------+---------------+------------------------------------------+---------------------------------------------------------------------------+


.. [1] When the certificate file is changed, `certfinder` will add the file back to the parsing queue.

