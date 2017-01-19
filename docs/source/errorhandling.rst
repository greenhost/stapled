| Exception                | Source        | Raised when?                             | Action                                                                    |
+==========================+===============+==========================================+===========================================================================+
| IOError/OSError          | certfinder    | Directory can't be read.                 | Ignore, certfinder will try at every refresh.                             |
| CertFileAccessError      | certfinder    | Certificate file can't be read.          | Schedule retry 3x *n**5s, then 3x every hour, the ignore. [1]_            |



.. [1] When the certificate file is changed, `certfinder` will add the file back to the parsing queue.

::
    Error                                  |Retry|Ignore|Retry (sched)|Ignore| Extra
    ---------------------------------------+:---:+:----:+:-----------:+:----:+:-------------------------------------------------------------
    OSError directory can't be accessed              |No   |Yes   |No           |No    |This should probably kill the entire process if just started.
    IOError file does not exist                      |No   |No    |No           |No    |File might be deleted after it was detected and before parsing, when found again will automatically be added again.
    IOError file is locked                           |3x 5s|No    |3x 30m       |No    |Process might release soon or later..
    IOError access denied permission (13)            |No   |No    |?            |No    |File might be deleted after it was detected and before parsing.
    IOError IO Error                                 |No   |No    |No           |No    |Are there cases where this could be temporary? e.g. NFS failure?
    Certificate corrupted or invalid format          |No   |No    |No           |No    |Maybe fixed in a new cert file so just wait for it to change.
    Certificate chain invalid                        |No   |No    |No           |No    |Maybe fixed in a new cert file so just wait for it to change.
    Certificate is expired                           |No   |No    |No           |No    |Maybe fixed in a new cert file so just wait for it to change.
    Certificate is revoked                           |No   |No    |No           |No    |Maybe fixed in a new cert file so just wait for it to change.
    No OCSP URI in Certificate                       |No   |No    |No           |No    |Maybe fixed in a new cert file so just wait for it to change.
    Connection error network level                   |3x 5s|No    |30m          |No    |Maybe short or long network interruption, but not necessarily caused by bad certificate.
    Connection error DNS lookup error                |3x 5s|No    |30m          |No    |Maybe short or long network interruption, but not necessarily caused by bad certificate.
    Connection error DNS bad response                |No   |No    |30m          |No    |Bad DNS record or none exists, need to try again a bit later so schedule only.
    Connection timeout                               |3x 5s|No    |30m          |No    |Maybe short or long network interruption, but not caused by bad certificate.
    Connection content timeout                       |3x 5s|No    |30m          |No    |Maybe short or long network interruption, but not caused by bad certificate.
    Connection too many redirects                    |No   |No    |30m          |No    |Probably a server side configuration error, not much sense to try again immediately, maybe later?
    HTTP status 400 Bad Request                      |No   |Yes   |1d?          |No    |This is an OCSP server's way of telling us something is invalid in our request, retying the same would be kinda stupid (unless the server is wrong).
    HTTP status 4xx (not 400)                        |3x 5s|No    |30m          |No    |This could be a server issue that may be fixed soon or later..
    HTTP status 5xx Internal server error            |3x 5s|No    |30m          |No    |This is a server issue that may be fixed soon or later..
    HTTP status 200 ok - empty response              |3x 5s|No    |3x 30m       |Yes   |I have seen this happen in the wild, nothing much that can be done about it, retry but eventually give up.
    OCSP response invalid                            |No   |No    |3x 30m       |No    |Not sure yet when this would happen in real life, but any of these are not unlikely in production, since you only find the non-laboratory crazy results in the wild.
    Chain including staple invalid                   |No   |No    |3x 30m       |No    |Maybe fixed after new request at a later point in time or with a new cert file so just wait for it to change.
    Certificate expired (staple validation)          |No   |No    |No           |No    |Maybe fixed in a new cert file so just wait for it to change.
    Certificate revoked (staple validation)          |No   |No    |No           |No    |Maybe fixed in a new cert file so just wait for it to change.
    IOError writing staple, file exists, is locked   |3x 5s|No    |3x 30m       |No    |Should at least eventually lead to a critical so sysadmins will figure out something is wrong.
    IOError writing staple, access denied            |3x 5s|No    |3x 30m       |No    |Should at least eventually lead to a critical so sysadmins will figure out something is wrong.
    IOError IO Error                                 |3x 5s|No    |3x 30m       |No    |Should at least eventually lead to a critical so sysadmins will figure out something is wrong.
    Other                                            |No   |No?   |No           |No    |Need to catch to prevent thread from terminating, may end in a useless loop state.
