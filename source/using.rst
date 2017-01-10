==========
User Guide
==========

.. contents:: Table of Contents
   :local:

.. _installation:

System Requirements
===================

This application requires Python 3.3 or higher and an installed version of PIP for Python 3

Using ocspd
===========

::

  usage: ocspd.py [-h] [--minimum-validity MINIMUM_VALIDITY]
                  [-t RENEWAL_THREADS] [-v] [-d]
                  [--file-extensions FILE_EXTENSIONS] [-r REFRESH_INTERVAL]
                  [-l LOGFILE] [--syslog]
                  directories [directories ...]

  Update OCSP staples from CA's and store the result so HAProxy can serve them
  to clients.

  positional arguments:
    directories           Directories containing the certificates used by
                          HAProxy. Multiple directories may be specified
                          separated by a space. This is a positional argument
                          and nothing but directories may succeed it.

  optional arguments:
    -h, --help            show this help message and exit
    --minimum-validity MINIMUM_VALIDITY
                          If the staple is valid for less than this time in
                          seconds an attempt will be made to get a new, valid
                          staple (default: 7200).
    -t RENEWAL_THREADS, --renewal-threads RENEWAL_THREADS
                          Amount of threads to run for renewing staples.
    -v, --verbose         Print more info (default: FATAL).
    -d, --daemon          Daemonise the process, release from shell and process
                          group, rununder new process group, optionally drop
                          privileges and chroot.
    --file-extensions FILE_EXTENSIONS
                          Files with which extensions should be scanned? Comma
                          separated list (default: crt,pem,cer)
    -r REFRESH_INTERVAL, --refresh-interval REFRESH_INTERVAL
                          Minimum time to wait between parsing cert dirs and
                          certificates (default=60).
    -l LOGFILE, --logfile LOGFILE
                          File to log output to.
    --syslog              Output to syslog.

  This will not serve OCSP responses.

