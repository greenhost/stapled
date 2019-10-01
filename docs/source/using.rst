.. include:: ../../README.rst

Using stapled
=============

.. argparse::
    :module: stapled.__main__
    :func: get_cli_arg_parser
    :prog: stapled
    :nodefault:

Testing stapled
===============

Testing an application like this is hard, but that is no excuse not to do
testing. We want to have unit tests but to do that correctly we need to run an
OCSP server locally, quite a setup. So until now we didn't do so yet. Note that
if you have experience with this kind of setup and you want to help this project
move forward, you are welcome to help.

Obviously we do test stapled, admittedly a little bit primitively. You can find
a script in ``scripts/`` called ``refresh_testdata.sh``. It will delete any
directory named ``testdata`` in the root of the project and create a fresh one.
Then it will download 3 certificate chains from live servers. These will be
placed in subdirectories with the same name as the domain name.

Next you can run ``python -m stapled -vvvv -d testdata/*`` to get output
printed to your terminal. The ``testdata/[domain].[tld]`` directories will be
populated with ``[domain].[tld].ocsp`` files.

Caveats
=======

In order to get HAPRoxy to serve staples, any staple valid file should exist
at the moment it is started. If a staple file does not exist for your
certificate stapling will remain disabled until you restart HAProxy. Even if
``stapled`` tries to send HAProxy a valid staple through its socket.

In order to get around this bootstrapping problem, add an empty staple file,
which is also valid according to HAProxy's documentation by running:

.. code-block:: bash

    touch [path-to-certificate].pem.ocsp

For each of your domains.

We tested this for HAProxy 1.6, perhaps this behaviour will change in
future versions.
