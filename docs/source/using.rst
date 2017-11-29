.. include:: ../../README.rst

Using stapled
===========

.. argparse::
    :module: stapled.__main__
    :func: get_cli_arg_parser
    :prog: stapled
    :nodefault:

Testing stapled
=============

Testing an application like this is hard, but that is no excuse not to do
testing. We want to have unit tests but to do that correctly we need to run an
OCSP server locally, quite a setup. So until now we didn't do so yet. Note that
if you have experience with this kind of setup and you want to help this project
move forward, you are welcome to help.

Obviously we do test stapled, admittedly a little bit primitively. You can find a
script in ``scripts/`` called ``refresh_testdata.sh``. It will delete any
directory named ``testdata`` in the root of the project and create a fresh one.
Then it will download 3 certificate chains from live servers. These will be
placed in subdirectories with the same name as the domain name.

Next you can run ``python stapled -vvvv -d testdata/*`` to get output printed to
your terminal. The ``testdata/[domain].[tld]`` directories will be populated
with ``[domain].[tld].ocsp`` files.
