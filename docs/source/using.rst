===========
Quick start
===========

.. contents:: Table of Contents
   :local:

System requirements
===================

This application requires **Python 3.3+**  and an installed version of **PIP**
for Python 3. It is also convenient to have ``virtualenv`` installed so you can
make a separate environment for ocspd's dependencies.

Installation
============

Before installation make sure you have met the :ref:`System Requirements`.
You can install the ocsp daemon from the source code repository on our gitlab
instance.

From gitlab
-----------

.. code-block:: python

    # Download the source from the repo
    git clone https://code.greenhost.net/open/ocspd.git
    # Rnter the source directory
    cd ocspd/
    # Setup a virtualenv
    virtualenv -p python3 env/
    # Load the virtualenv
    source env/bin/activate
    # Now install the dependencies
    pip install -r requirements.txt

Every time you want to run ``ocspd`` you will need to run
``source env/bin/activate`` to load the virtualenv first. Alternatively you can
start the daemon by starting python with ocspd.py as an argyme

Using ocspd
===========

.. argparse::
    :module: ocspd.main
    :func: get_cli_arg_parser
    :prog: ocspd.py
    :nodefault:

