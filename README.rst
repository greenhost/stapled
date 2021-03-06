.. image:: https://code.greenhost.net/open/stapled/badges/master/pipeline.svg
    :target: https://code.greenhost.net/open/stapled/commits/master
    :alt: Pipeline Status

.. image:: https://code.greenhost.net/open/stapled/raw/master/stapled_128.png
    :target: https://stapled.readthedocs.io/en/latest/
    :alt: Stapled logo
    :align: left

===========
Quick start
===========

.. contents:: Table of Contents
   :local:


Documentation
=============

Read the full documentation on
`Read the docs <https://stapled.readthedocs.org/>`_.


System requirements
===================

This application requires **Python 3.3+** and an installed
version of **PIP** for the Python version you are using. It is also convenient
to have ``virtualenv`` installed so you can make a separate environment for
stapled's dependencies.

Installation
============

Before installation make sure you have met the `System requirements`_.
You can install the ocsp daemon from the source code repository on our gitlab
instance.

From github (for developers)
----------------------------

.. code-block:: bash

    # Download the source from the repo
    git clone --recursive https://github.com/greenhost/stapled.git
    # OR, as a TIP, which downloads all the repos simultaneously in threads:
    git clone --recursive -j5 https://github.com/greenhost/stapled.git
    # Enter the source directory
    cd stapled/
    # Setup a virtualenv
    virtualenv -p python3 env/
    # Load the virtualenv
    source env/bin/activate

Every time you want to run ``stapled`` you will need to run
``source env/bin/activate`` to load the virtualenv first. Then you run stapled
as a module:

.. code-block:: bash

    pythom -m stapled [arguments]

Alternatively you can start the daemon by running ``stapled`` without even
activating the virtualenv if you install it like this:

.. code-block:: bash
    # Install dependencies..
    pip3 install asn1crypto ocspbuilder oscrypto certvalidator
    # Install the current directory with pip. This install the project dir as
    # a console script allowing you to run `stapled`,
    pip3 install -e .

Note that this means you have to keep track of the installed dependencies
yourself!

Upgrading
---------

If you had previously installed a version of stapled from github, to upgrade run
the following:

.. code-block:: bash

    # Deactivate the virtualenv if active
    deactivate
    # Delete the virtualenv (we will start clean)
    rm -rf ./env
    # Make a new virtualenv
    virtualenv -p python3 env/
    # Update to the latest version
    git pull
    # Clone submodules too
    git submodule upgrade --init --recursive
    # Install the current directory with pip. This allows you to edit the code
    pip3 install -e . --upgrade

Troubleshooting
===============

In order to get HAPRoxy to serve staples, any valid staple file should exist
at the moment it is started. If a staple file does not exist for your
certificate stapling will remain disabled until you restart HAProxy. Even if
`stapled` tries to send HAProxy a valid staple through its socket.

In order to get around this bootstrapping problem, add an empty staple file,
which is also valid according to HAProxy's documentation by running:

.. code-block:: bash

    touch [path-to-certificate].pem.ocsp

For each of your domains.

We tested this for HAProxy 1.6, perhaps this behaviour will change in
future versions.

Compiling this package
======================

There are 2 ways to compile the package and various target distributions.

Build locally
-------------

Assuming you have the following packages installed on a debian based system:

- build-essential
- python3-cffi
- libffi-dev
- python3-all
- python3-dev
- python3-setuptools
- python3-pip
- rpm
- tar, gzip & bzip2
- git
- debhelper
- stdeb (``pip3 install --user stdeb``)

Or the equivalents of these on another distribution. You can build the packages
by running one or more of the following ``make`` commands.

.. code-block:: bash

    # Clear out the cruft from any previous build
    make clean
    # Source distribution
    make sdist
    # Binary distribution
    make bdist
    # RPM package (Fedora, Redhat, CentOS) - untested!
    make rpm
    # Debian source package (Debian, Ubuntu)
    make deb-src
    # Debian package (Debian, Ubuntu)
    make deb
    # All of the above
    make all

Everything is tested under Debian Stretch (Python 3.5 and Debian Buster
(Python 3.7), on other distros :abbr:`YMMV (Your Mileage May Vary)`.

Docker build
------------

In order to be able to build a package reproducably by anyone, on any platform
we have a ``Dockerfile`` that will install an instance of Debian Stretch in a
docker container and can run the build process for you.

Assuming you have docker installed, you can simply run the below commands to
build a package.

.. code-block:: bash

    make docker-all

Remove any previous docker image and/or container named `stapled` then build the
image with the same dependencies we used. Then compile the packages, then
place them in the `./docker-dist` dir.

.. code-block:: bash

    make docker-nuke

Throw away any previous docker image and/or container named `stapled`.
This is part of the `make docker-all` target.

.. code-block:: bash

    make docker-build

Build the docker image. This is part of the `make docker-all` target.

.. code-block:: bash

    make docker-compile

Assuming you have a built image, this compiles the packages for you and places
them in `docker-dist`. This is part of the `make docker-all` target.

.. code-block:: bash

    make docker-install

Assuming you have a built image and compiled the packages, this installs the
packages in the docker container. This is part of the `make docker-all` target.

.. code-block:: bash

    make docker-run

Assuming you have a built image and compiled the packages, and installed them
in the docker container, this runs the installed binary to test if it works.

Packages
--------

You can download packages here: https://github.com/greenhost/stapled/releases
