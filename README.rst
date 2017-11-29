`|pipeline|`_

.. |pipeline| image::
    https://code.greenhost.net/open/ocspd/badges/master/pipeline.svg
.. _|pipeline|: https://code.greenhost.net/open/ocspd/commits/master
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

This application requires **Python 3.3+** or **Python 2.7.9** and an installed
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
    # Install a dependency that is not yet it PyPi
    pip install git+https://github.com/wbond/certvalidator.git@4383a4bfd5e769679bc4eedd1e4d334eb0c7d85a
    # Install the current directory with pip. This allows you to edit the code
    pip install .

Every time you want to run ``stapled`` you will need to run
``source env/bin/activate`` to load the virtualenv first. Alternatively you can
start the daemon by running ``stapled``

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
    # Install a dependency that is not yet it PyPi
    pip install git+https://github.com/wbond/certvalidator.git@4383a4bfd5e769679bc4eedd1e4d334eb0c7d85a --upgrade
    # Install the current directory with pip. This allows you to edit the code
    pip install . --upgrade

Compiling this package
======================

There are 2 ways to compile the package and various target distributions.

Build locally
-------------

Assuming you have the following packages installed on a debian based system:

- build-essential
- python-cffi
- python3-cffi
- libffi-dev
- python-all
- python3-all
- python-dev
- python3-dev
- python-setuptools
- python3-setuptools
- python-pip
- rpm
- tar, gzip & bzip2
- git
- debhelper

Or the equivalents of these on another distribution. You can build the packages
by running one or more of the following ``make`` commands.

```
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
```

Everything is tested under Debian Stretch, your mileage may vary.

Docker build
------------

In order to be able to build a package reproducably by anyone, on any platform
we have a ``Dockerfile`` that will install an instance of Debian Stretch in a
docker container and can run the build process for you.

Assuming you have docker installed, you can simply run the below commands to
build a package.

```
make docker-all
```
Remove any previous docker image and/or container named `stapled` then buil the
image with the same dependencies we used. Then compile the packages, then
place them in the `./docker-dist` dir.

```
make docker-nuke
```
Throw away any previous docker image and/or container named `stapled`.
This is part of the `make docker-all` target.

```
make docker-build
```
Build the docker image. This is part of the `make docker-all` target.

```
make docker-compile
```
Assuming you have a built image, this compiles the packages for you and places
them in `docker-dist`. This is part of the `make docker-all` target.

```
make docker-install
```
Assuming you have a built image and compiled the packages, this installs the
packages in the docker container. This is part of the `make docker-all` target.

```
make docker-run
```
Assuming you have a built image and compiled the packages, and installed them
in the docker container, this runs the installed binary to test if it works.

Packages
--------

You can download packages here: https://github.com/greenhost/stapled/releases
