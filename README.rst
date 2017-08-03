===========
Quick start
===========

.. contents:: Table of Contents
   :local:


Documentation
=============

Read the full documentation on
`Read the docs <https://readthedocs.org/projects/ocspd/>`_.


System requirements
===================

This application requires **Python 3.3+** or **Python 2.7.9** and an installed
version of **PIP** for the Python version you are using. It is also convenient
to have ``virtualenv`` installed so you can make a separate environment for
ocspd's dependencies.

Installation
============

Before installation make sure you have met the `System requirements`_.
You can install the ocsp daemon from the source code repository on our gitlab
instance.

From github (for developers)
----------------------------

.. code-block:: bash

    # Download the source from the repo
    git clone https://github.com/greenhost/ocspd.git
    # Enter the source directory
    cd ocspd/
    # Setup a virtualenv
    virtualenv -p python3 env/
    # Load the virtualenv
    source env/bin/activate
    # Install a dependency that is not yet it PyPi
    pip install git+https://github.com/wbond/certvalidator.git@4383a4bfd5e769679bc4eedd1e4d334eb0c7d85a
    # Install the current directory with pip. This allows you to edit the code
    pip install .

Every time you want to run ``ocspd`` you will need to run
``source env/bin/activate`` to load the virtualenv first. Alternatively you can
start the daemon by running ``ocspd``

Upgrading
---------

If you had previously installed a version of ocspd from github, to upgrade run
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
    # Install a dependency that is not yet it PyPi
    pip install git+https://github.com/wbond/certvalidator.git@4383a4bfd5e769679bc4eedd1e4d334eb0c7d85a --upgrade
    # Install the current directory with pip. This allows you to edit the code
    pip install . --upgrade

Debian package
--------------

We package ocspd for Debian, but it will still have depenfencies that are not
available as debian packages. This means you need to either still use PIP to
install those dependencies, or you need to package them yourself.

There is a build script in the root of this project: `build_deb_pkg.sh`. It
will automatically download the dependencies master branches from Github and
package them, the finished packages including a package for ocspd will be in
the `build` directory.

.. Warning:: Do not use this, none of the source code you are about to check
    out will be audited, you will need to vet it yourself. Also it will cause
    side effects inluding but not limited to loss of hair, stress and diziness.
    This is not for production use. We do not take any responsibility for what
    you do with this script, we provide it as is, it will probably fail anyway
    but we may also stop supporting it at any time, in fact this is highly
    likely.

    **You have been warned**, now please don't continue at your own risk or go
    for the PIP install.


.. code-block:: bash

    # Install available dependencies
    apt install python-future python-all python-configargparse
    # Download remaining dependencies and convert them to debian packages
    ./build_deb_pkg.sh
    # Install all packages
    dpkg -i build/*.deb
