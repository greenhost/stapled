============
Introduction
============

Why do I need ``ocspd``?
========================

``ocspd`` is meant to be a helper daemon for HAProxy which doesn't do OCSP stapling out of the box. However HAProxy *can* serve staple files if they are place in the certificate directory, which is what we use to our benefit.

.. toctree::
    :caption: Table of Contents
    :maxdepth: 3

    using
    modules
    core
    scheduling


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

