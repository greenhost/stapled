#!/usr/bin/env python3
"""
Python setuptools script for ``stapled`` application.
"""
import os
from setuptools import setup
from setuptools import find_packages
from stapled.version import __version__
try:
    from stapled.lib import find_libs, find_lib_paths
except ImportError:
    pass

setup(
    name='stapled',
    version=__version__,
    description='Daemon for updating OCSP staples',
    long_description=(
        "Update OCSP staples from CA's and store the result so "
        "they can be served to clients."
    ),
    author='Greenhost BV',
    author_email='info@greenhost.nl',
    url='https://github.com/greenhost/stapled',
    # Find packages in this package and all the packages that are packaged with
    # it. This is necessary because, for example, oscrypto includes
    # sub-packages as well.
    packages=find_packages(exclude=['stapled.lib']) + \
        find_libs(exclude=['dev', 'tests']),
    # Tell setup.py where the dependencies are located so they will be included
    # while packaging
    package_dir=find_lib_paths(),
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, <4',
    install_requires=[
        'python-daemon>=1.5.5',
        'future>=0.15.0',
        'configargparse>=0.10.0',
    ],
    extras_require={
        'docs': [
            'Sphinx>=1.0',
            'sphinx-argparse>=0.1.15',
            'sphinx_rtd_theme',
        ]
    },
    license='Apache Version 2.0',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Version 2.0',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    keywords='ocsp proxy ssl tls haproxy',
    entry_points={
        'console_scripts': [
            'stapled = stapled.__main__:init'
        ]
    },
    data_files=[
        ('/lib/systemd/system', ['config/stapled.service']),
        ('/etc/stapled/', ['config/stapled.conf']),
        ('/var/log/stapled', [])
    ]
)
