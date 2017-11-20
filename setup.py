#!/usr/bin/env python3
"""
Python setuptools script for ``ocspd`` application.
"""
import os
from setuptools import setup
from setuptools import find_packages
from __version__ import VERSION, APP_NAME

build_requires = [
    'rpm>=4.12'
    'tar',
    'gzip'
]

install_requires = [
    'python-daemon>=1.5.5',
    'future>=0.15.0',
    'configargparse>=0.10.0',
#   'certvalidator',
#   'asn1
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx-argparse>=0.1.15',
    'sphinx_rtd_theme',
]

long_description = (
    "Update OCSP staples from CA's and store the result so "
    "they can be served to clients."
)

setup(
    name=APP_NAME,
    version=VERSION,
    description='Daemon for updating OCSP staples',
    long_description=long_description,
    author='Greenhost BV',
    author_email='info@greenhost.nl',
    url='https://code.greenhost.net/open/ocspd',
    packages=find_packages(),
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
    },
    license='MIT License',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
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
    entry_points={
        'console_scripts': [
            'ocspd = ocspd.__main__:init'
        ]
    },
    data_files=[
        ('/lib/systemd/system', ['config/ocspd.service']),
        ('/etc/ocspd/', ['config/ocspd.conf']),
        ('/var/log/ocspd', []),
    ]
)
