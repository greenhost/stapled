#!/usr/bin/env python3
"""
Python setuptools script for ``ocspd`` application.
"""
from setuptools import setup
from setuptools import find_packages
from ocspd.version import __version__

setup(
    name='ocspd',
    version=__version__,
    description='Daemon for updating OCSP staples',
    long_description=(
        "Update OCSP staples from CA's and store the result so "
        "they can be served to clients."
    ),
    author='Greenhost BV',
    author_email='info@greenhost.nl',
    url='https://github.com/greenhost/ocspd',
    packages=find_packages(),
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, <4',
    install_requires=[
        'python-daemon>=1.5.5',
        'future>=0.15.0',
        'configargparse>=0.10.0',
        'asn1crypto>=0.23.0',
        'certvalidator>=0.11.1',
        'ocspbuilder>=0.10.2',
        'oscrypto>=0.18.0'
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
            'ocspd = ocspd.__main__:init'
        ]
    },
    data_files=[
        ('/lib/systemd/system', ['config/ocspd.service']),
        ('/etc/ocspd/', ['config/ocspd.conf']),
        ('/var/log/ocspd', [])
    ]
)
