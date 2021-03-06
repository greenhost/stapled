#!/usr/bin/env python3
"""
Python setuptools script for ``stapled`` application.
"""
import os
from setuptools import setup
from setuptools import find_packages
from stapled.version import __version__
from stapled.lib import find_lib_paths, find_lib_path_dict


def all_packages():
    """
    Find packages in this package and all the packages that are packaged with
    it. This is necessary because, for example, oscrypto includes sub-packages
    as well.
    """
    exclude = ('dev', 'tests')
    packages = find_packages(exclude=exclude)
    # Make a list of lists of packages (i.e. each invocation of find_packages
    # returns a list).
    libs = [find_packages(path, exclude=exclude) for path in find_lib_paths()]
    # Use ``sum`` to concatenate the list of lists. This works because the
    # initial value is a list, when "adding" a list, its ``__add__`` operator
    # concatenates the list to the initial value.
    return packages+sum(libs, [])


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
    packages=all_packages(),
    package_dir=find_lib_path_dict(),
    python_requires='!=3.0.*, !=3.1.*, !=3.2.*, <4',
    install_requires=[
        'python-daemon>=2.2.3',
        'configargparse>=0.14.0',
        # Required by deps in `stapled/libs`
        'future>=0.17.1',
        'cffi>=1.12.3',
        # Required for python-daemon (package dep not specified)
        'docutils>=0.15.2',
    ],
    extras_require={
        'docs': [
            'Sphinx>=2.2.0',
            'sphinx-argparse>=0.2.5',
            'sphinx_rtd_theme>=0.4.3',
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
