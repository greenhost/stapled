#!/usr/bin/env python3
"""
Python setuptools script for ``ocspd`` application.
"""
import os
import shutil
from setuptools import setup
from setuptools import find_packages
from setuptools.command.install import install
# pylint: disable=invalid-name
# Disable superfluous-parens, because we want py3 compatibility
# pylint: disable=superfluous-parens

version = '0.1'

install_requires = [
    'certvalidator>=0.11.1',
    'ocspbuilder>=0.10.2',
    'oscrypto>=0.17.2',
    'python-daemon>=1.5.5',
    'requests>=2.4.3',
    'future>=0.15.0',
    'configargparse>=0.10.0',
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


class CustomInstallCommand(install):
    """
    Installs systemd service to /lib/systemd/system/ocspd.service. Note that
    this is not installed when installing with --editable or setup.py develop.
    """

    CREATE_DIRS = [
        os.path.join('/lib', 'systemd', 'system'),
        os.path.join('/etc', 'ocspd'),
        os.path.join('/var', 'log', 'ocspd'),
    ]

    def run(self):
        """
        Installs and then copies the service file to the systemd directory
        """
        install.run(self)
        print("Creating needed directories")
        for directory in self.CREATE_DIRS:
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory)
                except OSError as exc:
                    if exc.errno == 13:
                        print("WARNING! Failed to create directory '{}'. This "
                              "might cause problems.".format(directory))
                    else:
                        raise

setup(
    name='ocspd',
    version=version,
    description='Daemon for updating OCSP staples',
    long_description=long_description,
    author='Greenhost BV',
    author_email='info@greenhost.nl',
    url='https://code.greenhost.net/open/ocspd',
    packages=find_packages(),
    include_package_data=True,
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
    data_files=[('/lib/systemd/system', ['scripts/ocspd.service'])],
    cmdclass={'install': CustomInstallCommand},
)
