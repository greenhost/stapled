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

version = '0.1'

install_requires = [
    'certvalidator>=0.11.1',
    'ocspbuilder>=0.10.2',
    'oscrypto>=0.17.2',
    'python-daemon>=2',
    'requests>=2.4.3',
    'future>=0.15.0',
    'pylru>=1.0.9'
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

    SERVICE_FILENAME = 'ocspd.service'
    SERVICE_FILE = os.path.join(os.getcwd(), 'scripts', SERVICE_FILENAME)
    SERVICE_DESTINATION_DIR = os.path.join('/lib', 'systemd', 'system')

    def run(self):
        """
        Installs and then copies the service file to the systemd directory
        """
        if not os.path.exists(self.SERVICE_DESTINATION_DIR):
            os.makedirs(self.SERVICE_DESTINATION_DIR)
        install.run(self)
        print("Installing ocspd.service")
        service_dest = os.path.join(
            self.SERVICE_DESTINATION_DIR,
            self.SERVICE_FILENAME)
        try:
            shutil.copy(self.SERVICE_FILE, service_dest)
        except IOError as exc:
            if exc.errno == 13:
                print("WARNING! systemd service was not installed due to "
                      "permission problems")
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
    cmdclass={'install': CustomInstallCommand},
)
