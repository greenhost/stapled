#!/usr/bin/env python

from setuptools import setup
from setuptools import find_packages

version = '0.1'

install_requires = [
    'certvalidator>=0.11.1',
    'ocspbuilder>=0.10.2',
    'oscrypto>=0.17.2',
    'python-daemon==2.1.2',
    'requests>=2.12.4',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

long_description = \
    ("Update OCSP staples from CA's and store the result so they "
     "can be served to clients.")

setup(name='ocspd',
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
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Topic :: Internet :: Proxy Servers',
          'Topic :: Security',
          'Topic :: System :: Networking',
          'Topic :: System :: Systems Administration',
          'Topic :: Utilities',
      ],
      entry_points={
          'console_scripts': [
              'ocspd = ocspd.main:init'
          ]
      },
     )
