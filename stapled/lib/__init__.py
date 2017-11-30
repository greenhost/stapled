"""
Find libraries in libs and return them in various forms or add them to the
python path.
"""
import os
import sys
from setuptools import find_packages


def _libs():
    """
    Make a dict containing the name and path of each of the libs.
    :return dict: name of the lib as key, path of the lib as value
    """
    exclude = ('__init__.py', '__init__.pyc', '__pycache__')
    lib_dir = os.path.dirname(__file__)
    # Filter out self
    libs = filter(lambda p: p not in exclude, os.listdir(lib_dir)
    )
    return dict((lib, os.path.join(lib_dir, lib)) for lib in libs)


def find_libs(exclude=[]):
    """
    Find libs in the paths of ``_libs`` and return it as a flat list.
    This is meant to be used in a setup.py file.
    :return list: list of found packages
    """
    paths = _libs().values()
    # Make a list of lists of packages (i.e. each invocation of find_packages
    # returns a list).
    package_lists = [find_packages(path, exclude=exclude) for path in paths]
    # Use ``sum`` to concatenate the list of lists. This works because the
    # initial value is a list, when "adding" a list, its ``__add__`` operator
    # concatenates the list to the initial value.
    return sum(package_lists, [])


def find_lib_paths():
    """
    Use ``_libs`` and add the name of the package to the end of the paths.
    This is done because the paths are ``lib/[project]/[project]`` not
    ``lib/[project]``.
    This is meant to be used in a setup.py file.
    :return list: list of lib paths where the __init__.py of the lib lives.
    """
    paths = _libs().items()
    return dict(
        (lib, os.path.join(path, lib)) for lib, path in paths
    )

def add_paths():
    """
    Add the found libs to the python path so they can be imported.
    """
    for lib in _libs().values():
        sys.path.append(lib)
