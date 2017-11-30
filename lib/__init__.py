"""
Find libraries in libs and return them in various forms or add them to the
python path.
"""
import os
import sys


def _libs():
    """
    Make a dict containing the name and path of each of the libs.
    :return dict: name of the lib as key, path of the lib as value
    """
    exclude = ('__init__.py', '__init__.pyc', '__pycache__')
    lib_dir = os.path.relpath(os.path.dirname(__file__))
    # Filter out self
    libs = filter(lambda p: p not in exclude, os.listdir(lib_dir)
    )
    return dict((lib, os.path.join(lib_dir, lib)) for lib in libs)


def find_lib_paths():
    """
    Find libs in the paths of ``_libs`` and return only the paths.
    This is meant to be used in a setup.py file.
    :return list: list of lib directories to search for packages
    """
    return _libs().values()



def find_lib_path_dict():
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
    libs = _libs().values()
    if libs:
        for lib in libs:
            sys.path.append(lib)
        return True
    else:
        return False

