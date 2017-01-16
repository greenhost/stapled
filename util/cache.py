"""
    Simple lightweight caching class without dependencies or fancy features.
"""
# pylint: disable=invalid-name


class cache(dict):
    """
    Cache decorator for caching function output based on (keyword) arguments.
    """
    def __init__(self, function):
        self.function = function
        super(cache, self).__init__()
        self.__doc__ = function.__doc__

    def __call__(self, *args, **kwargs):
        return self.wrapper(*args, **kwargs)

    def __missing__(self, key):
        result = self[key] = self.function(*key[0], **dict(key[1]))
        return result

    def wrapper(self, *args, **kwargs):
        return self[args, tuple(kwargs.items())]
