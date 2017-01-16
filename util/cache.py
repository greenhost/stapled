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

    def __call__(self, *args, **kwargs):
        return self[args, tuple(kwargs.items())]

    def __missing__(self, key):
        result = self[key] = self.function(*key[0], **dict(key[1]))
        return result
