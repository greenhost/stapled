# -*- coding: utf-8 -*-
"""
Defines a class that can be used as a decorator that will cache returns of a
method for a set of arguments and/or keyword arguments. If the arguments are
the same as the first time, it will take the result out of the cache.
"""
import collections
import functools


class cache(collections.OrderedDict):
    """
    Class to mimic lru cache, a fifo cache with a maximum size that returns the
    same result from cache if the same arguments are used on a method a second
    time.

    .. Note:: This should be used as a decorator:
        .. code::
            @cache(1000)
            def fib(n):
                if n <= 1:
                    return n
                else:
            return fib(n-1) + fib(n-2)
    """
    def __init__(self, max_size=None):
        if max_size == 0:
            max_size = None
        self.max_size = max_size
        super(cache, self).__init__()

    def __call__(self, func, *args, **kwargs):
        @functools.wraps(func)
        def decorated(*args, **kwargs):
            hashable = (args, tuple(kwargs.items()))
            try:
                return self[hashable]
            except KeyError:
                if self.max_size and len(self) >= self.max_size:
                    self.popitem(False)
                self[hashable] = func(*args, **kwargs)
            return self[hashable]
        return decorated
