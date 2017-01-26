# -*- coding: utf-8 -*-
"""
    Simple lightweight caching class without third-party dependencies or fancy
    features.
"""
# pylint: disable=invalid-name

from functools import lru_cache
cache = lru_cache(None)
