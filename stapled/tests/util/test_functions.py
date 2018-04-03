"""
Test utility functions defined for stapled.
"""

# pylint: disable=no-self-use
# pylint: disable=invalid-name

import types
import pytest
from stapled.util.functions import unique
from stapled.util.functions import unique_generator


class TestUniqueGenerator(object):
    """
    Test functionality of the unique_generator function.

    The unique_generator should return a generator object that can be iterated
    over. The yielded values should be unique.
    """
    def test_unique_generator_preserving_order(self):
        """
        Test unique_generator function with order preserving enabled.
         - Generator can be instantiated
         - Returned type is a generator
         - The yielded values are the unique values of the fed values.
        """
        gen = unique_generator((1, 4, 4, 3))
        assert isinstance(gen, types.GeneratorType)
        assert tuple(gen) == (1, 4, 3)

    def test_unique_dont_allow_dict_or_set(self):
        """
        Test unique_generator with bad arguments.
         - Instantiating with a set leads to exception
         - Instantiating with a dictionary leads to exception
        """
        with pytest.raises(
            TypeError,
            match=r"<(class|type) 'set'> types are always unique"
        ):
            unique_generator({1, 2, 3})

        with pytest.raises(
            TypeError,
            match=r"<(class|type) 'dict'> types are always unique"
        ):
            unique_generator(dict.fromkeys((1, 2, 3)))


class TestUnique(object):
    """
    Test functionality of the unique function.

    The unique_generator should return an object of the same type that you pass
    it but only containing unique values.
    """
    UNIQUE_TEST_DATA = [
        ([1, 2, 2, 3, 'a', 4, 4, 1], [1, 2, 3, 'a', 4]),
        ([4, 2, 2, 3, 'a', 4, 4, 1], [4, 2, 3, 'a', 1]),
        ((1, 2, 2, 3, 'a', 4, 4, 1), (1, 2, 3, 'a', 4)),
        ((4, 2, 2, 3, 'a', 4, 4, 1), (4, 2, 3, 'a', 1))
    ]

    @pytest.mark.parametrize("data,expected", UNIQUE_TEST_DATA)
    def test_unique_preserving_order(self, data, expected):
        """
        Test unique function with order preserving enabled.
         - Returned values are as expected (unique).
        """
        assert unique(data, True) == expected

    @pytest.mark.parametrize("data,expected", UNIQUE_TEST_DATA)
    def test_unique_not_preserving_order(self, data, expected):
        """
        Test unique function with order preserving disabled.
         - Returned values are as expected (unique).
        """
        assert set(unique(data, False)) == set(expected)

    def test_unique_dont_allow_dict_or_set(self):
        """
        Test unique with bad arguments.
         - Instantiating with a set leads to exception
         - Instantiating with a dictionary leads to exception
        """
        with pytest.raises(
            TypeError,
            match=r"<(class|type) 'set'> types are always unique"
        ):
            unique({1, 2, 3}, preserve_order=False)

        with pytest.raises(
            TypeError,
            match=r"<(class|type) 'dict'> types are always unique"
        ):
            unique(dict.fromkeys((1, 2, 3)), preserve_order=False)
