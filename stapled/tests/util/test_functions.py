import os
import pytest
import types
from stapled.util.functions import unique
from stapled.util.functions import unique_generator


class TestUniqueGenerator(object):

    def test_unique_generator_preserving_order(self):
        gen = unique_generator((1, 4, 4, 3))
        assert isinstance(gen, types.GeneratorType)
        assert tuple(gen) == (1, 4, 3)

    def test_unique_dont_allow_dict_or_set(self):
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
    UNIQUE_TEST_DATA = [
        ([1, 2, 2, 3, 'a', 4, 4, 1], [1, 2, 3, 'a', 4]),
        ([4, 2, 2, 3, 'a', 4, 4, 1], [4, 2, 3, 'a', 1]),
        ((1, 2, 2, 3, 'a', 4, 4, 1), (1, 2, 3, 'a', 4)),
        ((4, 2, 2, 3, 'a', 4, 4, 1), (4, 2, 3, 'a', 1))
    ]

    @pytest.mark.parametrize("data,expected", UNIQUE_TEST_DATA)
    def test_unique_preserving_order(self, data, expected):
        assert unique(data, True) == expected

    @pytest.mark.parametrize("data,expected", UNIQUE_TEST_DATA)
    def test_unique_not_preserving_order(self, data, expected):
        assert set(unique(data, False)) == set(expected)

    def test_unique_dont_allow_dict_or_set(self):
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
