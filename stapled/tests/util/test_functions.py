import os
import pytest
import types
from stapled.util.haproxy import parse_haproxy_config
from stapled.util.functions import unique
from stapled.util.functions import unique_generator

TEST_FILES = [
    (
        # Parsing haproxy admin socket with some cert dirs with absolute paths.
        # files (input)
        [
            'stapled/tests/.haproxy/haproxy-test.cfg'
        ],
        # expected (parsed output): tuple of arrays of arrays of crt directives
        # corresponding with an array of sockets.
        (
            [
                [
                    '/etc/ssl/private/__fallback.pem',
                    '/etc/ssl/private certs',
                    '/etc/ssl/private/fall back.pem',
                    '/etc/ssl/private certs2'
                ]
            ],
            [
                '/run/haproxy/admin.sock'
            ]
        )
    ), (
        # The same as above but with a `crt_base` directive
        # passing files as a string deliberately because that should also work.
        'stapled/tests/.haproxy/haproxy-test-base.cfg',
        (
            [['/etc/ssl/private/cert.pem', '/etc/ssl/private/certbot/']],
            ['/run/haproxy/admin-crt-base.sock']
        )
    ), (
        # The same as above but with a `crt_base` directive
        # passing files as a string deliberately because that should also work.
        'stapled/tests/.haproxy/haproxy-test-no-socket.cfg',
        (
            [['/etc/ssl/private/cert.pem', '/etc/ssl/private certs']],
            [None]
        )
    ), (
        # Two test files test
        [
            'stapled/tests/.haproxy/haproxy-test.cfg',
            'stapled/tests/.haproxy/haproxy-test-base.cfg',
            'stapled/tests/.haproxy/haproxy-test-no-socket.cfg'
        ],
        (
            [
                [
                    '/etc/ssl/private/__fallback.pem',
                    '/etc/ssl/private certs',
                    '/etc/ssl/private/fall back.pem',
                    '/etc/ssl/private certs2'
                ], [
                    '/etc/ssl/private/cert.pem',
                    '/etc/ssl/private/certbot/'
                ], [
                    '/etc/ssl/private/cert.pem',
                    '/etc/ssl/private certs'
                ]
            ],
            [
                '/run/haproxy/admin.sock',
                '/run/haproxy/admin-crt-base.sock',
                None
            ]
        )
    )
]


class TestParseHaproxyConfig(object):
    @pytest.mark.parametrize("files,expected", TEST_FILES)
    def test_files(self, files, expected):
        parsed = parse_haproxy_config(files)
        assert parsed == expected


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

    @pytest.mark.parametrize("data,expected", [
        ([1, 2, 2, 3, 'a', 4, 4, 1], [1, 2, 3, 'a', 4]),
        ([4, 2, 2, 3, 'a', 4, 4, 1], [4, 2, 3, 'a', 1]),
        ((1, 2, 2, 3, 'a', 4, 4, 1), (1, 2, 3, 'a', 4)),
        ((4, 2, 2, 3, 'a', 4, 4, 1), (4, 2, 3, 'a', 1))
    ])
    def test_unique_preserving_order(self, data, expected):
        assert unique(data, True) == expected

    @pytest.mark.parametrize("data,expected", [
        ([1, 2, 2, 3, 'a', 4, 4, 1], [1, 2, 3, 4, 'a']),
        ([4, 2, 2, 3, 'a', 4, 4, 1], [1, 2, 3, 4, 'a']),
        ((1, 2, 2, 3, 'a', 4, 4, 1), (1, 2, 3, 4, 'a')),
        ((4, 2, 2, 3, 'a', 4, 4, 1), (1, 2, 3, 4, 'a'))
    ])
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
