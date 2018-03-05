import pytest
from stapled.util.haproxy import parse_haproxy_config

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
                ['/run/haproxy/admin.sock']
            ]
        )
    # ), (
    #     # The same as above but with a `crt_base` directive
    #     # passing files as a string deliberately because that should also work.
    #     'stapled/tests/.haproxy/haproxy-test-base.cfg',
    #     (
    #         [['/etc/ssl/private/cert.pem', '/etc/ssl/private/certbot/']],
    #         [['/run/haproxy/admin-crt-base.sock']]
    #     )
    # ), (
    #     # The same as above but with a `crt_base` directive
    #     # passing files as a string deliberately because that should also work.
    #     'stapled/tests/.haproxy/haproxy-test-no-socket.cfg',
    #     (
    #         [['/etc/ssl/private/cert.pem', '/etc/ssl/private certs']],
    #         [None]
    #     )
    # ), (
    #     # Two test files test
    #     [
    #         'stapled/tests/.haproxy/haproxy-test.cfg',
    #         'stapled/tests/.haproxy/haproxy-test-base.cfg',
    #         'stapled/tests/.haproxy/haproxy-test-no-socket.cfg'
    #     ],
    #     (
    #         [
    #             [
    #                 '/etc/ssl/private/__fallback.pem',
    #                 '/etc/ssl/private certs',
    #                 '/etc/ssl/private/fall back.pem',
    #                 '/etc/ssl/private certs2'
    #             ], [
    #                 '/etc/ssl/private/cert.pem',
    #                 '/etc/ssl/private/certbot/'
    #             ], [
    #                 '/etc/ssl/private/cert.pem',
    #                 '/etc/ssl/private certs'
    #             ]
    #         ],
    #         [
    #             ['/run/haproxy/admin.sock'],
    #             ['/run/haproxy/admin-crt-base.sock'],
    #             [None]
    #         ]
    #     )
    )
]


class TestParseHaproxyConfig(object):
    @pytest.mark.parametrize("files,expected", TEST_FILES)
    def test_files(self, files, expected):
        parsed = parse_haproxy_config(files)
        assert parsed == expected
