import os
import pytest
from stapled.util.functions import parse_haproxy_config

TEST_FILES = [
    (
        # Basic parsing of `stats sock` and `crt`
        ['stapled/tests/.haproxy/haproxy-test.cfg'],
        (
            [['/etc/ssl/private/', '/etc/ssl/private\ certs']],
            ['/run/haproxy/admin.sock']
        )
    ), (
        # Adding a `crt_base` directive
        # passing files as a string deliberately
        'stapled/tests/.haproxy/haproxy-test-base.cfg',
        (
            [['tests/haproxy/', 'tests/haproxy/certbot/']],
            ['/run/haproxy/admin-crt-base.sock']
        )
    ), (
        # Two test files test
        [
            'stapled/tests/.haproxy/haproxy-test.cfg',
            'stapled/tests/haproxy/haproxy-test-base.cfg'
        ],
        (
            [
                ['/etc/ssl/private/', '/etc/ssl/private\ certs'],
                ['tests/haproxy/', 'tests/haproxy/certbot/']
            ],
            ['/run/haproxy/admin.sock', '/run/haproxy/admin-crt-base.sock']
        )
    )
]

class TestParseHaproxyConfig(object):
    @pytest.mark.parametrize("files,expected", TEST_FILES)
    def test_test_files(self, files, expected):
        print(os.getcwd())
        assert parse_haproxy_config(files) == expected
