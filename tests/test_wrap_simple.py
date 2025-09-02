#  Copyright (c) Kuba Szczodrzyński 2025-9-1.

from socket import socket
from ssl import SSLSocket

import pytest
from base import PROTOCOLS_v1_2, TestBase

from sslpsk3 import wrap_socket


@pytest.mark.parametrize("protocol", PROTOCOLS_v1_2)
class TestWrapSimple(TestBase):

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, protocol):
        self.protocol = protocol

    def wrap_server(self, sock: socket) -> SSLSocket:
        return wrap_socket(
            sock,
            psk=self.psk,
            ciphers=self.ciphers,
            ssl_version=self.protocol,
            server_side=True,
        )

    def wrap_client(self, sock: socket) -> SSLSocket:
        return wrap_socket(
            sock,
            psk=self.psk,
            ciphers=self.ciphers,
            ssl_version=self.protocol,
            server_side=False,
        )


del TestBase
