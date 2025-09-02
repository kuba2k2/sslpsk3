#  Copyright (c) Kuba Szczodrzyński 2025-9-1.

import random
import sys
from socket import SHUT_RDWR, SO_REUSEADDR, SOL_SOCKET, error, socket
from ssl import (
    PROTOCOL_TLS,
    PROTOCOL_TLSv1,
    PROTOCOL_TLSv1_1,
    PROTOCOL_TLSv1_2,
    SSLSocket,
)
from string import ascii_letters, digits
from threading import Thread

import pytest

PROTOCOLS_v1_2 = [PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2]

if sys.version_info >= (3, 13, 0):
    # Use TLSv1.3 starting with Python 3.13
    # (earlier versions give ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT)
    PROTOCOLS = PROTOCOLS_v1_2 + [PROTOCOL_TLS, None]
else:
    PROTOCOLS = PROTOCOLS_v1_2


def randbytes(length: int) -> bytes:
    # Available in Python 3.9+
    return bytes(random.randint(0, 255) for _ in range(length))


def randascii(length: int) -> str:
    # Available in Python 3.9+
    return "".join(random.choices(ascii_letters + digits, k=length))


@pytest.mark.parametrize("ciphers", ["PSK", "PSK-AES256-CBC-SHA"])
class TestBase:
    ADDRESS = ("127.0.0.1", 6000)
    PSK_LEN = 32
    DATA_LEN = 32
    ID_LEN = 16

    @pytest.fixture(scope="function", autouse=True)
    def setup_and_teardown(self, ciphers: str):
        self.ciphers = ciphers

        self.psk = randbytes(self.PSK_LEN)
        self.identity = randascii(self.ID_LEN)
        self.hint = randascii(self.ID_LEN)

        self.sock_listen = socket()
        self.sock_server = None
        self.sock_server_psk = None
        self.sock_client = socket()
        self.sock_client_psk = None

        yield

        for sock in [
            self.sock_server_psk or self.sock_server,
            self.sock_client_psk or self.sock_client,
            self.sock_listen,
        ]:
            try:
                sock.shutdown(SHUT_RDWR)
            except error:
                pass
            finally:
                sock.close()

    def wrap_server(self, sock: socket) -> SSLSocket:
        raise NotImplementedError()

    def wrap_client(self, sock: socket) -> SSLSocket:
        raise NotImplementedError()

    def start_server(self):
        self.sock_listen = socket()
        self.sock_listen.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.sock_listen.bind(self.ADDRESS)
        self.sock_listen.listen(1)

        def accept():
            self.sock_server, _ = self.sock_listen.accept()
            self.sock_server_psk = self.wrap_server(self.sock_server)
            data = self.sock_server_psk.recv(self.DATA_LEN)
            self.sock_server_psk.sendall(data)

        Thread(target=accept).start()

    def test(self):
        self.start_server()

        send_data = randbytes(self.DATA_LEN)

        self.sock_client = socket()
        self.sock_client.connect(self.ADDRESS)
        self.sock_client_psk = self.wrap_client(self.sock_client)
        self.sock_client_psk.sendall(send_data)
        recv_data = self.sock_client_psk.recv(32)

        assert send_data == recv_data
