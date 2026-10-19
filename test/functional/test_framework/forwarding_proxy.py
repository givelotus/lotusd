#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A forwarding SOCKS5 proxy for tests: stands in for Tor, Xray and other
clients a node reaches peers through with -proxy."""

import socket
import threading


class ForwardingSocks5Proxy:
    """Minimal SOCKS5 (no auth, CONNECT) that forwards traffic."""

    def __init__(self, port):
        self.requests = []  # (atyp, addr, port)
        self.lock = threading.Lock()
        self.server = socket.create_server(("127.0.0.1", port))
        self.running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self):
        while self.running:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            if not self.running:
                conn.close()
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    @staticmethod
    def recvall(conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data += chunk
        return data

    def handle(self, conn):
        try:
            ver, nmethods = self.recvall(conn, 2)
            self.recvall(conn, nmethods)
            conn.sendall(b"\x05\x00")
            ver, cmd, _, atyp = self.recvall(conn, 4)
            if atyp == 3:
                addr = self.recvall(conn, self.recvall(conn, 1)[0]).decode()
            elif atyp == 1:
                addr = socket.inet_ntoa(self.recvall(conn, 4))
            else:
                addr = socket.inet_ntop(socket.AF_INET6, self.recvall(conn, 16))
            port = int.from_bytes(self.recvall(conn, 2), "big")
            with self.lock:
                self.requests.append((atyp, addr, port))
            target = socket.create_connection(
                ("127.0.0.1" if addr == "localhost" else addr, port)
            )
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        except Exception:
            conn.close()
            return

        def pump(src, dst):
            try:
                while data := src.recv(65536):
                    dst.sendall(data)
            except OSError:
                pass
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        threading.Thread(target=pump, args=(conn, target), daemon=True).start()
        threading.Thread(target=pump, args=(target, conn), daemon=True).start()

    def stop(self):
        self.running = False
        # On Linux, close() alone neither wakes a thread blocked in accept()
        # nor stops the socket listening; shutdown() does both.
        try:
            self.server.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.server.close()
