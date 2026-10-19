#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet PWA routes: /wallet/ files and browser sessions.

Covers GET /wallet/* (from -walletpwadir, and the embedded bundle when the
build has one), the one-time login token and password logins at
/auth/session, the session cookie on JSON-RPC with its Origin, Host and CSRF
checks, expiry and logout, -rpcwhitelist for session users, -trustedproxy
and X-Forwarded-Proto, -publicbind, -walletpwa=0, -gui, and that Basic auth
(bitcoin-cli) and -rpccorsdomain behave as before. Raw http.client only; no
browser.
"""

import base64
import hmac
import http.client
import json
import os
import platform
import re
import stat
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_greater_than, p2p_port, rpc_port

PUBLIC_PORT_INDEX = 41
IDLE = 7 * 24 * 60 * 60
CSP_START = "default-src 'none'; script-src 'self'"


def rpcauth_line(user, password, salt="00112233445566778899aabbccddeeff"):
    """An -rpcauth value, as share/rpcauth makes it"""
    digest = hmac.new(salt.encode(), password.encode(), "SHA256").hexdigest()
    return f"{user}:{salt}${digest}"


class WalletPwaTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    requires = {"cli"}

    def setup_network(self):
        self.pwadir = os.path.join(self.options.tmpdir, "pwa")
        os.makedirs(os.path.join(self.pwadir, "views"))
        self.write_app("index.html", "<!doctype html><title>Wallet</title>")
        self.write_app("a.js", "export const v = 1;\n")
        self.write_app("views/v.js", "export {};\n")
        self.write_app(".secret.txt", "dot-files are never served")
        with open(
            os.path.join(self.options.tmpdir, "x.txt"), "w", encoding="utf8"
        ) as f:
            f.write("outside the app directory")
        self.base_args = [f"-walletpwadir={self.pwadir}", "-debug=http"]
        self.add_nodes(1, [self.base_args])
        self.start_nodes()

    def write_app(self, rel, text):
        with open(os.path.join(self.pwadir, rel), "w", encoding="utf8") as f:
            f.write(text)

    # HTTP helpers

    @property
    def host(self):
        return f"127.0.0.1:{rpc_port(0)}"

    @property
    def origin(self):
        return f"http://{self.host}"

    def request(self, method, path, body=None, headers=None, port=None):
        """Return (status, headers (lower-case names, lists), body bytes)."""
        conn = http.client.HTTPConnection("127.0.0.1", port or rpc_port(0), timeout=30)
        hdrs = {"Host": self.host}
        hdrs.update(headers or {})
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        conn.request(method, path, body, hdrs)
        res = conn.getresponse()
        data = res.read()
        out = {}
        for k, v in res.getheaders():
            out.setdefault(k.lower(), []).append(v)
        conn.close()
        return res.status, out, data

    def basic(self):
        user, password = self.cookie_credentials()
        return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def cookie_credentials(self):
        path = os.path.join(self.nodes[0].datadir, self.chain, ".cookie")
        with open(path, encoding="ascii") as f:
            return f.read().split(":", 1)

    def login(self, body, headers=None, expect=200):
        hdrs = {"Origin": self.origin, "Content-Type": "application/json"}
        hdrs.update(headers or {})
        status, h, data = self.request("POST", "/auth/session", body, hdrs)
        assert_equal(status, expect)
        if expect != 200:
            return None
        reply = json.loads(data)
        cookie = h["set-cookie"][0]
        name, value = cookie.split(";")[0].split("=", 1)
        assert_equal(name, f"nodewallet_{rpc_port(0)}")
        return {"cookie": f"{name}={value}", "set_cookie": cookie, **reply}

    def login_cookie_file(self, **kwargs):
        user, password = self.cookie_credentials()
        return self.login({"user": user, "password": password}, **kwargs)

    def session_headers(self, s, **override):
        hdrs = {
            "Cookie": s["cookie"],
            "Origin": self.origin,
            "X-CSRF-Token": s["csrf"],
            "Content-Type": "application/json",
        }
        hdrs.update(override)
        return {k: v for k, v in hdrs.items() if v is not None}

    def rpc(self, s, method, params=None, path="/", **override):
        body = {"jsonrpc": "1.0", "id": 1, "method": method, "params": params or []}
        return self.request("POST", path, body, self.session_headers(s, **override))

    def mint_url(self, *args):
        res = self.nodes[0].getwalletpwaurl(*args)
        m = re.fullmatch(r"(.*)/wallet/#/login/([0-9a-f]{64})", res["url"])
        assert m, res["url"]
        return res, m.group(1), m.group(2)

    def restart(self, extra_args=None, **kwargs):
        self.stop_node(0)
        self.start_node(0, self.base_args + (extra_args or []), **kwargs)

    # Tests

    def run_test(self):
        self.test_static_files()
        self.test_password_login()
        s = self.login_cookie_file()
        self.test_session_rpc(s)
        self.test_basic_auth_unchanged(s)
        self.test_tokens()
        self.test_expiry_and_logout()
        self.test_whitelist()
        self.test_cors_unchanged()
        self.test_trusted_proxy()
        self.test_publicbind()
        self.test_disabled_and_gui_errors()
        self.test_gui()
        self.test_embedded_bundle()

    def test_static_files(self):
        self.log.info("GET /wallet redirects to /wallet/")
        status, h, _ = self.request("GET", "/wallet")
        assert_equal((status, h["location"]), (308, ["/wallet/"]))

        self.log.info("/wallet/ is index.html, with the security headers")
        status, h, body = self.request("GET", "/wallet/")
        assert_equal(status, 200)
        assert_equal(body, b"<!doctype html><title>Wallet</title>")
        assert_equal(h["content-type"], ["text/html; charset=utf-8"])
        assert_equal(h["cache-control"], ["no-store"])
        assert h["content-security-policy"][0].startswith(CSP_START)
        assert "frame-ancestors 'none'" in h["content-security-policy"][0]
        assert_equal(h["x-content-type-options"], ["nosniff"])
        assert_equal(h["x-frame-options"], ["DENY"])
        assert_equal(h["referrer-policy"], ["no-referrer"])
        assert_equal(h["cross-origin-opener-policy"], ["same-origin"])
        assert_equal(h["cross-origin-resource-policy"], ["same-origin"])
        assert h["permissions-policy"][0].startswith("camera=(self)")
        assert "etag" not in h
        assert "access-control-allow-origin" not in h

        self.log.info("Files have their MIME types; edits show without a restart")
        status, h, body = self.request("GET", "/wallet/a.js?v=1")
        assert_equal((status, body), (200, b"export const v = 1;\n"))
        assert_equal(h["content-type"], ["text/javascript; charset=utf-8"])
        self.write_app("a.js", "export const v = 2;\n")
        assert_equal(self.request("GET", "/wallet/a.js")[2], b"export const v = 2;\n")
        assert_equal(self.request("GET", "/wallet/views/v.js")[0], 200)

        self.log.info("Traversal, dot-files and unknown types are 404")
        for path in (
            "/wallet/../x.txt",
            "/wallet/%2e%2e/x.txt",
            "/wallet/views/..%2f..%2fx.txt",
            "/wallet/views%5c..%5c..%5cx.txt",
            "/wallet/.secret.txt",
            "/wallet/missing.js",
            "/wallet/views",
            "/wallet/a.exe",
        ):
            status, h, _ = self.request("GET", path)
            assert_equal(status, 404)
            assert h["content-security-policy"][0].startswith(CSP_START)

        self.log.info("Other methods under /wallet/ are still JSON-RPC's")
        assert_equal(self.request("HEAD", "/wallet/")[0], 405)
        assert_equal(self.request("PUT", "/wallet/a.js")[0], 405)

    def test_password_login(self):
        self.log.info("A wrong password is refused after a delay")
        start = time.time()
        self.login({"user": "__cookie__", "password": "wrong"}, expect=401)
        assert_greater_than(time.time() - start, 0.24)
        self.login({"token": "00" * 32}, expect=401)

        self.log.info("Login requires JSON from the node's own origin")
        user, password = self.cookie_credentials()
        creds = {"user": user, "password": password}
        self.login(creds, headers={"Content-Type": "text/plain"}, expect=415)
        self.login(creds, headers={"Origin": "http://evil.example"}, expect=403)
        self.login(creds, headers={"Origin": "http://127.0.0.1:3000"}, expect=403)
        self.login(
            creds,
            headers={
                "Host": f"evil.example:{rpc_port(0)}",
                "Origin": f"http://evil.example:{rpc_port(0)}",
            },
            expect=403,
        )
        status, _, _ = self.request(
            "POST", "/auth/session", creds, {"Content-Type": "application/json"}
        )
        assert_equal(status, 403)
        self.login({"user": "x" * 5000, "password": ""}, expect=413)
        self.login([], expect=400)

        self.log.info("The cookie file's credentials log in")
        s = self.login_cookie_file()
        assert_equal(s["user"], "__cookie__")
        assert re.fullmatch("[0-9a-f]{64}", s["csrf"])
        cookie = s["set_cookie"]
        for attr in ("Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=2592000"):
            assert attr in cookie, cookie
        assert "Secure" not in cookie

        self.log.info("GET /auth/session returns the session and its CSRF token")
        status, h, body = self.request(
            "GET", "/auth/session", headers={"Cookie": s["cookie"]}
        )
        assert_equal(status, 200)
        info = json.loads(body)
        assert_equal((info["csrf"], info["user"]), (s["csrf"], "__cookie__"))
        assert_equal(info["pwa_version"], "dev")
        assert_equal(h["cache-control"], ["no-store"])
        assert "access-control-allow-origin" not in h
        assert_equal(self.request("GET", "/auth/session")[0], 401)
        assert_equal(
            self.request(
                "GET",
                "/auth/session",
                headers={"Cookie": s["cookie"], "Host": "evil.example"},
            )[0],
            403,
        )
        assert_equal(
            self.request(
                "GET",
                "/auth/session",
                headers={"Cookie": s["cookie"], "Origin": "http://evil.example"},
            )[0],
            403,
        )
        assert_equal(self.request("PUT", "/auth/session")[0], 405)

    def test_session_rpc(self, s):
        self.log.info("The session cookie authorizes JSON-RPC, with Origin and CSRF")
        status, h, body = self.rpc(s, "getblockcount")
        assert_equal((status, json.loads(body)["result"]), (200, 0))
        assert_equal(h["cache-control"], ["no-store"])
        # No wallet is loaded: an RPC error (or 404 without wallet support),
        # but authorized.
        assert self.rpc(s, "getbalances", path="/wallet/")[0] != 401
        self.log.info("...and nothing less")
        for override in (
            {"X-CSRF-Token": None},
            {"X-CSRF-Token": "0" * 64},
            {"X-CSRF-Token": s["csrf"].upper()},
            {"Origin": None},
            {"Origin": "http://evil.example"},
            {"Origin": "http://127.0.0.1:3000"},
            {"Origin": f"https://{self.host}"},
            {
                "Host": f"evil.example:{rpc_port(0)}",
                "Origin": f"http://evil.example:{rpc_port(0)}",
            },
            {"Host": "evil.example"},
            {"Content-Type": "text/plain"},
            {"Content-Type": None},
            {"Cookie": f"nodewallet_{rpc_port(0)}={'0' * 64}"},
            {"Cookie": f"nodewallet_1={s['cookie'].split('=', 1)[1]}"},
            {"Cookie": None},
        ):
            status, h, _ = self.rpc(s, "getblockcount", **override)
            assert_equal(status, 401)
            if override.get("X-CSRF-Token", "") is None:
                assert_equal(h["www-authenticate"], ['Basic realm="jsonrpc"'])
            else:
                # The PWA shows its own login: no browser password prompt.
                assert "www-authenticate" not in h

    def test_basic_auth_unchanged(self, s):
        self.log.info("Basic auth needs no CSRF or Origin, and bitcoin-cli works")
        status, _, body = self.request(
            "POST",
            "/",
            {"method": "getblockcount", "params": [], "id": 1},
            {"Authorization": self.basic()},
        )
        assert_equal((status, json.loads(body)["result"]), (200, 0))
        status, _, _ = self.request(
            "POST",
            "/",
            {"method": "getblockcount", "params": [], "id": 1},
            {
                "Authorization": "Basic " + base64.b64encode(b"__cookie__:x").decode(),
                "Cookie": s["cookie"],
                "X-CSRF-Token": s["csrf"],
                "Origin": self.origin,
            },
        )
        # Wrong Basic credentials are not rescued by a valid session.
        assert_equal(status, 401)
        assert_equal(self.nodes[0].cli("getblockcount").send_cli(), 0)
        assert_equal(self.nodes[0].getblockcount(), 0)

    def test_tokens(self):
        self.log.info("getwalletpwaurl's token logs in once")
        res, base, token = self.mint_url()
        assert_equal(base, self.origin)
        assert_equal(res["pwa_version"], self.nodes[0].getwalletpwaurl()["pwa_version"])
        assert_greater_than(res["expires"], int(time.time()) + 100)
        s = self.login({"token": token})
        assert_equal(s["user"], "__cookie__")
        assert_equal(self.rpc(s, "getblockcount")[0], 200)
        self.login({"token": token}, expect=401)
        self.login({"token": token.upper()}, expect=401)

        _, base, _ = self.mint_url("https://Node.Example.org:443")
        assert_equal(base, "https://node.example.org")
        for bad in ("node.example.org", "https://x/path", "ftp://x"):
            try:
                self.nodes[0].getwalletpwaurl(bad)
                raise AssertionError("accepted " + bad)
            except Exception as e:
                assert "base must be" in str(e), e

        self.log.info("Tokens expire after 120 s")
        now = int(time.time())
        _, _, token = self.mint_url()
        self.nodes[0].setmocktime(now + 121)
        self.login({"token": token}, expect=401)
        self.nodes[0].setmocktime(0)

        self.log.info("Tokens never reach debug.log")
        _, _, token = self.mint_url()
        self.login({"token": token})
        with open(self.nodes[0].debug_log_path, encoding="utf8") as f:
            log = f.read()
        assert token not in log
        assert "Wallet PWA session created for RPC user __cookie__" in log

    def test_expiry_and_logout(self):
        self.log.info("Sessions expire after 7 idle days")
        now = int(time.time())
        self.nodes[0].setmocktime(now)
        s = self.login_cookie_file()
        self.nodes[0].setmocktime(now + IDLE - 10)
        assert_equal(self.rpc(s, "getblockcount")[0], 200)
        self.nodes[0].setmocktime(now + 2 * IDLE - 20)
        assert_equal(
            self.request("GET", "/auth/session", headers={"Cookie": s["cookie"]})[0],
            200,
        )
        self.nodes[0].setmocktime(now + 3 * IDLE)
        assert_equal(
            self.request("GET", "/auth/session", headers={"Cookie": s["cookie"]})[0],
            401,
        )
        assert_equal(self.rpc(s, "getblockcount")[0], 401)
        self.log.info("...and 30 days after login, even when used")
        self.nodes[0].setmocktime(now)
        s = self.login_cookie_file()
        for day in range(6, 30, 6):
            self.nodes[0].setmocktime(now + day * 86400)
            assert_equal(self.rpc(s, "getblockcount")[0], 200)
        self.nodes[0].setmocktime(now + 30 * 86400)
        assert_equal(self.rpc(s, "getblockcount")[0], 401)
        self.nodes[0].setmocktime(0)

        self.log.info("Logout needs the CSRF token and ends the session")
        s = self.login_cookie_file()
        hdrs = self.session_headers(s)
        assert_equal(
            self.request(
                "POST", "/auth/logout", "{}", {**hdrs, "X-CSRF-Token": "0" * 64}
            )[0],
            401,
        )
        assert_equal(
            self.request(
                "POST", "/auth/logout", "{}", {**hdrs, "Origin": "http://evil.example"}
            )[0],
            403,
        )
        assert_equal(self.request("GET", "/auth/logout", headers=hdrs)[0], 405)
        status, h, body = self.request("POST", "/auth/logout", "{}", hdrs)
        assert_equal((status, body), (204, b""))
        assert_equal(h["set-cookie"], [f"nodewallet_{rpc_port(0)}=; Max-Age=0; Path=/"])
        assert_equal(self.rpc(s, "getblockcount")[0], 401)
        assert_equal(
            self.request("GET", "/auth/session", headers={"Cookie": s["cookie"]})[0],
            401,
        )
        assert_equal(self.request("POST", "/auth/logout", "{}", hdrs)[0], 401)

        self.log.info("A node restart logs everyone out")
        s = self.login_cookie_file()
        self.restart()
        assert_equal(self.rpc(s, "getblockcount")[0], 401)

    def test_whitelist(self):
        self.log.info("-rpcwhitelist applies to a session user (singleton and batch)")
        self.restart(
            [
                "-rpcauth=" + rpcauth_line("alice", "alicepw"),
                "-rpcwhitelist=alice:getblockcount,getbestblockhash",
                # The test framework's own (cookie) user stays unrestricted.
                "-rpcwhitelistdefault=0",
            ]
        )
        self.login({"user": "alice", "password": "wrong"}, expect=401)
        s = self.login({"user": "alice", "password": "alicepw"})
        assert_equal(s["user"], "alice")
        assert_equal(self.rpc(s, "getblockcount")[0], 200)
        assert_equal(self.rpc(s, "getblockchaininfo")[0], 403)
        batch = [
            {"jsonrpc": "1.0", "id": 1, "method": "getblockcount", "params": []},
            {"jsonrpc": "1.0", "id": 2, "method": "getbestblockhash", "params": []},
        ]
        status, _, body = self.request("POST", "/", batch, self.session_headers(s))
        assert_equal(status, 200)
        assert_equal([r["error"] for r in json.loads(body)], [None, None])
        batch.append({"jsonrpc": "1.0", "id": 3, "method": "stop", "params": []})
        assert_equal(self.request("POST", "/", batch, self.session_headers(s))[0], 403)
        self.log.info("A token minted by alice logs in as alice")
        token = self.request(
            "POST",
            "/",
            {"method": "getwalletpwaurl", "params": [], "id": 1},
            {"Authorization": "Basic " + base64.b64encode(b"alice:alicepw").decode()},
        )
        # getwalletpwaurl is not on alice's whitelist
        assert_equal(token[0], 403)
        self.restart(
            [
                "-rpcauth=" + rpcauth_line("alice", "alicepw"),
                "-rpcwhitelist=alice:getblockcount,getwalletpwaurl",
                "-rpcwhitelistdefault=0",
            ]
        )
        status, _, body = self.request(
            "POST",
            "/",
            {"method": "getwalletpwaurl", "params": [], "id": 1},
            {"Authorization": "Basic " + base64.b64encode(b"alice:alicepw").decode()},
        )
        assert_equal(status, 200)
        token = json.loads(body)["result"]["url"].rsplit("/", 1)[1]
        s = self.login({"token": token})
        assert_equal(s["user"], "alice")
        assert_equal(self.rpc(s, "getbestblockhash")[0], 403)
        self.restart()

    def test_cors_unchanged(self):
        self.log.info("-rpccorsdomain is still Basic-auth only")
        cors = "http://cors.example"
        self.restart([f"-rpccorsdomain={cors}"])
        status, h, _ = self.request(
            "OPTIONS",
            "/",
            None,
            {
                "Origin": cors,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert_equal(status, 200)
        assert_equal(h["access-control-allow-origin"], [cors])
        assert_equal(h["access-control-allow-credentials"], ["true"])
        status, h, _ = self.request(
            "POST",
            "/",
            {"method": "getblockcount", "params": [], "id": 1},
            {"Origin": cors, "Authorization": self.basic()},
        )
        assert_equal(status, 200)
        assert_equal(h["access-control-allow-origin"], [cors])
        status, h, _ = self.request(
            "POST",
            "/",
            {"method": "getblockcount", "params": [], "id": 1},
            {"Origin": cors},
        )
        assert_equal(status, 401)
        assert_equal(h["www-authenticate"], ['Basic realm="jsonrpc"'])
        # A session is not usable from the CORS origin.
        s = self.login_cookie_file()
        assert_equal(self.rpc(s, "getblockcount", Origin=cors)[0], 401)
        self.login_cookie_file(headers={"Origin": cors}, expect=403)
        assert_equal(self.rpc(s, "getblockcount")[0], 200)

    def test_trusted_proxy(self):
        self.log.info("Behind -trustedproxy, X-Forwarded-Proto: https sets Secure")
        self.restart(["-trustedproxy=127.0.0.1"])
        https_origin = {"Origin": f"https://{self.host}"}
        s = self.login_cookie_file(
            headers={**https_origin, "X-Forwarded-Proto": "http, https"}
        )
        assert "; Secure" in s["set_cookie"], s["set_cookie"]
        assert_equal(
            self.rpc(
                s, "getblockcount", **https_origin, **{"X-Forwarded-Proto": "https"}
            )[0],
            200,
        )
        # Over https the Origin must say https.
        assert_equal(
            self.rpc(s, "getblockcount", **{"X-Forwarded-Proto": "https"})[0], 401
        )
        s = self.login_cookie_file(headers={"X-Forwarded-Proto": "https, http"})
        assert "Secure" not in s["set_cookie"]

        self.log.info("A plain-http session from a non-loopback client is refused")
        self.restart(
            [
                "-trustedproxy=127.0.0.1",
                "-rpcallowip=127.0.0.1",
                "-rpcallowip=203.0.113.0/24",
            ]
        )
        user, password = self.cookie_credentials()
        status, _, body = self.request(
            "POST",
            "/auth/session",
            {"user": user, "password": password},
            {
                "Origin": self.origin,
                "Content-Type": "application/json",
                "X-Forwarded-For": "203.0.113.9",
            },
        )
        assert_equal(status, 403)
        assert_equal(
            json.loads(body)["error"],
            "wallet sessions need HTTPS or a loopback connection",
        )
        s = self.login_cookie_file(
            headers={
                **https_origin,
                "X-Forwarded-For": "203.0.113.9",
                "X-Forwarded-Proto": "https",
            }
        )
        assert "; Secure" in s["set_cookie"]

        self.log.info("X-Forwarded-Proto from an untrusted peer is ignored")
        self.restart(["-trustedproxy=10.0.0.0/8"])
        self.login_cookie_file(
            headers={**https_origin, "X-Forwarded-Proto": "https"}, expect=403
        )
        s = self.login_cookie_file(headers={"X-Forwarded-Proto": "https"})
        assert "Secure" not in s["set_cookie"]
        self.restart()

    def test_publicbind(self):
        self.log.info("-publicbind listeners do not serve the wallet")
        port = p2p_port(PUBLIC_PORT_INDEX)
        self.restart([f"-publicbind=127.0.0.1:{port}"])
        for method, path in (
            ("GET", "/wallet/"),
            ("GET", "/wallet"),
            ("GET", "/auth/session"),
            ("POST", "/auth/session"),
        ):
            assert_equal(self.request(method, path, port=port)[0], 404)
        self.restart()

    def test_disabled_and_gui_errors(self):
        self.log.info("-walletpwa=0 turns the routes and sessions off")
        s = self.login_cookie_file()
        self.restart(["-walletpwa=0"])
        for method, path in (
            ("GET", "/wallet/"),
            ("GET", "/wallet"),
            ("GET", "/wallet/a.js"),
            ("GET", "/auth/session"),
            ("POST", "/auth/session"),
            ("POST", "/auth/logout"),
        ):
            assert_equal(self.request(method, path)[0], 404)
        assert_equal(self.rpc(s, "getblockcount")[0], 401)
        try:
            self.nodes[0].getwalletpwaurl()
            raise AssertionError("getwalletpwaurl worked with -walletpwa=0")
        except Exception as e:
            assert "disabled" in str(e), e
        self.stop_node(0)

        self.log.info("-gui needs the wallet UI")
        self.nodes[0].assert_start_raises_init_error(
            ["-gui", "-walletpwa=0", f"-walletpwadir={self.pwadir}"],
            "Error: -gui needs the wallet UI, but -walletpwa=0",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.nodes[0].assert_start_raises_init_error(
            ["-walletpwadir=" + os.path.join(self.pwadir, "missing")],
            "is not a directory",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.nodes[0].assert_start_raises_init_error(
            ["-walletpwaorigin=https://node.example.org/path"],
            "Invalid -walletpwaorigin",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.start_node(0, ["-walletpwa=1"])
        self.has_bundle = self.nodes[0].getwalletpwaurl()["pwa_version"] != ""
        self.stop_node(0)
        if not self.has_bundle:
            self.nodes[0].assert_start_raises_init_error(
                ["-gui"],
                "Error: -gui needs the wallet UI, but this node was built without it",
                match=ErrorMatch.PARTIAL_REGEX,
            )
        self.start_node(0, self.base_args)

    def test_gui(self):
        self.log.info("-gui opens the login link with the platform's opener")
        bindir = os.path.join(self.options.tmpdir, "fakebin")
        record = os.path.join(self.options.tmpdir, "opened.txt")
        os.makedirs(bindir, exist_ok=True)
        for name in ("open", "xdg-open"):
            path = os.path.join(bindir, name)
            with open(path, "w", encoding="utf8") as f:
                f.write(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{record}"\n')
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""))
        env.setdefault("DISPLAY", ":0")
        if platform.system() == "Windows":
            self.log.info("Skipped: ShellExecute cannot be faked here")
            return
        self.restart(["-gui"], env=env)
        self.wait_until(lambda: os.path.exists(record))
        with open(record, encoding="utf8") as f:
            url = f.read().strip()
        m = re.fullmatch(
            rf"http://127\.0\.0\.1:{rpc_port(0)}/wallet/#/login/([0-9a-f]{{64}})", url
        )
        assert m, url
        s = self.login({"token": m.group(1)})
        assert_equal(s["user"], "__cookie__")
        self.login({"token": m.group(1)}, expect=401)
        with open(self.nodes[0].debug_log_path, encoding="utf8") as f:
            log = f.read()
        assert "Opening the wallet UI in the default browser" in log
        assert m.group(1) not in log
        self.restart()

    def test_embedded_bundle(self):
        if not self.has_bundle:
            self.log.info("No embedded bundle in this build: skipping its checks")
            return
        self.log.info("The embedded bundle: gzip, ETag and 304")
        self.restart_node(0, ["-debug=http"])
        status, h, body = self.request(
            "GET", "/wallet/", headers={"Accept-Encoding": "gzip"}
        )
        assert_equal(status, 200)
        assert_equal(h["content-encoding"], ["gzip"])
        assert_equal(h["cache-control"], ["no-cache"])
        assert_equal(h["vary"], ["Accept-Encoding"])
        etag = h["etag"][0]
        assert re.fullmatch(r'"[0-9a-f]{32}-gz"', etag), etag
        status, h, body = self.request(
            "GET",
            "/wallet/",
            headers={"Accept-Encoding": "gzip", "If-None-Match": etag},
        )
        assert_equal((status, body), (304, b""))
        status, h, body = self.request("GET", "/wallet/index.html")
        assert_equal(status, 200)
        assert "content-encoding" not in h or h["content-encoding"] != ["gzip"]
        assert re.fullmatch(r'"[0-9a-f]{32}"', h["etag"][0])
        status, _, body = self.request("GET", "/wallet/BUNDLE.json")
        assert_equal(status, 200)
        assert_equal(
            json.loads(body)["version"], self.nodes[0].getwalletpwaurl()["pwa_version"]
        )
        s = self.login_cookie_file()
        status, _, body = self.request(
            "GET", "/auth/session", headers={"Cookie": s["cookie"]}
        )
        assert_equal(
            json.loads(body)["pwa_version"],
            json.loads(self.request("GET", "/wallet/BUNDLE.json")[2])["version"],
        )


if __name__ == "__main__":
    WalletPwaTest().main()
