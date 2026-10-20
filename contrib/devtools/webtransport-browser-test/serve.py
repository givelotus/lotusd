#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Serve wt_test.html and write the page's GET /result?<json> to a file."""

import argparse
import http.server
import pathlib
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--result", required=True, help="where to write the JSON")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent
    result = pathlib.Path(args.result)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(root), **kw)

        def do_GET(self):
            if self.path.startswith("/result?"):
                result.write_text(urllib.parse.unquote(self.path[len("/result?"):]))
                self.send_response(204)
                self.end_headers()
                return
            super().do_GET()

        def log_message(self, *a):
            pass

    http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
