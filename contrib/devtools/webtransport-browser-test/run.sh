#!/usr/bin/env sh
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Run only with a coordinated runtime slot. All node data and browser profiles
# live under the required fresh --out directory; user profiles are never used.
set -eu
exec python3 "$(dirname "$0")/run.py" "$@"
