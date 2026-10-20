This folder contains lint scripts.

check-doc.py
============
Check for missing documentation of command line options.

lint-v2-tx-hybrid.py
====================
Check that the removed hybrid-transaction forms (the wrapped versions
0x80000007/0xC0000007, AdaptLegacy, HasStructuralV2Identity,
IsDisallowedNonV7Tx, bad-txns-non-v7-format) do not return to `src/` or
`test/functional/`.

git-subtree-check.sh
====================
Run this script from the root of the repository to verify that a subtree matches the contents of
the commit it claims to have been updated to.

To use, make sure that you have fetched the upstream repository branch in which the subtree is
maintained:
* for `src/secp256k1`: https://github.com/bitcoin-core/secp256k1.git (branch master)
* for `src/leveldb`: https://github.com/bitcoin-core/leveldb.git (branch bitcoin-fork)
* for `src/crypto/ctaes`: https://github.com/bitcoin-core/ctaes.git (branch master)

Usage: `git-subtree-check.sh DIR (COMMIT)`

`COMMIT` may be omitted, in which case `HEAD` is used.

Structured logging
==================
`lint-log-events.py` checks production structured calls for canonical registry
keys, duplicate fields, missing template values and required scope context.
Peer events (`peer_*`) carry `PeerId`, RPC calls (`rpc_call_*`) carry `Method`,
mempool transactions (`mempool_tx_*`) carry `TxId`, and block connections
(`block_connect_*`) carry `BlockHash`. Global listener/server events use names
that do not imply an individual peer or call. Test/benchmark fixtures are
excluded so deliberate malformed-input serializer tests remain possible.
Run `lint-log-events.py --self-test` for its parser/negative cases.

`lint-log-field-keys.py` invokes the native C++ compiler to verify valid keys
compile, while runtime ids, mismatched field types and out-of-range ids fail.
Free-form string keys are also rejected by C++ compile assertions in the
logging event unit suite. `ninja check-log-events check-log-field-keys` runs
these checks, and native `check`/`check-all` include them when these maintainer scripts
are present (upstream release source packages omit test/lint). Cross builds run
the source lint; compiler contract checks require a configured native compiler.
