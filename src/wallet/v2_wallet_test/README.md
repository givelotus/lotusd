# Offline native V2 Payment wallet packet

This candidate owns a freshly generated, encrypted native secp256k1 key in the
existing SQLite wallet backend. Wallet paths are directories containing
`wallet.sqlite`. BerkeleyDB, `wallet.dat`, key import and wallet migration are
unsupported. It uses no inherited wallet transactions, Bitcoin addresses,
descriptors, legacy sighashes or mempool/broadcast paths.

`wallet::Profile` binds exact caller ChainID, genesis ID and
`BlockValidationProfileDigest`. Its versioned string is a local storage identity,
not a new consensus hash or production profile. An existing inherited wallet's
development storage label does not match and is never upgraded automatically.
Every chain read checks this binding against the actual store. The enclosing
caller must serialize wallet and chain access.

Creation requires a nonempty passphrase and always generates a fresh compressed
`CKey`. Existing wallet crypter/master-key primitives encrypt it before any key
record is written; no plaintext key record or secret export API exists. Open
returns a locked wallet. The compiler receives only the x-only public key.
`RegisterPayment` accepts exactly `PUSH32 owner; CHECKSIGVERIFY; TRUE`, with this
wallet's owner and an empty proof. The helper also checks the declared leaf/root.
This is a narrow Payment policy API, not a general contract-artifact loader.

Track funding by explicit outpoint: actual authenticated `ReadCoin` supplies its
value, policy, height, parent MTP and coinbase status. There is no full UTXO scan.
Preparation chooses one mature, present, unreserved native Payment coin in
outpoint order. The caller supplies an explicit native recipient Output and
absolute fee; the final signature byte fee floor is checked. Tokens, minting,
multiple inputs and other owned policies are outside this packet.

Plans bind the wallet/profile, complete resolved coin, tip/root and native FULL
signing digest. Signing re-resolves and rejects stale or modified intent. Fresh
auxiliary entropy is supplied, scalar/auxiliary copies are cleansed immediately,
and the reviewed signer cleanses its secp keypair. The complete signed transaction
passes `CheckOrdinaryWithLookup` before one SQLite transaction records its bytes,
input reservation and owned outputs. Only then are public bytes/IDs returned.
The enclosing full-block validator remains responsible for block acceptance.

SQLite and chainstate commit separately. Reconciliation reports active coin
presence, maturity and local reservation; missing coins do not distinguish
spending, orphaning or lack of confirmation. It never uses retained historical
bodies as active-chain evidence. Cached checkpoints never authorize spending.
Reservations survive confirmation/disconnect until explicit `Abandon`; abandoning
does not revoke exported bytes. A backup is a point-in-time copy and cannot
remember exports made afterward. Failed/ambiguous wallet writes require reopening
and reconciliation before another spend attempt.

## Build and native API tests

Use a wallet-enabled, Chronik-OFF full build containing the shared manifest
adapter and reviewed signer cleansing. Source headers, command source and static
libraries must come from the same dependency source root. Configure fails closed
for an independent command checkout, even if the path appears similar.

```sh
cmake -S src/wallet/v2_wallet_test -B /tmp/new-v2-wallet-build -GNinja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DLOTUS_BUILD_DIR=/path/to/exact-source/build
cmake --build /tmp/new-v2-wallet-build -j4
ctest --test-dir /tmp/new-v2-wallet-build --output-on-failure
```

The tests use a synthetic authenticated disk store to isolate wallet behavior;
they directly commit fixture transitions and do not claim complete block
acceptance. They cover encrypted creation/backup/reopen, exact profile rejection,
owner/proof rejection, deterministic coin selection, maturity/fees, native FULL
signatures, modified/stale plans, reservations and disconnect reconciliation.
A real SQLite trigger makes the second state write fail and proves rollback of
both tracked outputs and reservations with no exported bytes. Temporary artifacts
are printed and retained, including on failure. No sockets or live wallets are
used. The same test source can be registered in the full-tree Boost unit suite;
root owns that CMake registration.

Observed dependency build: native `97b78c6849e11f3be7188593c70a3387e0db84a4`,
`/private/tmp/lotus-v2-daemon-indexed-exact-20261015/build`. Earlier failure evidence
under `/private/tmp/lotus-v2-wallet-chain-first` used mismatched old libraries and
indexed headers; it is preserved and is not wallet approval evidence.

## Compiler pilot helper protocol

`lotus-v2-wallet-pilot MANIFEST CHAIN_HOME WALLET_HOME OP` consumes one bounded JSON
object on stdin and emits one public JSON object. It calls root's shared
`OpenDevelopmentHome`, preserving the existing manifest/namespace checks and
initializing an explicitly supplied fresh chain home when needed. It opens no
sockets. `WALLET_HOME` is a directory, separate from chainstate.

| OP | Request fields | Success output |
| --- | --- | --- |
| `create` | `passphrase_file` | `public_key` |
| `register` | `script`, `proof: []`, `root` | `policy_root` |
| `track` | `prev_txid`, `prev_index` | result |
| `prepare` | `recipient`, `fee` | result |
| `sign` | `recipient`, `fee`, `passphrase_file` | `wire`, `txid`, `txhash`, `digest` |
| `reconcile` | none | `tip`, `height`, `coins` |
| `abandon` | `txid` | result |
| `stale` | `recipient`, `fee`, `passphrase_file`, `expected_tip` | predecessor `tip`, `disconnected_tip`, stale result |

Hashes/scripts are lowercase hex. Recipient is
`{flags:0,value:"decimal",branches:["hex"],paths:[[0]]}`; the codec accepts other
canonical native recipient policies but spending remains this one owned policy.
`fee` is unsigned decimal. `passphrase_file` is an explicit absolute temporary
file, read as exact bytes without newline stripping, never printed. The compiler
harness creates/removes that file and uses only ephemeral test wallet keys.

Every response includes `result`: `success` exits 0; `invalid`, `locked`, `stale`
and `insufficient_funds` exit 2; `storage_error` exits 4; setup/parsing exceptions
return `setup_error` and exit 1. Failure exports no wire. Reconcile coin records
contain `prev_txid`, `prev_index`, `present`, `reserved`, `mature`, `value`.

Run `stale` after maturity and before the first successful sign. It prepares,
checks the explicit expected tip, disconnects through `DisconnectDevelopmentTip`
and rejects the old plan. The caller must reconnect the exact removed block
before continuing. This operation exists only for the offline integration gate.

The compiler pilot owns artifact compilation, funding/maturity blocks, reference
validation and actual daemon full-block submission of wallet-produced bytes.
Those gates remain distinct from the synthetic API tests above. Root owns shared
manifest/command and full-tree target integration; this packet adds only wallet
API, tests and the isolated helper.
