# Lotus V2 addresses ("xpi1...")

## Status and provisional design decision (2026-10-19)

This format is pre-release and remains open to revision during testnet,
before a production format is frozen. The accepted direction is a typed
address: either an explicit MAST commitment or parameters for an exactly
specified common spending-program template. There is no requirement to
preserve unreleased address encodings through such revisions.

The released implementation baseline has only type 0. A separate candidate
adds the type-1 codec/template and native message RPC support described here.
Its build and runtime validation status must be recorded with its delivery;
this document does not claim the candidate is integrated. Native wallet
receive/spend wiring is a distinct dependency. Existing type-0 bytes and
vectors are unchanged.

## Address types and extension

| Type ID | Meaning | Payload |
|---|---|---|
| 0 | Explicit MAST root | One 32-byte branch root |
| 1 | Standard keyhash spending-program template | Public-key hash |
| 2–30 | Reserved for future standardized templates | Defined by each template |
| 31 | Escape introducing an extended template ID | Extended ID followed by that template's parameters |

The first address-body character carries the five-bit type selector. IDs
0–30 fit in that character; selector 31 introduces an extended ID instead
of requiring extra characters for common types. Do not use ad hoc ranges
of ordinary IDs to signal that another byte is relevant. Extension fields
are address-alphabet symbols, not implicitly eight-bit bytes.

The exact extended-ID encoding, maximum encoded length, and any extended-ID
range assignments must be specified and tested before implementation. The
encoding must be bounded and canonical: a direct ID must not also have an
extended spelling, and overlong or truncated encodings must be rejected.
All type/extension/payload symbols must be covered by the checksum.

Each allocated template defines exact program bytes, parameter encoding and
lengths, and deterministic branch-root derivation. A change to an allocated
template's interpretation requires a new ID.

### Type 1: x-only keyhash template (candidate, 2026-10-20)

The payload is **32 bytes: unkeyed BLAKE3 of the 32-byte big-endian x
coordinate of a valid secp256k1 public key**. This is the same x-only public
key representation consumed by native BIP340 `CHECKSIG`, not HASH160 of SEC
bytes. Points P and -P intentionally have one address and the same BIP340
spending authority. No compressed-key parity bit is hashed.

The exact 37-byte native VM program is:

```
7a ba 20 <keyhash:32> 92 bb
DUP BLAKE3 PUSH32(keyhash) EQUALVERIFY CHECKSIG
```

The argument stack is `[signature, xonly_public_key]`, with the public key
on top. The signature is the existing native transaction BIP340 signature
(64 bytes in default sighash mode, or the existing explicit-mode encoding).
No new opcode, transaction signature algorithm or consensus exception is
introduced. `CHECKSIG` enforces a valid 32-byte x-only point. The ordinary
payment output is `flags=0, branches=[BranchLeaf(program)], paths=[[0]]`,
with its value supplied by the payer. The recipient reconstructs this exact
program to spend the output. Native ownership detection must not mutate
canonical transaction output bytes into scripts.

Type 1 uses the same 52-symbol payload, four zero padding bits, eight-symbol
checksum, 61-symbol body and network constants as type 0; only the first
selector changes from 0 (`q`) to 1 (`p`). Therefore the existing fixed-length
checksum substitution/length analysis applies without a new shorter body.
Types 2–31 remain rejected by the candidate codec until separately defined.

Independent Python `blake3` reference vector (public scalar 1):

```
xonly = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
keyhash = f9f2a0b353f482f415281da3a00929d08a7d9a6498054f5ef6623b5580e607f7
BranchLeaf(program) = 84f3ac422780d391bc9210fa6e19dc8d0fd2bb1acd390e065c6a0acda9f667bb
regtest = rxpi1pl8e2pv6n7jp0g9fgrk36qzff6z98mxnynqz57hhkvga4tq8xqlmsq2859j5u
```

This preserves a full 256-bit hash instead of shortening to HASH160. It
fits the existing native VM and address body without introducing a hash
opcode or legacy ECDSA transaction template. It remains provisional through
testnet. Enabling the codec alone is insufficient to make these addresses
the wallet default: coin selection, signing, change, ownership, rescan,
restart and reorg must first pass the native wallet lifecycle gates.

A paying wallet expands a recognized template into the canonical program
and MAST commitment. The on-chain output can retain the ordinary root
representation if the existing VM can express that exact template. Both
paying and receiving wallets must implement the template identically.
Unknown types are unsupported, never guessed or interpreted as type 0.
Type 0 is an explicit commitment, not an unknown/invalid program; a payer
need not know its preimage. An opaque root cannot in general be converted
back into a template address.

Before activation, extend the C++/Python codecs, wallet/RPC integrations,
PWA/SDK consumers and shared vectors together. Add negative vectors for
unknown IDs, noncanonical extensions, lengths/padding, malformed parameters
and wrong networks. Re-evaluate checksum/error-detection bounds for every
new body length: the existing 61-symbol guarantees do not automatically
apply to shorter keyhash or extended addresses. Current decoders must
continue rejecting unsupported types until that work is complete.

Application message signing for type 1 uses the separately specified
[compact recoverable ECDSA message proof](lotus-message-signing.md). It deliberately
retains the familiar address/message/signature workflow; it does not alter
native BIP340 transaction signatures or accept arbitrary MAST policies as
single-key statements.

## Specification and implementation tracking

This monorepo document is the design-decision home on branch `lotus-v2`.
The daemon source mirrors the address-format document at
`doc/standards/xpiaddr.md`; its owning patch is currently `v2/065` in the
consolidated stack. Keep the owner document and this decision synchronized
when either changes. The earlier addendum-source update is commit
`4ecbec839b`; it is an implementation-facing mirror, not a separate authority.

Implementation tracking: the original type-0 codec is integrated. The type-1
codec/template and compact message RPC support are in a separate candidate;
native wallet receive/spend wiring is being validated independently. The PWA
obtains addresses from the daemon and must not relabel a legacy address as
native. This status does not reconcile every older specification with the
current implementation stack.

## Implemented type 0

A Lotus V2 output locks coins to branch roots: an ordinary payment is one
32-byte root over every way the coins can be spent. A version 0 address carries
exactly that root; the output it describes is `flags=0, branches=[root],
paths=[[0]]`.

Example (mainnet, root `sha256("example branch root")`):

```
xpi1q80z6tf5zlwd794z4dpe28fehp3qdt2lg8q3jz3mzacmrqw20vseq37xlywnx
```

Design goals: one double-click selects the whole address (no `:`); the prefix
says the network; a checksum detects typos and wrong-network pastes but never
corrects anything; and the format is simple to implement exactly. It uses
cashaddr's alphabet and 40-bit BCH checksum, but drops cashaddr's prefix
expansion, size-coded version byte, variable-length regrouping and optional
prefix.

Daemon-source implementations: `src/lotus_v2/address.{h,cpp}` (C++) and
`test/functional/test_framework/xpiaddr.py` (Python reference). Test vectors:
`src/test/data/lotus_v2_address.json` (valid and invalid, with the exact
rejection reason for each invalid one).


## Alphabet and symbols

```
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"      (symbol value = index, 0..31)
```

A symbol's uppercase form is accepted on input only (see Case).

## String layout (version 0)

```
<hrp> "1" <version> <payload: 52 symbols> <checksum: 8 symbols>
```

| field | symbols | content |
|---|---|---|
| hrp | 3 or 4 chars | `xpi` mainnet, `txpi` testnet, `rxpi` regtest; literal, lowercase |
| separator | 1 | the character `1` (not in CHARSET) |
| version | 1 | `0` (`q`) = one 32-byte branch root |
| payload | 52 | 260 bits: the root's 256 bits, most significant bit first, followed by 4 zero bits; cut into 52 five-bit groups, first group first |
| checksum | 8 | makes `PolyMod(body) == K[hrp]` where body = the 61 symbols after `1` |

Total length: 65 characters (`xpi`), 66 (`txpi`, `rxpi`). Version 0 bodies are exactly 61
symbols; type 1 uses the same layout with selector 1; unsupported types MUST be rejected. Each future
template must specify its exact payload length; the extension envelope is described above.

Payload as an integer: `P = (int(root, big-endian) << 4)`; payload symbol `i` (0-based) is
`(P >> (5 * (51 - i))) & 31`. Decoding: `P = fold(acc = acc*32 + s)` over the 52 symbols;
require `P & 15 == 0`; root = `P >> 4` as 32 big-endian bytes.

## Checksum

```
GEN = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]

def polymod(symbols):           # identical to cashaddr's PolyMod without the final "^ 1"
    c = 1
    for d in symbols:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        for i in range(5):
            if (c0 >> i) & 1:
                c ^= GEN[i]
    return c
```

Constants (40 bits each; literals, part of the spec):

```
K["xpi"]  = 0xb70061479e
K["txpi"] = 0xadda0f1635
K["rxpi"] = 0x8172b45d63
```

Encoding: `mod = polymod(data + [0]*8) ^ K[hrp]`; checksum symbol `i` = `(mod >> (5*(7-i))) & 31`
(`data` = version + payload symbols).
Verification for type 0: `polymod(all 61 body symbols) == K[hrp]`.

Nothing from the hrp is fed to `polymod`. There is no "expand prefix" step and no "^ 1".

Guarantees (61-symbol body): any <= 6 substitutions (claimed by cashaddr;
<= 5 verified exhaustively when this format was designed), any burst of <= 8 symbols, any single insertion or deletion
(length), any uncorrupted wrong-network string, any wrong-network string with <= 4
substitutions; everything else missed with probability ~2^-40.

## Case

Encoders output lowercase. Decoders accept a string that is entirely lowercase or entirely
uppercase (letters only matter; digits and `1` are caseless) and MUST reject mixed case; after
the check, lowercase the string. Uppercase is intended for QR codes.

## Decoding, in order (each step's failure reason is the string the reference uses)

1. `mixed case`: reject if `s != lower(s) and s != upper(s)`; then `s = lower(s)`.
2. `unknown prefix`: split at the **last** `1`; the part before it must be one of `xpi`, `txpi`,
   `rxpi`. (If the application knows which network it is on and the hrp differs: `wrong network`.)
3. `bad length`: the body (after the `1`) must be exactly 61 characters.
4. `bad character`: every body character must be in CHARSET.
5. `bad checksum`: `polymod(body symbols) != K[hrp]`.
6. `unknown version`: body symbol 0 must be 0, or 1 with the type-1 candidate.
7. `nonzero padding`: the low 4 bits of the 260-bit payload integer must be zero.

Output: (network, 32-byte root). Decoders MUST NOT attempt error correction or suggest
corrected strings. Callers strip whitespace and URI framing before decoding.

## URI and QR

Payment request: `xpi:<address>[?amount=<decimal XPI>...]`, BIP21 style; scheme matching is
case-insensitive, parameter names are case-sensitive. QR encoders SHOULD emit `XPI:` + the
uppercase address when there are no parameters (fits QR alphanumeric mode) and the lowercase
URI otherwise.

## Adding a network (provenance of K)

`K = SHA256("xpi address checksum" || chain_id || counter)[0:5]` as a big-endian integer, with
`counter` the smallest single byte such that (a) `K >> 35 != 0` and (b) for every existing
network constant `K'`, no pattern of <= 4 symbol substitutions has syndrome `K ^ K'`
(checked meet-in-the-middle: `K ^ K'` must not be the sum of two syndromes of weight <= 2, of
which there are about 1.76 million). For the three defined networks `counter = 0`:

```
mainnet chain_id 960da6d7e4c6f4fe0b639f08e7c344a2c654610aed4b3377149666406a0d1597 -> 0xb70061479e
testnet chain_id 5f5e904cc5dfab62a8b62ee22551bca02e47a6d92d0de1f73c150e906bc3851b -> 0xadda0f1635
regtest chain_id 00..00                                                            -> 0x8172b45d63
```

Implementations hardcode the literals; they never run this derivation.

## Current rejection and future allocation

The original type-0 decoder rejects selectors 1–31. The type-1 candidate accepts
0 and 1, and retains rejection of 2–31, including the selector-31 negative
vector. Selector 31 is reserved for the provisional extension escape; it is
not permanently invalid by design.

Future types retain the first symbol as selector and use checksum-covered,
strictly specified parameters. Extended IDs must be canonical and bounded,
not arbitrary variable-length fields. Any decision to retain the current
checksum/constants for new body lengths requires the checks described above.
