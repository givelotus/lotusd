# Lotus V2 addresses ("xpi1...")

## Status and provisional design decision (2026-10-19)

This format is pre-release and remains open to revision during testnet,
before a production format is frozen. The accepted direction is a typed
address: either an explicit MAST commitment or parameters for an exactly
specified common spending-program template. There is no requirement to
preserve unreleased address encodings through such revisions.

The existing C++/Python codecs and published vectors in this source tree
implement only type 0, described below using its original name "version 0".
The template and extension rules in the next section record the agreed
specification direction; they are not a claim of wallet/RPC implementation
or current decoder acceptance. Existing type-0 bytes and vectors are
unchanged by this document update.

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

Each allocated template must define its exact program bytes, parameter
encoding and lengths, and deterministic branch-root derivation. Type 1
means "reveal a public key matching this hash, then satisfy the standard
signature check". Its hash algorithm/width, public-key representation,
program bytes and signature rules remain to be pinned in the template
specification and shared test vectors; this decision does not silently
choose HASH160 or a particular native program encoding. A change to an
allocated template's interpretation requires a new ID.

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

Native message signing is separate work. A keyhash template can permit a
proof containing the public key and a message signature, but needs an
explicit proof encoding and message-specific signing domain. This address
design alone does not enable the legacy signmessage/verifymessage RPCs for
native addresses.

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

Implementations: `src/lotus_v2/address.{h,cpp}` (C++) and
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
symbols; other types are not implemented and MUST currently be rejected. Each future
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
6. `unknown version`: body symbol 0 must be 0.
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

The implemented type-0 decoder rejects selectors 1–31, including the existing
selector-31 negative vector. That remains correct until template/extension
support is implemented. Selector 31 is reserved for the provisional extension
escape; it is no longer designated permanently invalid by the design.

Future types retain the first symbol as selector and use checksum-covered,
strictly specified parameters. Extended IDs must be canonical and bounded,
not arbitrary variable-length fields. Any decision to retain the current
checksum/constants for new body lengths requires the checks described above.
