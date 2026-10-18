# Native output framing reference

`native_outputs.json` copies the four literal Python-reference wire vectors in
`src/lotus_v2/test_output.cpp::FixedVectors` at source commit `5aa296b7c`.
They cover native, burn, token (full u64 value), and token burn outputs. Hash
strings preserve byte order exactly; no display reversal is performed.

The Rust tests require byte-exact decode/encode equality and reject every
truncated prefix. Structural and malformed-frame tests supplement these fixtures.
These are output framing vectors, not transaction identity or consensus proofs.
