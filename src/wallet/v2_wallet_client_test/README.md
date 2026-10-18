# Inherited stream flag regression

Run against an actual built client and a valid development manifest:

```sh
python3 src/wallet/v2_wallet_client_test/test_fd_flags.py \
  /absolute/path/to/lotus-v2-wallet-client \
  /absolute/path/to/manifest.json
```

The test creates temporary encrypted wallets and private Unix socketpairs. It
starts no nodes and sends no node requests. Parent-owned pipe descriptors share
the child's stdin/stdout open file descriptions, allowing exact `F_GETFL`
comparisons after the child exits.

Both initially blocking and initially nonblocking streams retain an additional
`O_APPEND` flag. Each mode exercises successful create/info, malformed JSON,
argument setup failure, an input deadline and a closed output pipe. The macOS
kernel exposes a sticky written flag through `F_GETFL`; a preliminary output
write establishes that flag before taking the baseline snapshot.
