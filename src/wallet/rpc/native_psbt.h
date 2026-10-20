// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#ifndef BITCOIN_WALLET_RPC_NATIVE_PSBT_H
#define BITCOIN_WALLET_RPC_NATIVE_PSBT_H

class CWallet;
class JSONRPCRequest;
class UniValue;

UniValue WalletProcessNativePsbtRPC(const JSONRPCRequest &request,
                                    const CWallet &wallet);
#endif
