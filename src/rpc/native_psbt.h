// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#ifndef BITCOIN_RPC_NATIVE_PSBT_H
#define BITCOIN_RPC_NATIVE_PSBT_H

#include <lotus_v2/psbt_signing.h>

#include <optional>
#include <string>

class CMutableTransaction;
class JSONRPCRequest;
class UniValue;
struct RPCResult;
struct RPCResults;

namespace rpc {
RPCResults NativePsbtDecodeResults(RPCResult legacy);
RPCResults NativePsbtFinalizeResults(RPCResult legacy);
bool IsNativePsbt(const std::string &base64);
lotus::v2::NativePsbt DecodeNativePsbtBase64(const std::string &base64);
std::string EncodeNativePsbtBase64(const lotus::v2::NativePsbt &psbt);
lotus::v2::NativePsbtContext
NativePsbtNodeContext(const JSONRPCRequest &request);
bool ValidateNativePsbtNode(const JSONRPCRequest &request,
                            const lotus::v2::Transaction &tx,
                            std::string &error);
UniValue DecodeNativePsbtRPC(const JSONRPCRequest &request);
UniValue CombineNativePsbtRPC(const JSONRPCRequest &request);
UniValue FinalizeNativePsbtRPC(const JSONRPCRequest &request);
UniValue UpdateNativePsbtRPC(const JSONRPCRequest &request);
std::string ConvertNativePsbtRPC(const CMutableTransaction &tx);
} // namespace rpc
#endif
