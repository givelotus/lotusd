// Copyright (c) 2021 The Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <array>
#include <atomic>
#include <optional>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <hash.h>
#include <logging.h>
#include <node/miner.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/blockstorage.h>
#include <node/ui_interface.h>
#include <common/args.h>
#include <streams.h>
#include <util/time.h>
#include <timedata.h>
#include <undo.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <nng/nng.h>
// NNG 2 declares every protocol in nng.h and removed the per-protocol headers.
#if NNG_MAJOR_VERSION < 2
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/reqrep0/rep.h>
#endif

#include "nng_interface_generated.h"
#include <nng_interface/nng_interface.h>

using node::NodeContext;

enum class NngRpcWorkerState {
    UNINIT,
    RECV,
    SEND,
    CLOSED,
};

class NngRpcServer;

// NNG 2 takes its own nng_err type here; NNG 1 takes an int.
static const char *NngErrorString(int rv) {
#if NNG_MAJOR_VERSION >= 2
    return nng_strerror(static_cast<nng_err>(rv));
#else
    return nng_strerror(rv);
#endif
}

// NNG 2 renamed nng_close to nng_socket_close.
static int NngCloseSocket(nng_socket sock) {
#if NNG_MAJOR_VERSION >= 2
    return nng_socket_close(sock);
#else
    return nng_close(sock);
#endif
}

#define NNG_TRY_LOG(call)                                                      \
    do {                                                                       \
        int rv = (call);                                                       \
        if (rv != 0) {                                                         \
            LogPrintf("NNG Error: %s (at %s:%d: %s)\n", NngErrorString(rv),   \
                      __FILE__, __LINE__, #call);                              \
            return;                                                            \
        }                                                                      \
    } while (false)

#define NNG_TRY_ERROR(call, format_str)                                        \
    do {                                                                       \
        int rv = (call);                                                       \
        if (rv != 0) {                                                         \
            return InitError(strprintf(_(format_str), NngErrorString(rv)));   \
        }                                                                      \
    } while (false)

enum class NngRpcErrorCode {
    NO_RPC_ERROR = 0,
    NNG_ERROR,
    INVALID_FLATBUFFER_ENCODING,
    UNKNOWN_RPC_METHOD,
    BLOCK_ID_UNKNOWN_TYPE,
    BLOCK_NOT_FOUND,
    BLOCK_DATA_CORRUPTED,
    INVALID_BLOCK_SLICE,
    INVALID_MINING_REQUEST,
    MINING_TEMPLATE_BUILD_FAILED,
};

struct RpcResult {
    NngRpcErrorCode error_code;
    std::vector<uint8_t> data = std::vector<uint8_t>();
};

std::string ErrorMsg(NngRpcErrorCode code) {
    switch (code) {
        case NngRpcErrorCode::NO_RPC_ERROR:
            return "No error";
        case NngRpcErrorCode::INVALID_FLATBUFFER_ENCODING:
            return "Invalid flatbuffer encoding";
        case NngRpcErrorCode::UNKNOWN_RPC_METHOD:
            return "Unknown RPC method";
        case NngRpcErrorCode::BLOCK_ID_UNKNOWN_TYPE:
            return "Unknown block ID type, only blockhash and block height "
                   "allowed";
        case NngRpcErrorCode::BLOCK_NOT_FOUND:
            return "Block not found";
        case NngRpcErrorCode::BLOCK_DATA_CORRUPTED:
            return "Block data corrupted";
        case NngRpcErrorCode::INVALID_BLOCK_SLICE:
            return "Invalid block slice";
        case NngRpcErrorCode::INVALID_MINING_REQUEST:
            return "Invalid mining request";
        case NngRpcErrorCode::MINING_TEMPLATE_BUILD_FAILED:
            return "Failed to build mining template";
        default:
            return "Unknown error";
    }
}

class NngRpcServer;

class NngRpcWorker {
    NngRpcWorkerState m_state;
    nng_aio *m_aio;
    nng_ctx m_ctx;
    NngRpcServer *m_server;

    void HandleCallback();

public:
    NngRpcWorker();

    void Init(nng_socket sock, NngRpcServer *server);
    void Shutdown();
    static void Callback(void *arg);
};

class NngRpcServer {
    static const size_t NUM_WORKERS = 64;

    nng_socket m_sock;
    std::vector<NngRpcWorker> m_workers;
    const NodeContext &m_node;

    NngRpcErrorCode GetBlock(flatbuffers::FlatBufferBuilder &builder,
                             const NngInterface::GetBlockRequest *request);

    NngRpcErrorCode
    GetBlockRange(flatbuffers::FlatBufferBuilder &builder,
                  const NngInterface::GetBlockRangeRequest *request);

    NngRpcErrorCode
    GetBlockSlice(flatbuffers::FlatBufferBuilder &builder,
                  const NngInterface::GetBlockSliceRequest *request);

    NngRpcErrorCode
    GetUndoSlice(flatbuffers::FlatBufferBuilder &builder,
                 const NngInterface::GetUndoSliceRequest *request);

    NngRpcErrorCode GetMempool(flatbuffers::FlatBufferBuilder &builder,
                               const NngInterface::GetMempoolRequest *request);

    NngRpcErrorCode
    GetMiningTemplate(flatbuffers::FlatBufferBuilder &builder,
                      const NngInterface::GetMiningTemplateRequest *request);

public:
    NngRpcServer(const Consensus::Params &consensus, const NodeContext &node)
        : m_node(node) { (void)consensus; }

    NngRpcErrorCode HandleMsg(flatbuffers::FlatBufferBuilder &builder,
                              nng_msg *incoming_msg);
    bool Listen(const std::string &rpc_url);
    void Shutdown() {
        for (NngRpcWorker &worker : m_workers) {
            worker.Shutdown();
        }
        NngCloseSocket(m_sock);
    }
};

bool NngRpcServer::Listen(const std::string &rpc_url) {
    NNG_TRY_ERROR(nng_rep0_open(&m_sock), "Failed opening NNG rep0 socket: %s");
    std::string listen_failure_msg =
        strprintf("Failed listening on -nngrpc=%s: %%s", rpc_url);
    NNG_TRY_ERROR(nng_listen(m_sock, rpc_url.c_str(), NULL, 0),
                  listen_failure_msg.c_str());
    m_workers.resize(NUM_WORKERS);
    for (NngRpcWorker &worker : m_workers) {
        worker.Init(m_sock, this);
    }
    LogPrintf("NNG interface: RPC server listening at %s\n", rpc_url);
    return true;
}

NngRpcWorker::NngRpcWorker() {
    m_state = NngRpcWorkerState::UNINIT;
}

void NngRpcWorker::Init(nng_socket sock, NngRpcServer *server) {
    m_server = server;
    NNG_TRY_LOG(nng_aio_alloc(&m_aio, NngRpcWorker::Callback, this));
    NNG_TRY_LOG(nng_ctx_open(&m_ctx, sock));
    m_state = NngRpcWorkerState::RECV;
    nng_ctx_recv(m_ctx, m_aio);
}

void NngRpcWorker::Shutdown() {
    m_state = NngRpcWorkerState::CLOSED;
    NNG_TRY_LOG(nng_ctx_close(m_ctx));
    nng_aio_free(m_aio);
}

void NngRpcWorker::Callback(void *arg) {
    NngRpcWorker *worker = (NngRpcWorker *)arg;
    worker->HandleCallback();
}

void NngRpcWorker::HandleCallback() {
    switch (m_state) {
        case NngRpcWorkerState::UNINIT:
            LogPrintf("Error: Worker in state UNINIT\n");
            break;
        case NngRpcWorkerState::RECV: {
            NNG_TRY_LOG(nng_aio_result(m_aio));
            nng_msg *incoming_msg = nng_aio_get_msg(m_aio);
            flatbuffers::FlatBufferBuilder fbb;
            NngRpcErrorCode error_code = m_server->HandleMsg(fbb, incoming_msg);
            flatbuffers::FlatBufferBuilder result_fbb(fbb.GetSize() + 256);
            if (error_code == NngRpcErrorCode::NO_RPC_ERROR) {
                result_fbb.Finish(NngInterface::CreateRpcResult(
                    result_fbb, true, 0, result_fbb.CreateString(""),
                    result_fbb.CreateVector(fbb.GetBufferPointer(),
                                            fbb.GetSize())));
            } else {
                result_fbb.Finish(NngInterface::CreateRpcResult(
                    result_fbb, false, int32_t(error_code),
                    result_fbb.CreateString(ErrorMsg(error_code))));
            }
            nng_msg *outgoing_msg;
            NNG_TRY_LOG(nng_msg_alloc(&outgoing_msg, result_fbb.GetSize()));
            memcpy(nng_msg_body(outgoing_msg),
                   (void *)result_fbb.GetBufferPointer(), result_fbb.GetSize());
            nng_aio_set_msg(m_aio, outgoing_msg);
            m_state = NngRpcWorkerState::SEND;
            nng_ctx_send(m_ctx, m_aio);
            break;
        }
        case NngRpcWorkerState::SEND: {
            NNG_TRY_LOG(nng_aio_result(m_aio));
            m_state = NngRpcWorkerState::RECV;
            nng_ctx_recv(m_ctx, m_aio);
            break;
        }
        case NngRpcWorkerState::CLOSED: {
            break;
        }
    }
}

NngRpcErrorCode NngRpcServer::HandleMsg(flatbuffers::FlatBufferBuilder &fbb,
                                        nng_msg *incoming_msg) {
    flatbuffers::Verifier verifier((uint8_t *)nng_msg_body(incoming_msg),
                                   nng_msg_len(incoming_msg));
    if (!verifier.VerifyBuffer<NngInterface::RpcCall>()) {
        return NngRpcErrorCode::INVALID_FLATBUFFER_ENCODING;
    }
    const NngInterface::RpcCall *rpc =
        flatbuffers::GetRoot<NngInterface::RpcCall>(nng_msg_body(incoming_msg));
    switch (rpc->rpc_type()) {
        case NngInterface::RpcRequest_GetBlockRequest: {
            return GetBlock(fbb, rpc->rpc_as_GetBlockRequest());
        }
        case NngInterface::RpcRequest_GetBlockRangeRequest: {
            return GetBlockRange(fbb, rpc->rpc_as_GetBlockRangeRequest());
        }
        case NngInterface::RpcRequest_GetBlockSliceRequest: {
            return GetBlockSlice(fbb, rpc->rpc_as_GetBlockSliceRequest());
        }
        case NngInterface::RpcRequest_GetUndoSliceRequest: {
            return GetUndoSlice(fbb, rpc->rpc_as_GetUndoSliceRequest());
        }
        case NngInterface::RpcRequest_GetMempoolRequest: {
            return GetMempool(fbb, rpc->rpc_as_GetMempoolRequest());
        }
        case NngInterface::RpcRequest_GetMiningTemplateRequest: {
            return GetMiningTemplate(fbb,
                                     rpc->rpc_as_GetMiningTemplateRequest());
        }
        default:
            return NngRpcErrorCode::UNKNOWN_RPC_METHOD;
    }
}

template <typename T>
NngRpcErrorCode GetBlockIndex(ChainstateManager &chainman, const T *request, CBlockIndex *&block_index) {
    LOCK(cs_main);
    switch (request->block_id_type()) {
        case NngInterface::BlockIdentifier_Height: {
            int32_t height = request->block_id_as_Height()->height();
            block_index = chainman.ActiveChain()[height];
            break;
        }
        case NngInterface::BlockIdentifier_Hash: {
            const NngInterface::Hash *hash =
                request->block_id_as_Hash()->hash();
            const std::vector<uint8_t> blockhash(hash->data()->begin(), hash->data()->end());
            block_index = chainman.m_blockman.LookupBlockIndex(BlockHash(uint256(blockhash)));
            break;
        }
        default:
            return NngRpcErrorCode::BLOCK_ID_UNKNOWN_TYPE;
    }
    if (!block_index) {
        return NngRpcErrorCode::BLOCK_NOT_FOUND;
    }
    return NngRpcErrorCode::NO_RPC_ERROR;
}

NngInterface::Hash CreateFbsHash(const uint8_t *data) {
    std::array<uint8_t, 32> array;
    memcpy(array.data(), data, array.size());
    return NngInterface::Hash(flatbuffers::span<uint8_t, 32>{array});
}

flatbuffers::Offset<NngInterface::BlockHash>
CreateFbsBlockHash(flatbuffers::FlatBufferBuilder &fbb,
                   const BlockHash &blockhash) {
    NngInterface::Hash hash = CreateFbsHash(blockhash.data());
    return NngInterface::CreateBlockHash(fbb, &hash);
}

flatbuffers::Offset<NngInterface::BlockHeader>
CreateFbsBlockHeader(flatbuffers::FlatBufferBuilder &fbb,
                     const CBlockHeader &header) {
    DataStream raw_header{};
    raw_header << header;
    return NngInterface::CreateBlockHeader(
        fbb, fbb.CreateVector((uint8_t *)raw_header.data(), raw_header.size()),
        CreateFbsBlockHash(fbb, header.GetHash()),
        CreateFbsBlockHash(fbb, header.hashPrevBlock), header.nBits,
        header.GetBlockTime());
}

flatbuffers::Offset<NngInterface::TxId>
CreateFbsTxId(flatbuffers::FlatBufferBuilder &fbb, const TxId &txid) {
    NngInterface::Hash hash = CreateFbsHash(txid.data());
    return NngInterface::CreateTxId(fbb, &hash);
}

flatbuffers::Offset<NngInterface::TxOut>
CreateFbsTxOut(flatbuffers::FlatBufferBuilder &fbb,
               const CTxOut &spent_output) {
    return NngInterface::CreateTxOut(
        fbb, spent_output.nValue / Amount::satoshi(),
        fbb.CreateVector(spent_output.scriptPubKey.data(),
                         spent_output.scriptPubKey.size()));
}

flatbuffers::Offset<NngInterface::Coin>
CreateFbsCoin(flatbuffers::FlatBufferBuilder &fbb, const Coin &spent_coin) {
    const int32_t nHeight =
        spent_coin.GetHeight() == 0x7fff'ffff ? -1 : spent_coin.GetHeight();
    return NngInterface::CreateCoin(fbb,
                                    CreateFbsTxOut(fbb, spent_coin.GetTxOut()),
                                    spent_coin.IsCoinBase(), nHeight);
}

flatbuffers::Offset<
    flatbuffers::Vector<flatbuffers::Offset<NngInterface::Coin>>>
CreateFbsSpentCoins(flatbuffers::FlatBufferBuilder &fbb,
                    std::optional<const std::vector<Coin> *> spent_coins,
                    size_t &nUndoPos) {
    if (!spent_coins) {
        return 0;
    }
    std::vector<flatbuffers::Offset<NngInterface::Coin>> coins;
    for (const Coin &coin : **spent_coins) {
        nUndoPos +=
            GetSerializeSize(Using<TxInUndoFormatter>(coin));
        coins.push_back(CreateFbsCoin(fbb, coin));
    }
    nUndoPos += GetSizeOfCompactSize(coins.size());
    return fbb.CreateVector(coins);
}

flatbuffers::Offset<NngInterface::Tx>
CreateFbsTxMempool(flatbuffers::FlatBufferBuilder &fbb,
                   const CTransactionRef &tx,
                   const std::vector<Coin> &spent_coins) {
    size_t nUndoPos;
    DataStream tx_ser{};
    tx_ser << tx;
    return NngInterface::CreateTx(
        fbb, CreateFbsTxId(fbb, tx->GetId()),
        fbb.CreateVector((uint8_t *)tx_ser.data(), tx_ser.size()),
        CreateFbsSpentCoins(fbb, std::optional(&spent_coins), nUndoPos));
}

flatbuffers::Offset<NngInterface::BlockTx>
CreateFbsBlockTx(flatbuffers::FlatBufferBuilder &fbb, const CTransactionRef &tx,
                 std::optional<const std::vector<Coin> *> spent_coins,
                 size_t &nDataPos, size_t &nUndoPos) {
    DataStream tx_ser{};
    tx_ser << tx;
    const size_t data_pos = nDataPos;
    const size_t undo_pos = spent_coins ? nUndoPos : 0;
    nDataPos += tx_ser.size();
    auto ffb_spent_coins = CreateFbsSpentCoins(fbb, spent_coins, nUndoPos);
    return NngInterface::CreateBlockTx(
        fbb,
        NngInterface::CreateTx(
            fbb, CreateFbsTxId(fbb, tx->GetId()),
            fbb.CreateVector((uint8_t *)tx_ser.data(), tx_ser.size()),
            ffb_spent_coins),
        data_pos, undo_pos, spent_coins ? nUndoPos - undo_pos : 0);
}

flatbuffers::Offset<NngInterface::BlockMetadata>
CreateFbsBlockMetadata(flatbuffers::FlatBufferBuilder &fbb,
                       const CBlockMetadataField &metadata_field) {
    return NngInterface::CreateBlockMetadata(
        fbb, metadata_field.nFieldId,
        fbb.CreateVector(metadata_field.vData.data(),
                         metadata_field.vData.size()));
}

size_t GetFirstBlockTxOffset(const CBlock &block, const CBlockIndex *pindex) {
    return pindex->nDataPos + ::GetSerializeSize(CBlockHeader()) +
           ::GetSerializeSize(block.vMetadata) +
           GetSizeOfCompactSize(block.vtx.size());
}

size_t GetFirstUndoOffset(const CBlock &block, const CBlockIndex *pindex) {
    return pindex->nUndoPos + GetSizeOfCompactSize(block.vtx.size() - 1);
}

flatbuffers::Offset<NngInterface::Block>
CreateFbsBlock(node::BlockManager &blockman, flatbuffers::FlatBufferBuilder &fbb, const CBlock &block,
               const CBlockIndex *pindex) {
    size_t nDataPos = GetFirstBlockTxOffset(block, pindex);
    size_t nUndoPos = 0;
    CBlockUndo block_undo;
    if (pindex->nHeight) { // Genesis block doesn't have undo data
        nUndoPos = GetFirstUndoOffset(block, pindex);
        if (!blockman.ReadBlockUndo(block_undo, *pindex)) {
            return 0;
        }
    }
    std::vector<flatbuffers::Offset<NngInterface::BlockTx>> txs_fbs;
    for (size_t tx_idx = 0; tx_idx < block.vtx.size(); ++tx_idx) {
        std::optional<std::vector<Coin> *> spent_coins =
            tx_idx != 0
                ? std::optional(&block_undo.vtxundo[tx_idx - 1].vprevout)
                : std::nullopt;
        txs_fbs.push_back(CreateFbsBlockTx(fbb, block.vtx[tx_idx], spent_coins,
                                           nDataPos, nUndoPos));
    }
    std::vector<flatbuffers::Offset<NngInterface::BlockMetadata>> metadata;
    for (const CBlockMetadataField &metadata_field : block.vMetadata) {
        metadata.push_back(CreateFbsBlockMetadata(fbb, metadata_field));
    }
    return NngInterface::CreateBlock(
        fbb, CreateFbsBlockHeader(fbb, block.GetBlockHeader()),
        fbb.CreateVector(metadata), fbb.CreateVector(txs_fbs), pindex->nFile,
        pindex->nDataPos, pindex->nUndoPos);
}

/**
 * Convert a uint256 hash to little-endian hex as used by Stratum mining
 * protocol for prevhash.  Lotus uses little-endian uint256 internally, so the
 * raw bytes from hash.begin() are already in the correct byte order.
 */
static std::string HashToStratumHex(const uint256 &hash) {
    return HexStr(Span<const uint8_t>(hash.begin(), 32));
}

/** Convert a 32-bit integer to little-endian hex as used by Stratum params. */
static std::string Uint32ToStratumHex(uint32_t val) {
    uint8_t buf[4];
    buf[0] = val & 0xff;
    buf[1] = (val >> 8) & 0xff;
    buf[2] = (val >> 16) & 0xff;
    buf[3] = (val >> 24) & 0xff;
    return HexStr(Span<const uint8_t>(buf, 4));
}

/**
 * Compute merkle branches for the coinbase (tx index 0), suitable for
 * Stratum-style coinbase-first merkle root reconstruction.
 *
 * Uses Lotus merkle leaf format: SHA256d(tx_hash || tx_id)
 * Uses Lotus merkle tree construction: odd levels padded with uint256()
 */
static std::vector<uint256> ComputeMerkleBranches(const CBlock &block) {
    std::vector<uint256> leaves;
    leaves.reserve(block.vtx.size());
    for (const auto &tx : block.vtx) {
        HashWriter leaf_hash{};
        leaf_hash << tx->GetHash();
        leaf_hash << tx->GetId();
        leaves.push_back(leaf_hash.GetHash());
    }

    std::vector<uint256> branch;
    while (leaves.size() > 1) {
        // The coinbase is always the leftmost node, so its sibling is the
        // second node of each level (zero when the level has one node).
        branch.push_back(leaves.size() > 1 ? leaves[1] : uint256());

        std::vector<uint256> nextLevel;
        nextLevel.reserve((leaves.size() + 1) / 2);
        for (size_t i = 0; i < leaves.size(); i += 2) {
            const uint256 &left = leaves[i];
            // Lotus pads odd levels with uint256() instead of duplicating.
            const uint256 right =
                (i + 1 < leaves.size()) ? leaves[i + 1] : uint256();
            nextLevel.push_back(Hash(left, right));
        }
        leaves = std::move(nextLevel);
    }
    return branch;
}

/**
 * Split coinbase into coinbase1/coinbase2 for stratum extranonce insertion.
 *
 * The output is deterministic and updates the scriptSig length to account
 * for the reserved extranonce bytes.
 */
static std::pair<std::string, std::string>
SplitCoinbase(const CTransaction &coinbaseTx, size_t extranonce1Size,
              size_t extranonce2Size) {
    DataStream ss{};
    ss << coinbaseTx;
    const std::vector<uint8_t> raw(UCharCast(ss.data()),
                                   UCharCast(ss.data()) + ss.size());

    // version, input count (a coinbase has one input), prevout
    const size_t scriptSigLenPos = 4 + 1 + 36;
    const size_t scriptSigLen = coinbaseTx.vin[0].scriptSig.size();
    const size_t scriptSigStart =
        scriptSigLenPos + GetSizeOfCompactSize(scriptSigLen);
    const size_t scriptSigEnd = scriptSigStart + scriptSigLen;

    DataStream newLen{};
    WriteCompactSize(newLen, scriptSigLen + extranonce1Size + extranonce2Size);

    std::vector<uint8_t> cb1Data(raw.begin(), raw.begin() + scriptSigLenPos);
    cb1Data.insert(cb1Data.end(), UCharCast(newLen.data()),
                   UCharCast(newLen.data()) + newLen.size());
    cb1Data.insert(cb1Data.end(), raw.begin() + scriptSigStart,
                   raw.begin() + scriptSigEnd);

    const std::vector<uint8_t> cb2Data(raw.begin() + scriptSigEnd, raw.end());
    return {HexStr(cb1Data), HexStr(cb2Data)};
}

NngRpcErrorCode
NngRpcServer::GetBlock(flatbuffers::FlatBufferBuilder &fbb,
                       const NngInterface::GetBlockRequest *request) {
    LOCK(cs_main);
    NngRpcErrorCode code;
    CBlockIndex *pindex;
    if ((code = GetBlockIndex(*m_node.chainman, request, pindex)) !=
        NngRpcErrorCode::NO_RPC_ERROR) {
        return code;
    }
    CBlock block;
    if (!m_node.chainman->m_blockman.ReadBlock(block, *pindex)) {
        return NngRpcErrorCode::BLOCK_DATA_CORRUPTED;
    }
    fbb.Finish(NngInterface::CreateGetBlockResponse(
        fbb, CreateFbsBlock(m_node.chainman->m_blockman, fbb, block, pindex)));
    return NngRpcErrorCode::NO_RPC_ERROR;
}

NngRpcErrorCode
NngRpcServer::GetBlockRange(flatbuffers::FlatBufferBuilder &fbb,
                            const NngInterface::GetBlockRangeRequest *request) {
    LOCK(cs_main);
    const int32_t chain_height = m_node.chainman->ActiveHeight();
    const int32_t start_height = request->start_height();
    uint32_t num_blocks = request->num_blocks();
    int32_t end_height = start_height + num_blocks - 1;
    if (end_height > chain_height) {
        end_height = chain_height;
        num_blocks = end_height - start_height + 1;
    }

    CBlockIndex *pindex = nullptr;
    if (start_height >= 0) {
        pindex = m_node.chainman->ActiveTip()->GetAncestor(end_height);
    } else {
        num_blocks = 0;
    }
    std::vector<flatbuffers::Offset<NngInterface::Block>> blocks_fbs(
        num_blocks);
    for (auto block_fbs = blocks_fbs.rbegin();
         block_fbs != blocks_fbs.rend() && pindex != nullptr; ++block_fbs) {
        CBlock block;
        if (!m_node.chainman->m_blockman.ReadBlock(block, *pindex)) {
            return NngRpcErrorCode::BLOCK_DATA_CORRUPTED;
        }
        *block_fbs = CreateFbsBlock(m_node.chainman->m_blockman, fbb, block, pindex);
        pindex = pindex->pprev;
    }
    fbb.Finish(NngInterface::CreateGetBlockRangeResponse(
        fbb, fbb.CreateVector(blocks_fbs)));
    return NngRpcErrorCode::NO_RPC_ERROR;
}

NngRpcErrorCode
NngRpcServer::GetBlockSlice(flatbuffers::FlatBufferBuilder &fbb,
                            const NngInterface::GetBlockSliceRequest *request) {
    const FlatFilePos filePos(request->file_num(), request->data_pos());
    AutoFile file{m_node.chainman->m_blockman.OpenBlockFile(filePos, true)};
    std::vector<uint8_t> data(request->num_bytes());
    try {
        file.read(MakeWritableByteSpan(data));
    } catch (const std::exception &e) {
        return NngRpcErrorCode::INVALID_BLOCK_SLICE;
    }
    fbb.Finish(
        NngInterface::CreateGetBlockSliceResponse(fbb, fbb.CreateVector(data)));
    return NngRpcErrorCode::NO_RPC_ERROR;
}

NngRpcErrorCode
NngRpcServer::GetUndoSlice(flatbuffers::FlatBufferBuilder &fbb,
                           const NngInterface::GetUndoSliceRequest *request) {
    const FlatFilePos filePos(request->file_num(), request->undo_pos());
    AutoFile file{m_node.chainman->m_blockman.OpenUndoFile(filePos, true)};
    std::vector<uint8_t> data(request->num_bytes());
    try {
        file.read(MakeWritableByteSpan(data));
    } catch (const std::exception &e) {
        return NngRpcErrorCode::INVALID_BLOCK_SLICE;
    }
    fbb.Finish(
        NngInterface::CreateGetUndoSliceResponse(fbb, fbb.CreateVector(data)));
    return NngRpcErrorCode::NO_RPC_ERROR;
}

NngRpcErrorCode
NngRpcServer::GetMempool(flatbuffers::FlatBufferBuilder &fbb,
                         const NngInterface::GetMempoolRequest *request) {
    LOCK(m_node.mempool->cs);
    std::vector<flatbuffers::Offset<NngInterface::MempoolTx>> txs_fbs;
    for (const auto &entry_ptr : m_node.mempool->mapTx) {
        std::map<COutPoint, Coin> spent_coins_map;
        for (const CTxIn &input : entry_ptr->GetSharedTx()->vin) {
            spent_coins_map[input.prevout] = Coin();
        }
        FindCoins(m_node, spent_coins_map);
        std::vector<Coin> spent_coin;
        spent_coin.reserve(spent_coins_map.size());
        for (const CTxIn &input : entry_ptr->GetSharedTx()->vin) {
            spent_coin.push_back(spent_coins_map[input.prevout]);
        }
        txs_fbs.push_back(NngInterface::CreateMempoolTx(
            fbb, CreateFbsTxMempool(fbb, entry_ptr->GetSharedTx(), spent_coin),
            entry_ptr->GetTime().count()));
    }
    fbb.Finish(
        NngInterface::CreateGetMempoolResponse(fbb, fbb.CreateVector(txs_fbs)));
    return NngRpcErrorCode::NO_RPC_ERROR;
}

NngRpcErrorCode NngRpcServer::GetMiningTemplate(
    flatbuffers::FlatBufferBuilder &fbb,
    const NngInterface::GetMiningTemplateRequest *request) {
    const Config &config = GetConfig();
    const CChainParams &chainparams = config.GetChainParams();
    ChainstateManager &chainman = *m_node.chainman;

    LOCK(cs_main);
    const CBlockIndex *pindexPrev = chainman.ActiveTip();
    if (!pindexPrev) {
        return NngRpcErrorCode::MINING_TEMPLATE_BUILD_FAILED;
    }

    CScript coinbaseScript;
    if (request && request->coinbase_script()) {
        const auto &scriptBytes = *request->coinbase_script();
        const std::vector<uint8_t> scriptVec(scriptBytes.begin(),
                                             scriptBytes.end());
        coinbaseScript = CScript(scriptVec.begin(), scriptVec.end());
    }
    if (coinbaseScript.empty()) {
        // Keep behavior predictable for pure-template callers: this mirrors
        // getblocktemplate's scriptDummy behavior and avoids address parsing
        // policy decisions in the NNG layer.
        coinbaseScript = CScript() << OP_RETURN;
    }

    std::vector<uint8_t> coinbaseIdentity;
    if (request && request->coinbase_identity()) {
        const auto &identityBytes = *request->coinbase_identity();
        coinbaseIdentity.assign(identityBytes.begin(), identityBytes.end());
    }

    std::unique_ptr<node::CBlockTemplate> pblocktemplate;
    try {
        pblocktemplate = node::BlockAssembler{config,
                                              chainman.ActiveChainstate(),
                                              m_node.mempool.get()}
                             .CreateNewBlock(coinbaseScript);
    } catch (const std::exception &e) {
        LogPrintf("NNG mining template build failed: %s\n", e.what());
        return NngRpcErrorCode::MINING_TEMPLATE_BUILD_FAILED;
    }
    if (!pblocktemplate) {
        return NngRpcErrorCode::MINING_TEMPLATE_BUILD_FAILED;
    }

    CBlock *pblock = &pblocktemplate->block;

    const uint32_t en1Size = request ? request->extranonce1_size() : 4;
    const uint32_t en2Size = request ? request->extranonce2_size() : 4;

    if (!coinbaseIdentity.empty()) {
        CMutableTransaction coinbaseTx(*pblock->vtx[0]);
        coinbaseTx.vin[0].scriptSig << coinbaseIdentity;
        pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
        if (!pblocktemplate->entries.empty()) {
            pblocktemplate->entries[0].tx = pblock->vtx[0];
        }
    }

    // The coinbase scriptSig, with the extranonce space reserved, must stay
    // within the consensus limit.
    const uint64_t projectedScriptSigSize =
        uint64_t(pblock->vtx[0]->vin[0].scriptSig.size()) + en1Size + en2Size;
    if (projectedScriptSigSize > MAX_COINBASE_SCRIPTSIG_SIZE) {
        return NngRpcErrorCode::INVALID_MINING_REQUEST;
    }

    node::UpdateTime(pblock, chainparams, pindexPrev,
                     TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()));
    pblock->nNonce = 0;

    auto [cb1, cb2] = SplitCoinbase(*pblock->vtx[0], en1Size, en2Size);

    // Compute the merkle branches from the coinbase the stratum coordinator
    // reconstructs: coinbase1 || extranonce1 || extranonce2 || coinbase2.
    // The extranonce bytes are placeholders: the branches do not depend on
    // the coinbase.
    std::vector<uint256> merkleBranches;
    {
        std::vector<uint8_t> reconstructedRaw = ParseHex(cb1);
        reconstructedRaw.insert(reconstructedRaw.end(), en1Size + en2Size,
                                0x00);
        const std::vector<uint8_t> cb2Raw = ParseHex(cb2);
        reconstructedRaw.insert(reconstructedRaw.end(), cb2Raw.begin(),
                                cb2Raw.end());

        DataStream reconstructedSs{MakeByteSpan(reconstructedRaw)};
        CBlock tempBlock = *pblock;
        tempBlock.vtx[0] =
            MakeTransactionRef(CTransaction(deserialize, reconstructedSs));
        merkleBranches = ComputeMerkleBranches(tempBlock);
    }

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    DataStream blockStream{};
    blockStream << *pblock;
    DataStream headerStream{};
    headerStream << pblock->GetBlockHeader();
    DataStream coinbaseStream{};
    coinbaseStream << *pblock->vtx[0];

    Amount coinbaseValue = Amount::zero();
    for (const auto &out : pblock->vtx[0]->vout) {
        coinbaseValue += out.nValue;
    }

    std::vector<flatbuffers::Offset<flatbuffers::String>> branchesFbs;
    for (const auto &branch : merkleBranches) {
        branchesFbs.push_back(fbb.CreateString(branch.GetHex()));
    }

    std::vector<flatbuffers::Offset<NngInterface::MiningTemplateTx>> txsFbs;
    const bool includeTxs = request ? request->include_transactions() : true;
    if (includeTxs) {
        for (size_t i = 1; i < pblock->vtx.size(); ++i) {
            DataStream txStream{};
            txStream << *pblock->vtx[i];
            Amount fee = Amount::zero();
            int64_t sigChecks = 0;
            if (i < pblocktemplate->entries.size()) {
                fee = pblocktemplate->entries[i].fees;
                sigChecks = pblocktemplate->entries[i].sigChecks;
            }
            txsFbs.push_back(NngInterface::CreateMiningTemplateTx(
                fbb,
                fbb.CreateVector(UCharCast(txStream.data()), txStream.size()),
                CreateFbsTxId(fbb, pblock->vtx[i]->GetId()), fee / SATOSHI,
                sigChecks));
        }
    }

    static std::atomic<uint64_t> s_templateId{1};
    const uint64_t templateId = s_templateId.fetch_add(1);

    arith_uint256 targetArith;
    targetArith.SetCompact(pblock->nBits);
    const uint256 targetU256 = ArithToUint256(targetArith);
    NngInterface::Hash targetHash = CreateFbsHash(targetU256.begin());

    const uint64_t mintime = pindexPrev->GetMedianTimePast() + 1;
    const uint64_t maxtime =
        TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) +
        MAX_FUTURE_BLOCK_TIME;

    auto response = NngInterface::CreateGetMiningTemplateResponse(
        fbb, templateId,
        fbb.CreateVector(UCharCast(blockStream.data()), blockStream.size()),
        fbb.CreateVector(UCharCast(headerStream.data()), headerStream.size()),
        CreateFbsBlockHash(fbb, pblock->hashPrevBlock), pindexPrev->nHeight + 1,
        pblock->nHeaderVersion, pblock->nBits, &targetHash,
        pblock->GetBlockTime(), mintime, maxtime, coinbaseValue / SATOSHI,
        fbb.CreateVector(UCharCast(coinbaseStream.data()),
                         coinbaseStream.size()),
        fbb.CreateVector(txsFbs), fbb.CreateString(cb1), fbb.CreateString(cb2),
        fbb.CreateVector(branchesFbs),
        fbb.CreateString(HashToStratumHex(pblock->hashPrevBlock)),
        fbb.CreateString(Uint32ToStratumHex(pblock->nBits)),
        fbb.CreateString(HexStr(pblock->vTime)));
    fbb.Finish(response);
    return NngRpcErrorCode::NO_RPC_ERROR;
}

class NngPubServer final : public CValidationInterface {
public:
    NngPubServer(const NodeContext &node, std::set<std::string> enabled_messages)
        : m_node(node), m_enabled_messages(enabled_messages) {}

    bool Listen(const std::string &pub_url) {
        NNG_TRY_ERROR(nng_pub0_open(&m_sock),
                      "Failed opening NNG pub0 socket: %s");
        std::string listen_failure_msg =
            strprintf("Failed listening on -nngpub=%s: %%s", pub_url);
        NNG_TRY_ERROR(nng_listen(m_sock, pub_url.c_str(), NULL, 0),
                      listen_failure_msg.c_str());
        LogPrintf("NNG interface: pubsub server listening at %s\n", pub_url);
        m_node.validation_signals->RegisterValidationInterface(this);
        return true;
    }

    void Shutdown() { NngCloseSocket(m_sock); }

private:
    const NodeContext &m_node;
    nng_socket m_sock;
    std::set<std::string> m_enabled_messages;
    // Monotonic process-local epoch used by miningwrkchg.
    std::atomic<uint64_t> m_templateEpoch{1};

    void BroadcastMessage(const std::string msg_type,
                          const flatbuffers::FlatBufferBuilder &fbb) {
        std::vector<uint8_t> msg;
        msg.resize(12 + fbb.GetSize());
        memcpy(msg.data(), msg_type.data(), msg_type.size());
        memcpy(msg.data() + 12, fbb.GetBufferPointer(), fbb.GetSize());
        NNG_TRY_LOG(nng_send(m_sock, msg.data(), msg.size(), 0));
    }

    void EmitMiningWorkChanged(NngInterface::MiningWorkChangeReason reason,
                               const CBlockIndex *tip) {
        if (!IsMessageEnabled(MSG_MININGWRKCHG) || tip == nullptr) {
            return;
        }
        // This signal is intentionally small and constant-shape to keep event
        // latency low for external stratum coordinators that refresh jobs on
        // every tip/mempool invalidation.
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateMiningWorkChanged(
            fbb, reason, CreateFbsBlockHash(fbb, tip->GetBlockHash()),
            tip->nHeight, GetTime(), m_templateEpoch.fetch_add(1)));
        BroadcastMessage(MSG_MININGWRKCHG, fbb);
    }

    void EmitMempoolWorkChanged() {
        if (!IsMessageEnabled(MSG_MININGWRKCHG)) {
            return;
        }
        const CBlockIndex *tip =
            WITH_LOCK(cs_main, return m_node.chainman->ActiveTip());
        EmitMiningWorkChanged(
            NngInterface::MiningWorkChangeReason_MEMPOOL_REFRESH, tip);
    }

    void UpdatedBlockTip(const CBlockIndex *pindexNew,
                         const CBlockIndex *pindexFork,
                         bool fInitialDownload) override {
        if (IsMessageEnabled(MSG_UPDATEBLKTIP)) {
            flatbuffers::FlatBufferBuilder fbb;
            fbb.Finish(NngInterface::CreateUpdatedBlockTip(
                fbb, CreateFbsBlockHash(fbb, pindexNew->GetBlockHash())));
            BroadcastMessage(MSG_UPDATEBLKTIP, fbb);
        }
        const bool reorg = pindexFork != nullptr && pindexNew != nullptr &&
                           pindexNew->pprev != pindexFork;
        EmitMiningWorkChanged(
            reorg ? NngInterface::MiningWorkChangeReason_REORG
                  : NngInterface::MiningWorkChangeReason_NEW_TIP,
            pindexNew);
    }

    void
    TransactionAddedToMempool(const CTransactionRef &ptx,
                              std::shared_ptr<const std::vector<Coin>> spent_coins,
                              uint64_t mempool_sequence) override {
        if (IsMessageEnabled(MSG_MEMPOOLTXADD)) {
            flatbuffers::FlatBufferBuilder fbb;
            fbb.Finish(NngInterface::CreateTransactionAddedToMempool(
                fbb, NngInterface::CreateMempoolTx(
                         fbb, CreateFbsTxMempool(fbb, ptx, *spent_coins),
                         GetTime())));
            BroadcastMessage(MSG_MEMPOOLTXADD, fbb);
        }
        EmitMempoolWorkChanged();
    }

    void TransactionRemovedFromMempool(const CTransactionRef &ptx,
                                       MemPoolRemovalReason reason,
                                       uint64_t mempool_sequence) override {
        if (IsMessageEnabled(MSG_MEMPOOLTXREM)) {
            flatbuffers::FlatBufferBuilder fbb;
            fbb.Finish(NngInterface::CreateTransactionRemovedFromMempool(
                fbb, CreateFbsTxId(fbb, ptx->GetId())));
            BroadcastMessage(MSG_MEMPOOLTXREM, fbb);
        }
        EmitMempoolWorkChanged();
    }

    void BlockConnected(ChainstateRole role,
                        const std::shared_ptr<const CBlock> &block,
                        const CBlockIndex *pindex) override {
        if (!IsMessageEnabled(MSG_BLKCONNECTED)) {
            return;
        }
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateBlockConnected(
            fbb, CreateFbsBlock(m_node.chainman->m_blockman, fbb, *block, pindex), /*txs_conflicted=*/0));
        BroadcastMessage(MSG_BLKCONNECTED, fbb);
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock> &block,
                           const CBlockIndex *pindex) override {
        if (!IsMessageEnabled(MSG_BLKDISCONCTD)) {
            return;
        }
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateBlockDisconnected(
            fbb, CreateFbsBlock(m_node.chainman->m_blockman, fbb, *block, pindex)));
        BroadcastMessage(MSG_BLKDISCONCTD, fbb);
    }

    void ChainStateFlushed(ChainstateRole role, const CBlockLocator &locator) override {
        if (!IsMessageEnabled(MSG_CHAINSTFLUSH)) {
            return;
        }
        if (locator.vHave.size() == 0) {
            return;
        }
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateChainStateFlushed(
            fbb, CreateFbsBlockHash(fbb, locator.vHave[0])));
        BroadcastMessage(MSG_CHAINSTFLUSH, fbb);
    }

    bool IsMessageEnabled(const std::string &msg) {
        return m_enabled_messages.find(msg) != m_enabled_messages.end();
    }
};

std::unique_ptr<NngRpcServer> g_rpc_server;
std::unique_ptr<NngPubServer> g_pub_server;

bool RunRpcServer(const NodeContext &node, const Consensus::Params &consensus) {
    if (gArgs.IsArgSet("-nngrpc")) {
        std::string rpc_url = gArgs.GetArg("-nngrpc", "");
        g_rpc_server = std::make_unique<NngRpcServer>(consensus, node);
        if (!g_rpc_server->Listen(rpc_url)) {
            return false;
        }
    } else {
        g_rpc_server = nullptr;
    }
    return true;
}

bool RunPubServer(const NodeContext &node) {
    if (gArgs.IsArgSet("-nngpub")) {
        std::string pub_url = gArgs.GetArg("-nngpub", "");
        std::vector<std::string> vEnabledMessages = gArgs.GetArgs("-nngpubmsg");
        std::set<std::string> enabled_messages(vEnabledMessages.begin(),
                                               vEnabledMessages.end());
        for (const std::string &enabled_message : enabled_messages) {
            if (std::find(AVAILABLE_PUB_MESSAGES.begin(),
                          AVAILABLE_PUB_MESSAGES.end(),
                          enabled_message) == AVAILABLE_PUB_MESSAGES.end()) {
                return InitError(
                    strprintf(_("Invalid message type '%s' in -nngpubmsg."),
                              enabled_message));
            }
        }
        if (enabled_messages.empty()) {
            LogPrintf("Warning: Specified -nngpub, but no -nngpubmsg "
                      "enabled.\n");
        }
        g_pub_server = std::make_unique<NngPubServer>(node, enabled_messages);
        if (!g_pub_server->Listen(pub_url)) {
            return false;
        }
    } else {
        g_pub_server = nullptr;
    }
    return true;
}

bool StartNngInterface(const NodeContext &node,
                       const Consensus::Params &consensus) {
#if NNG_MAJOR_VERSION >= 2
    // NNG 2 has an explicit library initializer; run it before any socket
    // is opened.
    if (const nng_err rv = nng_init(nullptr); rv != 0) {
        return InitError(strprintf(_("Failed initializing NNG: %s"),
                                   NngErrorString(rv)));
    }
#endif
    if (!RunRpcServer(node, consensus)) {
        return false;
    }
    if (!RunPubServer(node)) {
        return false;
    }
    return true;
}

void StopNngInterface() {
    if (g_rpc_server) {
        g_rpc_server->Shutdown();
    }
    if (g_pub_server) {
        g_pub_server->Shutdown();
    }
}
