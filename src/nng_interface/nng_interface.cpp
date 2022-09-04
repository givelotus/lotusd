// Copyright (c) 2021 The Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <array>
#include <optional>

#include <blockdb.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <logging.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/ui_interface.h>
#include <timedata.h>
#include <undo.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <nng/nng.h>
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/reqrep0/rep.h>

#include "nng_interface_generated.h"
#include <nng_interface/nng_interface.h>

enum class NngRpcWorkerState {
    UNINIT,
    RECV,
    SEND,
    CLOSED,
};

class NngRpcServer;

#define NNG_TRY_LOG(call)                                                      \
    do {                                                                       \
        int rv = (call);                                                       \
        if (rv != 0) {                                                         \
            LogPrintf("NNG Error: %s (at %s:%d: %s)\n", nng_strerror(rv),      \
                      __FILE__, __LINE__, #call);                              \
            return;                                                            \
        }                                                                      \
    } while (false)

#define NNG_TRY_ERROR(call, format_str)                                        \
    do {                                                                       \
        int rv = (call);                                                       \
        if (rv != 0) {                                                         \
            return InitError(strprintf(_(format_str), nng_strerror(rv)));      \
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
    const Consensus::Params &m_consensus;
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

public:
    NngRpcServer(const Consensus::Params &consensus, const NodeContext &node)
        : m_consensus(consensus), m_node(node) {}

    NngRpcErrorCode HandleMsg(flatbuffers::FlatBufferBuilder &builder,
                              nng_msg *incoming_msg);
    bool Listen(const std::string &rpc_url);
    void Shutdown() {
        for (NngRpcWorker &worker : m_workers) {
            worker.Shutdown();
        }
        nng_close(m_sock);
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
        default:
            return NngRpcErrorCode::UNKNOWN_RPC_METHOD;
    }
}

template <typename T>
NngRpcErrorCode GetBlockIndex(const T *request, CBlockIndex *&block_index) {
    switch (request->block_id_type()) {
        case NngInterface::BlockIdentifier_Height: {
            int32_t height = request->block_id_as_Height()->height();
            block_index = ::ChainActive().Tip()->GetAncestor(height);
            break;
        }
        case NngInterface::BlockIdentifier_Hash: {
            const NngInterface::Hash *hash =
                request->block_id_as_Hash()->hash();
            const std::vector<uint8_t> blockhash(hash->data()->begin(),
                                                 hash->data()->end());
            LOCK(cs_main);
            block_index = LookupBlockIndex(BlockHash(uint256(blockhash)));
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
    CDataStream raw_header(SER_NETWORK, PROTOCOL_VERSION);
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
            GetSerializeSize(Using<TxInUndoFormatter>(coin), PROTOCOL_VERSION);
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
    CDataStream tx_ser(SER_NETWORK, PROTOCOL_VERSION);
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
    CDataStream tx_ser(SER_NETWORK, PROTOCOL_VERSION);
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
           ::GetSerializeSize(block.vMetadata, CLIENT_VERSION) +
           GetSizeOfCompactSize(block.vtx.size());
}

size_t GetFirstUndoOffset(const CBlock &block, const CBlockIndex *pindex) {
    return pindex->nUndoPos + GetSizeOfCompactSize(block.vtx.size() - 1);
}

flatbuffers::Offset<NngInterface::Block>
CreateFbsBlock(flatbuffers::FlatBufferBuilder &fbb, const CBlock &block,
               const CBlockIndex *pindex) {
    size_t nDataPos = GetFirstBlockTxOffset(block, pindex);
    size_t nUndoPos = 0;
    CBlockUndo block_undo;
    if (pindex->nHeight) { // Genesis block doesn't have undo data
        nUndoPos = GetFirstUndoOffset(block, pindex);
        if (!UndoReadFromDisk(block_undo, pindex)) {
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

NngRpcErrorCode
NngRpcServer::GetBlock(flatbuffers::FlatBufferBuilder &fbb,
                       const NngInterface::GetBlockRequest *request) {
    LOCK(cs_main);
    NngRpcErrorCode code;
    CBlockIndex *pindex;
    if ((code = GetBlockIndex(request, pindex)) !=
        NngRpcErrorCode::NO_RPC_ERROR) {
        return code;
    }
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, m_consensus)) {
        return NngRpcErrorCode::BLOCK_DATA_CORRUPTED;
    }
    fbb.Finish(NngInterface::CreateGetBlockResponse(
        fbb, CreateFbsBlock(fbb, block, pindex)));
    return NngRpcErrorCode::NO_RPC_ERROR;
}

NngRpcErrorCode
NngRpcServer::GetBlockRange(flatbuffers::FlatBufferBuilder &fbb,
                            const NngInterface::GetBlockRangeRequest *request) {
    LOCK(cs_main);
    const int32_t chain_height = ::ChainActive().Height();
    const int32_t start_height = request->start_height();
    uint32_t num_blocks = request->num_blocks();
    int32_t end_height = start_height + num_blocks - 1;
    if (end_height > chain_height) {
        end_height = chain_height;
        num_blocks = end_height - start_height + 1;
    }

    CBlockIndex *pindex = nullptr;
    if (start_height >= 0) {
        pindex = ::ChainActive().Tip()->GetAncestor(end_height);
    } else {
        num_blocks = 0;
    }
    std::vector<flatbuffers::Offset<NngInterface::Block>> blocks_fbs(
        num_blocks);
    for (auto block_fbs = blocks_fbs.rbegin();
         block_fbs != blocks_fbs.rend() && pindex != nullptr; ++block_fbs) {
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex, m_consensus)) {
            return NngRpcErrorCode::BLOCK_DATA_CORRUPTED;
        }
        *block_fbs = CreateFbsBlock(fbb, block, pindex);
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
    CAutoFile file(OpenBlockFile(filePos, true), SER_DISK, CLIENT_VERSION);
    std::vector<uint8_t> data(request->num_bytes());
    try {
        file.read((char *)data.data(), request->num_bytes());
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
    CAutoFile file(OpenUndoFile(filePos, true), SER_DISK, CLIENT_VERSION);
    std::vector<uint8_t> data(request->num_bytes());
    try {
        file.read((char *)data.data(), request->num_bytes());
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
    for (const CTxMemPoolEntry &entry : m_node.mempool->mapTx) {
        std::map<COutPoint, Coin> spent_coins_map;
        for (const CTxIn &input : entry.GetSharedTx()->vin) {
            spent_coins_map[input.prevout] = Coin();
        }
        FindCoins(m_node, spent_coins_map);
        std::vector<Coin> spent_coin;
        spent_coin.reserve(spent_coins_map.size());
        for (const CTxIn &input : entry.GetSharedTx()->vin) {
            spent_coin.push_back(spent_coins_map[input.prevout]);
        }
        txs_fbs.push_back(NngInterface::CreateMempoolTx(
            fbb, CreateFbsTxMempool(fbb, entry.GetSharedTx(), spent_coin),
            entry.GetTime().count()));
    }
    fbb.Finish(
        NngInterface::CreateGetMempoolResponse(fbb, fbb.CreateVector(txs_fbs)));
    return NngRpcErrorCode::NO_RPC_ERROR;
}

class NngPubServer final : public CValidationInterface {
public:
    NngPubServer(std::set<std::string> enabled_messages)
        : m_enabled_messages(enabled_messages) {}

    bool Listen(const std::string &pub_url) {
        NNG_TRY_ERROR(nng_pub0_open(&m_sock),
                      "Failed opening NNG pub0 socket: %s");
        std::string listen_failure_msg =
            strprintf("Failed listening on -nngpub=%s: %%s", pub_url);
        NNG_TRY_ERROR(nng_listen(m_sock, pub_url.c_str(), NULL, 0),
                      listen_failure_msg.c_str());
        LogPrintf("NNG interface: pubsub server listening at %s\n", pub_url);
        RegisterValidationInterface(this);
        return true;
    }

    void Shutdown() { nng_close(m_sock); }

private:
    nng_socket m_sock;
    std::set<std::string> m_enabled_messages;

    void BroadcastMessage(const std::string msg_type,
                          const flatbuffers::FlatBufferBuilder &fbb) {
        std::vector<uint8_t> msg;
        msg.resize(12 + fbb.GetSize());
        memcpy(msg.data(), msg_type.data(), msg_type.size());
        memcpy(msg.data() + 12, fbb.GetBufferPointer(), fbb.GetSize());
        NNG_TRY_LOG(nng_send(m_sock, msg.data(), msg.size(), 0));
    }

    void UpdatedBlockTip(const CBlockIndex *pindexNew,
                         const CBlockIndex *pindexFork,
                         bool fInitialDownload) override {
        if (!IsMessageEnabled(MSG_UPDATEBLKTIP)) {
            return;
        }
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateUpdatedBlockTip(
            fbb, CreateFbsBlockHash(fbb, pindexNew->GetBlockHash())));
        BroadcastMessage(MSG_UPDATEBLKTIP, fbb);
    }

    void
    TransactionAddedToMempool(const CTransactionRef &ptx,
                              const std::vector<Coin> &spent_coins,
                              uint64_t mempool_sequence) override {
        if (!IsMessageEnabled(MSG_MEMPOOLTXADD)) {
            return;
        }
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateTransactionAddedToMempool(
            fbb, NngInterface::CreateMempoolTx(
                     fbb, CreateFbsTxMempool(fbb, ptx, spent_coins),
                     GetAdjustedTime())));
        BroadcastMessage(MSG_MEMPOOLTXADD, fbb);
    }

    void TransactionRemovedFromMempool(const CTransactionRef &ptx,
                                       MemPoolRemovalReason reason,
                                       uint64_t mempool_sequence) override {
        if (!IsMessageEnabled(MSG_MEMPOOLTXREM)) {
            return;
        }
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateTransactionRemovedFromMempool(
            fbb, CreateFbsTxId(fbb, ptx->GetId())));
        BroadcastMessage(MSG_MEMPOOLTXREM, fbb);
    }

    void BlockConnected(const std::shared_ptr<const CBlock> &block,
                        const CBlockIndex *pindex) override {
        if (!IsMessageEnabled(MSG_BLKCONNECTED)) {
            return;
        }
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateBlockConnected(
            fbb, CreateFbsBlock(fbb, *block, pindex), /*txs_conflicted=*/0));
        BroadcastMessage(MSG_BLKCONNECTED, fbb);
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock> &block,
                           const CBlockIndex *pindex) override {
        if (!IsMessageEnabled(MSG_BLKDISCONCTD)) {
            return;
        }
        flatbuffers::FlatBufferBuilder fbb;
        fbb.Finish(NngInterface::CreateBlockDisconnected(
            fbb, CreateFbsBlock(fbb, *block, pindex)));
        BroadcastMessage(MSG_BLKDISCONCTD, fbb);
    }

    void ChainStateFlushed(const CBlockLocator &locator) override {
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

bool RunPubServer() {
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
        g_pub_server = std::make_unique<NngPubServer>(enabled_messages);
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
    if (!RunRpcServer(node, consensus)) {
        return false;
    }
    if (!RunPubServer()) {
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
