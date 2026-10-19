// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hosts/abc/abc_v2.h>

#include <ext/lotus_v2/db/model.h>
#include <ext/lotus_v2/service/service.h>

#include <blockindex.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <sync.h>
#include <validation.h>
#include <chainparams.h>
#include <lotus_v2/chronik_explorer.h>
#include <lotus_v2/header.h>
#include <lotus_v2/output.h>
#include <lotus_v2/tagged_hash.h>
#include <lotus_v2/transaction.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <tinyformat.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>

namespace chronik::native::abc {

namespace ffi = lotus_v2::ffi;

namespace {

ffi::Bytes32 HashArray(const uint256 &hash) {
    ffi::Bytes32 out;
    std::copy_n(hash.begin(), 32, out.begin());
    return out;
}

ffi::WireRange Range(const lotus::v2::ChronikWireRange &r) {
    return ffi::WireRange{.offset = r.offset, .length = r.length};
}

/** The Rust bridge's normalization of the coinbase tx. */
void NormalizeCoinbase(lotus::v2::Transaction &v2tx) {
    v2tx.lock = 0;
    if (v2tx.inputs.size() != 1) {
        v2tx.inputs.resize(1);
    }
    auto &cb_in = v2tx.inputs[0];
    cb_in.prev_txid.fill(0);
    cb_in.prev_index = std::numeric_limits<uint32_t>::max();
    cb_in.sequence = std::numeric_limits<uint32_t>::max();
    cb_in.flags = 2;
    cb_in.path_index = 0;
    cb_in.witnesses.clear();
    if (cb_in.coinbase_data.size() > 8192) {
        cb_in.coinbase_data.resize(8192);
    }
    if (cb_in.has_coinbase_data && cb_in.coinbase_data.empty()) {
        cb_in.has_coinbase_data = false;
    } else if (!cb_in.has_coinbase_data) {
        cb_in.coinbase_data.clear();
    }
    for (auto &out : v2tx.outputs) {
        out.flags &= static_cast<uint8_t>(~1U);
        out.token_id.fill(0);
    }
}

/** The Rust bridge's normalization of the inputs of a non-coinbase tx. */
void NormalizeInputs(lotus::v2::Transaction &v2tx) {
    for (auto &in : v2tx.inputs) {
        in.has_coinbase_data = false;
        in.coinbase_data.clear();
        if (in.flags != 1 && in.flags != 3) {
            in.flags = 1;
        }
        if (in.flags == 1) {
            if (in.path_index >= lotus::v2::MAX_OUTPUT_PATHS) {
                in.path_index = 0;
            }
            if (in.sequence != std::numeric_limits<uint32_t>::max() &&
                (in.sequence & ~0x40ffffU) != 0) {
                in.sequence = std::numeric_limits<uint32_t>::max();
            }
            if (in.witnesses.empty()) {
                lotus::v2::BranchWitness w;
                w.script = {0x4e};
                in.witnesses.push_back(std::move(w));
            } else if (in.witnesses.size() > lotus::v2::MAX_OUTPUT_BRANCHES) {
                in.witnesses.resize(lotus::v2::MAX_OUTPUT_BRANCHES);
            }
        }
        for (auto &w : in.witnesses) {
            if (w.script.size() > lotus::v2::DefaultTxProfile.max_script_bytes) {
                w.script.resize(lotus::v2::DefaultTxProfile.max_script_bytes);
            }
        }
    }
}

} // namespace

ffi::Binding GetV2Binding() {
    const ffi::Bytes32 genesis = HashArray(Params().GenesisBlock().GetHash());
    return ffi::Binding{
        .chain_id = GetActiveV2ChainId(),
        .genesis = genesis,
        .profile =
            lotus::v2::TaggedHash(lotus::v2::HashDomain::HeaderBody, genesis),
    };
}

ffi::NativeBlock ConvertV2NativeBlock(const CBlock &block,
                                      const CBlockIndex &bindex) {
    if (bindex.nHeight < 0) {
        throw std::runtime_error("Block height cannot be negative");
    }
    const uint64_t height = static_cast<uint64_t>(bindex.nHeight);
    ffi::NativeBlock out;
    out.anchor = ffi::Anchor{.block_id = HashArray(bindex.GetBlockHash()),
                             .height = height};
    out.parent =
        height == 0
            ? out.anchor
            : ffi::Anchor{.block_id = HashArray(bindex.pprev
                                                    ? bindex.pprev->GetBlockHash()
                                                    : ::BlockHash()),
                          .height = height - 1};

    std::array<uint8_t, lotus::v2::HEADER_SIZE> header_wire{};
    lotus::v2::SerializeHeader(block.GetBlockHeader().ToV2Header(),
                               header_wire);
    if (height == 0) {
        std::fill_n(header_wire.begin(), 32, uint8_t{0});
    } else {
        std::copy_n(out.parent.block_id.begin(), 32, header_wire.begin());
    }
    for (size_t i = 0; i < 8; ++i) {
        header_wire[62 + i] = static_cast<uint8_t>((height >> (8 * i)) & 0xffU);
    }
    static_assert(lotus::v2::HEADER_SIZE == std::tuple_size_v<
                                                decltype(out.header_wire)>);
    out.header_wire = header_wire;

    out.transactions.reserve(block.vtx.size());
    for (size_t n = 0; n < block.vtx.size(); ++n) {
        const CTransaction &ctx = *block.vtx[n];
        lotus::v2::Transaction v2tx = ctx.ToV2Transaction();
        if (n == 0) {
            NormalizeCoinbase(v2tx);
        } else {
            NormalizeInputs(v2tx);
        }

        std::vector<uint8_t> tx_wire;
        std::string err;
        if (!lotus::v2::EncodeTransaction(v2tx, lotus::v2::DefaultTxProfile,
                                          tx_wire, err)) {
            throw std::runtime_error("V2 EncodeTransaction failed: " + err);
        }
        std::vector<uint8_t> fact_wire;
        std::vector<lotus::v2::ChronikFullInput> fact_inputs;
        if (!lotus::v2::MakeChronikExplorerFacts(
                v2tx, lotus::v2::DefaultTxProfile,
                std::span<const uint8_t>(tx_wire.data(), tx_wire.size()),
                fact_wire, fact_inputs, err)) {
            throw std::runtime_error("MakeChronikExplorerFacts failed: " + err);
        }

        ffi::NativeTx tx;
        tx.txid = HashArray(ctx.GetId());
        tx.txhash = HashArray(ctx.GetHash());
        tx.index = static_cast<uint32_t>(n);
        tx.full_inputs.reserve(fact_inputs.size());
        for (size_t i = 0; i < fact_inputs.size(); ++i) {
            const auto &fi = fact_inputs[i];
            if (fi.flags == 1) {
                tx.inputs.push_back(ffi::Input{
                    .txid = fi.prev_txid,
                    .out_idx = fi.prev_index,
                    .input_index = static_cast<uint32_t>(i),
                });
            }
            ffi::NativeFullInput full;
            full.prev_txid = fi.prev_txid;
            full.prev_index = fi.prev_index;
            full.sequence = fi.sequence;
            full.flags = fi.flags;
            full.path_index = fi.path_index;
            full.has_coinbase_data = fi.has_coinbase_data;
            full.coinbase_data = Range(fi.coinbase_data);
            full.witnesses.reserve(fi.witnesses.size());
            for (const auto &w : fi.witnesses) {
                full.witnesses.push_back(ffi::NativeWitness{
                    .script = Range(w.script),
                    .siblings_table = Range(w.siblings_table),
                    .siblings_count = w.siblings_count,
                    .arguments_table = Range(w.arguments_table),
                    .arguments_count = w.arguments_count,
                });
            }
            tx.full_inputs.push_back(std::move(full));
        }
        tx.outputs.reserve(v2tx.outputs.size());
        for (const auto &output : v2tx.outputs) {
            std::vector<uint8_t> out_wire;
            if (!lotus::v2::EncodeOutput(output, out_wire, err)) {
                throw std::runtime_error("V2 EncodeOutput failed: " + err);
            }
            tx.outputs.push_back(ffi::NativeOutput{.wire = std::move(out_wire)});
        }
        tx.wire = std::move(fact_wire);
        tx.lock = v2tx.lock;
        out.transactions.push_back(std::move(tx));
    }
    return out;
}

// ---- AbcV2ServiceExtension ----

namespace {

/** bridge.rs v2_limits */
ffi::ServiceLimits V2Limits() {
    return ffi::ServiceLimits{
        .block_bytes = uint32_t(lotus_v2::MAX_BATCH_BYTES),
        .transactions = uint32_t(lotus_v2::MAX_TRANSACTIONS),
        .changes = uint32_t(lotus_v2::MAX_CHANGES),
        .roots = 256,
        .clauses = 16,
        .page_size = 1000,
        .posting_reads = 65536,
        .work = 131072,
        .response_bytes = 1024 * 1024,
    };
}

} // namespace

AbcV2ServiceExtension::AbcV2ServiceExtension(const node::NodeContext &node,
                                             const Host &host)
    : m_node(node), m_host(host) {}

AbcV2ServiceExtension::~AbcV2ServiceExtension() = default;

void AbcV2ServiceExtension::Log(const std::string &msg) const {
    m_host.Log(LogLevel::Debug, msg);
}

void AbcV2ServiceExtension::Open(const std::filesystem::path &indexes_dir,
                                 bool wipe) {
    // Rust: <datadir_net>/indexes/chronik/v2_index, whatever the legacy
    // env's backend.
    const std::filesystem::path path = indexes_dir / "chronik" / "v2_index";
    // An env is opened once per process: release any previous service first.
    m_service.reset();
    std::error_code ec;
    const bool fresh = wipe || !std::filesystem::is_regular_file(
                                   path / "mdbx.dat", ec);
    if (fresh && std::filesystem::exists(path, ec)) {
        std::filesystem::remove_all(path, ec);
    }
    // Rust nests it in the legacy env's directory, which always exists there.
    std::filesystem::create_directories(path.parent_path(), ec);
    const ffi::Binding binding = GetV2Binding();
    auto sha256 = [this](ByteView data, uint8_t out[32]) {
        m_host.Sha256(data, out);
    };
    try {
        m_service = lotus_v2::V2Service::Open(path.string(), binding, fresh,
                                              V2Limits(), sha256);
    } catch (const std::exception &) {
        std::filesystem::remove_all(path, ec);
        try {
            m_service = lotus_v2::V2Service::Open(path.string(), binding, true,
                                                  V2Limits(), sha256);
        } catch (const std::exception &e) {
            throw ChronikError(std::string("V2Service open failed: ") +
                               e.what());
        }
    }
}

void AbcV2ServiceExtension::Resync() {
    lotus_v2::V2Service &v2 = *m_service;
    ChainstateManager &chainman = *m_node.chainman;
    const CBlockIndex *tip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    if (!tip || tip->nHeight < 0) {
        return;
    }
    const auto active_at = [&](uint64_t height) -> const CBlockIndex * {
        LOCK(chainman.GetMutex());
        if (height > uint64_t(std::numeric_limits<int>::max())) {
            return nullptr;
        }
        return chainman.ActiveChain()[int(height)];
    };
    try {
        while (const std::optional<ffi::Anchor> cp = v2.Checkpoint()) {
            if (cp->height <= uint64_t(tip->nHeight)) {
                const CBlockIndex *bindex = active_at(cp->height);
                if (bindex && HashArray(bindex->GetBlockHash()) ==
                                  cp->block_id) {
                    break;
                }
            }
            try {
                v2.DisconnectBlock(*cp);
            } catch (const std::exception &) {
                break;
            }
        }
    } catch (const std::exception &) {
        return;
    }
    int start_height = 0;
    try {
        if (const auto cp = v2.Checkpoint()) {
            start_height = int(cp->height) + 1;
        }
    } catch (const std::exception &) {
        return;
    }
    for (int h = start_height; h <= tip->nHeight; ++h) {
        if (m_host.ShutdownRequested()) {
            return;
        }
        const CBlockIndex *bindex = active_at(uint64_t(h));
        if (!bindex) {
            break;
        }
        CBlock block;
        if (!chainman.m_blockman.ReadBlock(block, *bindex)) {
            break;
        }
        try {
            ffi::NativeBlock native = ConvertV2NativeBlock(block, *bindex);
            if (h == 0) {
                v2.InitializeGenesis(native);
            } else {
                v2.ConnectBlock(native);
            }
        } catch (const std::exception &e) {
            Log(strprintf("Chronik V2 resync skipped at height %d: %s\n", h,
                          e.what()));
            break;
        }
    }
    try {
        if (const auto cp = v2.Checkpoint()) {
            v2.PublishAuthority(*cp);
        }
    } catch (const std::exception &) {
    }
}

void AbcV2ServiceExtension::Connect(const Block &block, WriteTxn *) {
    const CBlockIndex *bindex = WITH_LOCK(
        m_node.chainman->GetMutex(),
        return m_node.chainman->m_blockman.LookupBlockIndex(
            ::BlockHash(uint256(std::span<const uint8_t>(block.info.hash.b)))));
    if (!bindex) {
        return;
    }
    CBlock cblock;
    if (!m_node.chainman->m_blockman.ReadBlock(cblock, *bindex)) {
        return;
    }
    ffi::NativeBlock native;
    try {
        native = ConvertV2NativeBlock(cblock, *bindex);
    } catch (const std::exception &) {
        // Rust: `if let Ok(native_block) = bridge_v2_native_block(..)`
        return;
    }
    try {
        if (native.anchor.height == 0) {
            m_service->InitializeGenesis(native);
        } else {
            m_service->ConnectBlock(native);
        }
        try {
            m_service->PublishAuthority(native.anchor);
        } catch (const std::exception &) {
        }
    } catch (const std::exception &e) {
        Log(std::string("Chronik V2 connect_block skipped: ") + e.what() +
            "\n");
    }
}

void AbcV2ServiceExtension::Disconnect(const Block &block, WriteTxn *) {
    if (block.info.height < 0) {
        return;
    }
    const ffi::Anchor expected{.block_id = block.info.hash.b,
                               .height = uint64_t(block.info.height)};
    try {
        m_service->DisconnectBlock(expected);
        if (const auto cp = m_service->Checkpoint()) {
            m_service->PublishAuthority(*cp);
        }
    } catch (const std::exception &) {
    }
}

void AbcV2ServiceExtension::Close() { m_service.reset(); }

} // namespace chronik::native::abc
