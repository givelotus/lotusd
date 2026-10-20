// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/service/service.h>

#include <map>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <optional>
#include <random>

#include <sys/stat.h>

namespace chronik::native::lotus_v2 {

namespace qb = query_branches;

namespace {

[[noreturn]] void Fail(const std::string &msg) { throw V2ServiceError(msg); }

/** e.to_string() of a DB failure. */
template <typename F> auto Db(F &&f) -> decltype(f()) {
    try {
        return f();
    } catch (const V2ServiceError &) {
        throw;
    } catch (const ChronikError &e) {
        Fail(e.what());
    }
}

Anchor ToAnchor(const ffi::Anchor &a) { return Anchor{a.block_id, a.height}; }
ffi::Anchor FfiAnchor(const Anchor &a) {
    return ffi::Anchor{a.block_id, a.height};
}
WireRange Range(const ffi::WireRange &r) { return WireRange{r.offset, r.length}; }

ffi::Location FfiLocation(const TxLocation &l) {
    return ffi::Location{ffi::Anchor{l.block_id.b, l.height}, l.tx_index,
                         l.txid.hash.b, l.txhash.hash.b};
}

ffi::Continuation FfiContinuation(const std::optional<qb::Cursor> &c) {
    ffi::Continuation out;
    out.present = c.has_value();
    out.version = 1;
    if (c) {
        out.version = c->version;
        out.chain_id = c->snapshot.chain_id.b;
        out.profile = c->snapshot.profile_id.b;
        out.anchor = ffi::Anchor{c->snapshot.tip.b, c->snapshot.height};
        out.filter_digest = c->filter_digest.b;
        out.has_last = c->last_key.has_value();
        if (c->last_key) {
            out.last_txid = c->last_key->txid.hash.b;
            out.last_out_idx = c->last_key->out_idx;
        }
    }
    return out;
}

/** Rust io::Error Display: "<description> (os error N)". */
std::string IoError(int err) {
    return std::string(std::strerror(err)) + " (os error " +
           std::to_string(err) + ")";
}

} // namespace

ffi::Continuation EmptyContinuation() { return FfiContinuation(std::nullopt); }

std::unique_ptr<V2Service>
V2Service::Open(const std::string &path, const ffi::Binding &binding,
                bool fresh, const ffi::ServiceLimits &limits,
                qb::Sha256Fn sha256, std::shared_ptr<const TxSource> source) {
    if (path.empty() || path.size() > 4096) {
        Fail("path bound");
    }
    // block_bytes is the consensus block-size limit; the index bounds and
    // the largest transaction and change counts follow from it.
    std::optional<Bounds> bounds;
    try {
        bounds.emplace(limits.block_bytes);
    } catch (const V2Error &) {
        Fail("service limits");
    }
    if (limits.transactions == 0 ||
        limits.transactions > bounds->Transactions() || limits.changes == 0 ||
        limits.changes > bounds->Changes() || limits.roots == 0 ||
        limits.roots > 256 || limits.clauses == 0 || limits.clauses > 16 ||
        limits.page_size == 0 || limits.page_size > 1000 ||
        limits.posting_reads == 0 || limits.posting_reads > 65536 ||
        limits.work == 0 || limits.work > 131072 ||
        limits.response_bytes < 512 || limits.response_bytes > 1024 * 1024) {
        Fail("service limits");
    }
    std::unique_ptr<V2Service> service(new V2Service());
    try {
        std::random_device rd;
        for (size_t i = 0; i < service->m_service_epoch.size(); i += 4) {
            const uint32_t word = rd();
            for (size_t j = 0; j < 4; ++j) {
                service->m_service_epoch[i + j] = uint8_t(word >> (8 * j));
            }
        }
    } catch (const std::exception &) {
        Fail("explorer entropy unavailable");
    }
    const std::filesystem::path dir(path);
    if (fresh) {
        if (::mkdir(dir.c_str(), 0777) != 0) {
            Fail(IoError(errno));
        }
    } else {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(dir / "mdbx.dat", ec)) {
            Fail("existing V2 DB required");
        }
    }
    const Binding db_binding{binding.chain_id, binding.genesis,
                             binding.profile};
    try {
        if (source) {
            service->m_db = std::make_shared<SharedV2Db>(dir, db_binding,
                                                         *bounds, source);
        } else {
            static std::mutex memory_mutex;
            static std::map<std::string, std::shared_ptr<MemTxSource>> memory;
            std::shared_ptr<MemTxSource> recorder;
            {
                std::lock_guard lock(memory_mutex);
                auto &entry = memory[path];
                if (!entry) {
                    entry = std::make_shared<MemTxSource>();
                }
                recorder = entry;
            }
            service->m_db = std::make_shared<SharedV2Db>(dir, db_binding,
                                                         *bounds, recorder);
        }
    } catch (const V2Error &e) {
        if (e.kind() == V2Error::Kind::Schema) {
            throw V2SchemaError(e.what());
        }
        Fail(e.what());
    } catch (const ChronikError &e) {
        Fail(e.what());
    }
    service->m_limits = limits;
    service->m_bounds = *bounds;
    service->m_genesis = binding.genesis;
    service->m_authority = std::make_shared<Authority>();
    service->m_index_error = std::make_shared<std::atomic<bool>>(false);
    service->m_sha256 = std::move(sha256);
    return service;
}

uint64_t V2Service::InvalidateAuthority() {
    return Db([&] { return m_authority->Publish(std::nullopt); });
}

uint64_t V2Service::PublishAuthority(const ffi::Anchor &anchor) {
    return Db([&] { return m_authority->Publish(ToAnchor(anchor)); });
}

uint64_t V2Service::SuspendAuthority() {
    return Db([&] { return m_authority->Suspend(); });
}

uint64_t V2Service::PublishAuthorityContext(const ffi::Anchor &anchor,
                                            uint64_t context_generation,
                                            uint64_t chain_revision) {
    return Db([&] {
        return m_authority->PublishContext(ToAnchor(anchor),
                                           context_generation, chain_revision);
    });
}

std::optional<ffi::Anchor> V2Service::Checkpoint() const {
    std::lock_guard<std::mutex> lock(m_db->mutex);
    const auto checkpoint = Db([&] { return m_db->db.Checkpoint(); });
    if (!checkpoint) {
        return std::nullopt;
    }
    return FfiAnchor(*checkpoint);
}

ConfirmedTx ConvertNativeTx(const ffi::NativeTx &tx, const Anchor &block) {
    ConfirmedTx ctx;
    for (const ffi::NativeOutput &o : tx.outputs) {
        OutputError err;
        auto output = Output::Decode(o.wire, &err);
        if (!output) {
            Fail(err.Message());
        }
        ctx.outputs.push_back(std::move(*output));
    }
    ctx.location = TxLocation{H(block.block_id), block.height, tx.index,
                              TxId{H(tx.txid)}, TxHash{H(tx.txhash)}};
    ctx.pos = TxPos{tx.file_num, tx.data_pos};
    ctx.explorer.wire = tx.wire;
    ctx.explorer.lock = tx.lock;
    for (const ffi::NativeFullInput &i : tx.full_inputs) {
        InputFact fact;
        fact.prev_txid = i.prev_txid;
        fact.prev_index = i.prev_index;
        fact.sequence = i.sequence;
        fact.flags = i.flags;
        fact.path_index = i.path_index;
        fact.has_coinbase_data = i.has_coinbase_data;
        fact.coinbase_data = Range(i.coinbase_data);
        for (const ffi::NativeWitness &w : i.witnesses) {
            fact.witnesses.push_back(WitnessFact{
                Range(w.script), Range(w.siblings_table), w.siblings_count,
                Range(w.arguments_table), w.arguments_count});
        }
        ctx.explorer.inputs.push_back(std::move(fact));
    }
    for (const ffi::Input &i : tx.inputs) {
        ctx.spends.push_back(
            SpentInput{OutPoint{TxId{H(i.txid)}, i.out_idx}, i.input_index});
    }
    return ctx;
}

CommittedBlock V2Service::Block(const ffi::NativeBlock &block) const {
    if (block.transactions.size() > m_limits.transactions) {
        Fail("transaction bound");
    }
    // The block's wire bytes are within the consensus size limit; the facts
    // copied for them are within the index bounds it implies.
    const size_t cap = m_bounds.BatchBytes();
    size_t wire = block.header_wire.size();
    size_t bytes = 218;
    size_t changes = 0;
    if (wire > m_bounds.BlockBytes() || bytes > cap) {
        Fail("block bytes bound");
    }
    for (const ffi::NativeTx &tx : block.transactions) {
        wire += tx.wire.size();
        if (wire > m_bounds.BlockBytes()) {
            Fail("block bytes bound");
        }
        size_t descriptor_bytes = 0;
        for (const ffi::NativeFullInput &i : tx.full_inputs) {
            descriptor_bytes += i.witnesses.size() * 80 + 128;
        }
        bytes += tx.wire.size() + descriptor_bytes;
        if (bytes > cap) {
            Fail("full facts bound");
        }
        changes += tx.inputs.size() + tx.outputs.size();
        bytes += 76 + tx.inputs.size() * 40;
        if (changes > m_limits.changes || bytes > cap) {
            Fail("block input bound");
        }
        for (const ffi::NativeOutput &output : tx.outputs) {
            if (output.wire.size() > MAX_OUTPUT_BYTES) {
                Fail("output bound");
            }
            bytes += 4 + output.wire.size();
            if (bytes > cap) {
                Fail("block bytes bound");
            }
        }
    }
    CommittedBlock out;
    out.anchor = ToAnchor(block.anchor);
    out.parent = ToAnchor(block.parent);
    out.explorer.header_wire = block.header_wire;
    for (const ffi::NativeTx &tx : block.transactions) {
        out.transactions.push_back(ConvertNativeTx(tx, out.anchor));
    }
    return out;
}

template <typename F> void V2Service::Transition(F &&action) {
    try {
        InvalidateAuthority();
        action();
    } catch (...) {
        m_index_error->store(true, std::memory_order_release);
        throw;
    }
    m_index_error->store(false, std::memory_order_release);
}

void V2Service::InitializeGenesis(const ffi::NativeBlock &block) {
    Transition([&] {
        if (block.anchor.height != 0 || block.parent.height != 0 ||
            block.anchor.block_id != block.parent.block_id ||
            block.anchor.block_id != m_genesis) {
            Fail("genesis binding/shape");
        }
        const CommittedBlock committed = Block(block);
        std::lock_guard<std::mutex> lock(m_db->mutex);
        Db([&] { m_db->db.InitializeGenesis(committed); });
    });
}

void V2Service::ConnectBlock(const ffi::NativeBlock &block) {
    Transition([&] {
        const CommittedBlock committed = Block(block);
        std::lock_guard<std::mutex> lock(m_db->mutex);
        Db([&] { m_db->db.Connect(committed); });
    });
}

void V2Service::DisconnectBlock(const ffi::Anchor &expected) {
    Transition([&] {
        std::lock_guard<std::mutex> lock(m_db->mutex);
        Db([&] { m_db->db.Disconnect(ToAnchor(expected)); });
    });
}

ffi::Status V2Service::GetStatus(const ffi::Anchor &node) const {
    std::optional<Anchor> checkpoint;
    {
        std::lock_guard<std::mutex> lock(m_db->mutex);
        checkpoint = Db([&] { return m_db->db.Checkpoint(); });
    }
    ffi::Status status;
    status.initialized = checkpoint.has_value();
    status.ready = checkpoint == ToAnchor(node);
    status.indexed = FfiAnchor(checkpoint.value_or(Anchor{}));
    status.node = node;
    return status;
}

ffi::BranchPage
V2Service::QueryBranches(const ffi::BranchRequest &request) const {
    if (request.positions.size() > m_limits.clauses ||
        request.any_branch.size() > m_limits.roots) {
        Fail("query input bound");
    }
    size_t total = request.any_branch.size();
    for (const ffi::Position &p : request.positions) {
        total += p.roots.size();
    }
    if (total > m_limits.roots || request.positions.size() > m_limits.clauses) {
        Fail("query input bound");
    }
    qb::BranchFilter filter;
    for (const ffi::Root &r : request.any_branch) {
        filter.any_branch.push_back(H(r.bytes));
    }
    for (const ffi::Position &p : request.positions) {
        qb::PositionClause clause{p.position, {}};
        for (const ffi::Root &r : p.roots) {
            clause.roots.push_back(H(r.bytes));
        }
        filter.positions.push_back(std::move(clause));
    }
    std::optional<qb::Cursor> cursor;
    const ffi::Continuation &c = request.cursor;
    if (c.present) {
        cursor = qb::Cursor{
            c.version,
            qb::Snapshot{H(c.chain_id), H(c.profile), H(c.anchor.block_id),
                         c.anchor.height},
            H(c.filter_digest),
            c.has_last ? std::optional<OutPoint>(
                             OutPoint{TxId{H(c.last_txid)}, c.last_out_idx})
                       : std::nullopt};
    }
    std::lock_guard<std::mutex> lock(m_db->mutex);
    const ReadSnapshot snapshot = Db([&] { return m_db->db.Snapshot(); });
    const qb::SnapshotPostingSource source(snapshot);
    // Fixed-width transport includes absent spend slots. This conservative
    // budget covers vector framing and all optional cursor/record fields.
    const size_t envelope = 307;
    const size_t room = size_t(m_limits.response_bytes) - envelope;
    const size_t page_cap =
        std::max<size_t>(std::min<size_t>(m_limits.page_size, room / 300), 1);
    qb::Limits limits;
    limits.roots = m_limits.roots;
    limits.clauses = m_limits.clauses;
    limits.page_size = page_cap;
    limits.posting_reads = m_limits.posting_reads;
    limits.work = m_limits.work;
    limits.result_bytes = room > page_cap * 119 ? room - page_cap * 119 : 0;
    qb::Page page;
    try {
        page = qb::Query(source, filter,
                         request.utxos ? qb::QueryKind::Utxos()
                                       : qb::QueryKind::History(
                                             request.include_burn),
                         limits, cursor, m_sha256);
    } catch (const qb::QueryError &e) {
        Fail("V2 query: " + e.Debug());
    }
    ffi::BranchPage out;
    size_t encoded_bytes = envelope;
    for (qb::Match &m : page.matches) {
        ffi::OutputMatch match;
        match.txid = m.record.outpoint.txid.hash.b;
        match.out_idx = m.record.outpoint.out_idx;
        OutputError err;
        auto wire = m.record.output.Encode(&err);
        if (!wire) {
            Fail(err.Message());
        }
        match.wire = std::move(*wire);
        match.creation = FfiLocation(m.record.creation);
        match.spent = m.record.spend.has_value();
        if (m.record.spend) {
            match.spend = FfiLocation(m.record.spend->transaction);
            match.input_index = m.record.spend->input_index;
        }
        match.matching_positions = std::move(m.matching_positions);
        encoded_bytes +=
            265 + match.wire.size() + match.matching_positions.size();
        out.matches.push_back(std::move(match));
    }
    if (encoded_bytes > m_limits.response_bytes) {
        Fail("response bytes bound");
    }
    out.anchor = ffi::Anchor{page.snapshot.tip.b, page.snapshot.height};
    out.chain_id = page.snapshot.chain_id.b;
    out.profile = page.snapshot.profile_id.b;
    out.cursor = FfiContinuation(page.continuation);
    out.posting_reads = page.posting_reads;
    out.work = page.work;
    out.encoded_bytes = encoded_bytes;
    return out;
}

} // namespace chronik::native::lotus_v2
