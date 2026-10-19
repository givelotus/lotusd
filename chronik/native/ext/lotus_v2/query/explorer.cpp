// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ext/lotus_v2/query/explorer.h>

#include <ext/lotus_v2/db/branch.h>
#include <ext/lotus_v2/db/explorer.h>

#include <algorithm>

namespace chronik::native::lotus_v2::query_explorer {

namespace {

void CheckPageSize(size_t size) {
    if (size == 0 || size > MAX_PAGE_SIZE) {
        ThrowInvalid("explorer page limits");
    }
}

template <typename T> T Required(std::optional<T> item) {
    if (!item) {
        ThrowCorrupt();
    }
    return std::move(*item);
}

} // namespace

// Physical read ceilings with shared canonical joins: transaction = eT + t/eH
// + eB/eH/parent-eH + eO = 7; historical output = o + creation t/eH
// + optional spender t/eH = 5; input = transaction7 + eI1 + witness
// endpoints2 + output5 + creation transaction7 = 22; witness = input22
// + eW1 + transaction7 + up to four wire-chunk reads = 34.

std::optional<BlockMeta> SnapshotExplorerSource::Block(const Hash32 &id) const {
    return m_s.ExplorerBlock(id);
}
std::optional<BlockMeta>
SnapshotExplorerSource::BlockAtHeight(uint64_t height) const {
    return m_s.ExplorerBlockAtHeight(height);
}
std::optional<TxMeta>
SnapshotExplorerSource::Transaction(const TxId &id) const {
    return m_s.ExplorerTx(id);
}
std::optional<TxMeta>
SnapshotExplorerSource::TransactionByHash(const TxHash &hash) const {
    return m_s.ExplorerTxByHash(hash);
}
std::optional<std::pair<TxId, TxHash>>
SnapshotExplorerSource::BlockTransaction(const Hash32 &block,
                                         uint32_t index) const {
    return m_s.ExplorerBlockTx(block, index);
}
std::optional<InputMeta> SnapshotExplorerSource::GetInput(const TxId &id,
                                                       uint32_t index) const {
    return m_s.ExplorerInput(id, index);
}
std::optional<WitnessFact>
SnapshotExplorerSource::Witness(const TxId &id, uint32_t input,
                                uint32_t index) const {
    return m_s.ExplorerWitness(id, input, index);
}
std::optional<OutputRecord>
SnapshotExplorerSource::GetOutput(const OutPoint &op) const {
    return m_s.GetOutput(op);
}
std::optional<Bytes> SnapshotExplorerSource::Wire(const TxId &id,
                                                  uint32_t chunk) const {
    return m_s.ExplorerWireChunk(id, chunk);
}

std::string UnsignedDecimal(U128 value) {
    if (value == 0) {
        return "0";
    }
    std::string out;
    while (value > 0) {
        out.push_back(char('0' + int(value % 10)));
        value /= 10;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

uint64_t Confirmations(uint64_t tip_height, uint64_t creation_height) {
    if (tip_height < creation_height ||
        tip_height - creation_height == UINT64_MAX) {
        ThrowInvalid("confirmation arithmetic");
    }
    return tip_height - creation_height + 1;
}

template <typename T>
Page<T> OrdinalPage(uint32_t count, std::optional<uint64_t> after, size_t size,
                    size_t initial_reads, size_t reads_per_item,
                    const std::function<std::pair<T, size_t>(uint32_t)> &load) {
    CheckPageSize(size);
    if (after && *after >= count) {
        ThrowInvalid("explorer continuation ordinal");
    }
    const uint64_t start = after ? *after + 1 : 0;
    Page<T> page;
    page.items.reserve(std::min<size_t>(size, count));
    uint64_t index = start;
    size_t bytes = 0;
    size_t examined = 0;
    while (index < count && page.items.size() < size) {
        // Reserve reads and examination before the storage call.
        if (examined + 1 > MAX_EXAMINED ||
            initial_reads + (examined + 1) * reads_per_item > MAX_KEY_READS) {
            break;
        }
        ++examined;
        auto [item, record_bytes] = load(uint32_t(index));
        if (record_bytes > MAX_PAGE_BYTES) {
            ThrowInvalid("explorer record limit");
        }
        if (bytes + record_bytes > MAX_PAGE_BYTES) {
            if (page.items.empty()) {
                ThrowInvalid("explorer record limit");
            }
            break;
        }
        bytes += record_bytes;
        page.items.push_back(std::move(item));
        ++index;
    }
    page.exhausted = index == count;
    if (!page.exhausted) {
        if (index == 0) {
            ThrowCorrupt();
        }
        page.next_index = index - 1;
    }
    page.examined = examined;
    page.key_reads = initial_reads + examined * reads_per_item;
    return page;
}

// Explicit instantiations used by the pages below and by tests.
template Page<TxMeta> OrdinalPage<TxMeta>(
    uint32_t, std::optional<uint64_t>, size_t, size_t, size_t,
    const std::function<std::pair<TxMeta, size_t>(uint32_t)> &);
template Page<InputMeta> OrdinalPage<InputMeta>(
    uint32_t, std::optional<uint64_t>, size_t, size_t, size_t,
    const std::function<std::pair<InputMeta, size_t>(uint32_t)> &);
template Page<OutputRecord> OrdinalPage<OutputRecord>(
    uint32_t, std::optional<uint64_t>, size_t, size_t, size_t,
    const std::function<std::pair<OutputRecord, size_t>(uint32_t)> &);
template Page<WitnessFact> OrdinalPage<WitnessFact>(
    uint32_t, std::optional<uint64_t>, size_t, size_t, size_t,
    const std::function<std::pair<WitnessFact, size_t>(uint32_t)> &);
template Page<uint32_t> OrdinalPage<uint32_t>(
    uint32_t, std::optional<uint64_t>, size_t, size_t, size_t,
    const std::function<std::pair<uint32_t, size_t>(uint32_t)> &);

Page<BlockMeta> BlocksPage(const ExplorerSource &source, uint64_t tip,
                           std::optional<uint64_t> before, size_t size) {
    CheckPageSize(size);
    std::optional<uint64_t> next;
    if (!before) {
        next = tip;
    } else if (*before != 0) {
        next = std::min(*before - 1, tip);
    }
    Page<BlockMeta> page;
    page.items.reserve(size);
    while (next) {
        if (page.items.size() == size) {
            break;
        }
        const uint64_t height = *next;
        BlockMeta block = Required(source.BlockAtHeight(height));
        if (block.anchor.height != height) {
            ThrowCorrupt();
        }
        page.items.push_back(std::move(block));
        next = height == 0 ? std::nullopt : std::optional<uint64_t>(height - 1);
    }
    page.exhausted = !next;
    page.examined = page.items.size();
    if (!page.exhausted && !page.items.empty()) {
        page.next_index = page.items.back().anchor.height;
    }
    page.key_reads = page.examined * 4;
    return page;
}

std::optional<Page<TxMeta>>
BlockTransactionsPage(const ExplorerSource &source, const Hash32 &block,
                      std::optional<uint64_t> after, size_t size) {
    CheckPageSize(size);
    const auto meta = source.Block(block);
    if (!meta) {
        return std::nullopt;
    }
    return OrdinalPage<TxMeta>(
        meta->tx_count, after, size, 3, 8,
        [&](uint32_t index) -> std::pair<TxMeta, size_t> {
            const auto [id, hash] =
                Required(source.BlockTransaction(block, index));
            TxMeta tx = Required(source.Transaction(id));
            if (tx.location.txhash != hash || tx.location.block_id != block ||
                tx.location.tx_index != index ||
                tx.location.height != meta->anchor.height) {
                ThrowCorrupt();
            }
            return {std::move(tx), 256};
        });
}

std::optional<Page<InputMeta>> InputsPage(const ExplorerSource &source,
                                          const TxId &id,
                                          std::optional<uint64_t> after,
                                          size_t size) {
    CheckPageSize(size);
    const auto tx = source.Transaction(id);
    if (!tx) {
        return std::nullopt;
    }
    return OrdinalPage<InputMeta>(
        tx->input_count, after, size, 7, 22,
        [&](uint32_t index) -> std::pair<InputMeta, size_t> {
            InputMeta input = Required(source.GetInput(id, index));
            ValidateInputMeta(input, tx->wire_size);
            size_t bytes = 256;
            if (const auto &coin = input.resolved_creation) {
                bytes += 812 + 128;
                for (const auto &path : coin->output.paths) {
                    bytes += path.size();
                }
            }
            return {std::move(input), bytes};
        });
}

std::optional<Page<OutputRecord>> OutputsPage(const ExplorerSource &source,
                                              const TxId &id,
                                              std::optional<uint64_t> after,
                                              size_t size) {
    CheckPageSize(size);
    const auto tx = source.Transaction(id);
    if (!tx) {
        return std::nullopt;
    }
    return OrdinalPage<OutputRecord>(
        tx->output_count, after, size, 7, 5,
        [&](uint32_t index) -> std::pair<OutputRecord, size_t> {
            const OutPoint op{id, index};
            OutputRecord output = Required(source.GetOutput(op));
            if (output.creation != tx->location || output.outpoint != op) {
                ThrowCorrupt();
            }
            return {std::move(output), 1200};
        });
}

std::optional<Page<WitnessFact>>
WitnessesPage(const ExplorerSource &source, const TxId &id,
              uint32_t input_index, std::optional<uint64_t> after,
              size_t size) {
    CheckPageSize(size);
    const auto tx = source.Transaction(id);
    if (!tx || input_index >= tx->input_count) {
        return std::nullopt;
    }
    const InputMeta input = Required(source.GetInput(id, input_index));
    return OrdinalPage<WitnessFact>(
        input.witness_count, after, size, 29, 34,
        [&](uint32_t index) -> std::pair<WitnessFact, size_t> {
            WitnessFact witness =
                Required(source.Witness(id, input_index, index));
            ValidateWitnessFact(witness, tx->wire_size);
            return {std::move(witness), 128};
        });
}

std::optional<WireChunk> GetWireChunk(const ExplorerSource &source,
                                      const TxId &id, uint64_t offset,
                                      size_t length) {
    if (length == 0 || length > WIRE_CHUNK_BYTES) {
        ThrowInvalid("explorer wire limits");
    }
    const auto tx = source.Transaction(id);
    if (!tx) {
        return std::nullopt;
    }
    if (offset > tx->wire_size) {
        ThrowInvalid("explorer wire range");
    }
    const uint64_t remaining = tx->wire_size - offset;
    const size_t wanted = size_t(std::min<uint64_t>(remaining, length));
    Bytes bytes;
    bytes.reserve(wanted);
    const uint64_t end = offset + wanted;
    uint64_t position = offset;
    while (position < end) {
        const uint64_t chunk_index = position / WIRE_CHUNK_BYTES;
        if (chunk_index > UINT32_MAX) {
            ThrowCorrupt();
        }
        const uint32_t index = uint32_t(chunk_index);
        const Bytes chunk = Required(source.Wire(id, index));
        const uint64_t chunk_start = uint64_t(index) * WIRE_CHUNK_BYTES;
        const size_t expected = size_t(
            std::min<uint64_t>(tx->wire_size - chunk_start, WIRE_CHUNK_BYTES));
        if (chunk.size() != expected) {
            ThrowCorrupt();
        }
        const size_t local = size_t(position - chunk_start);
        const size_t take =
            std::min<size_t>(expected - local, size_t(end - position));
        if (take == 0) {
            ThrowCorrupt();
        }
        bytes.insert(bytes.end(), chunk.begin() + local,
                     chunk.begin() + local + take);
        position += take;
    }
    WireChunk out{id, tx->location.txhash, tx->wire_size, offset,
                  std::move(bytes), std::nullopt};
    if (end != tx->wire_size) {
        out.next_offset = end;
    }
    return out;
}

} // namespace chronik::native::lotus_v2::query_explorer
