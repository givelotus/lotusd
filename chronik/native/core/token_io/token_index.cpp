// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/token_io/token_index.h>

#include <chronik/native/groups/token_id.h>
#include <chronik/native/mem/tokens.h>
#include <chronik/native/token_io/io.h>

namespace chronik::native::token_io {

namespace {

class EcashTokenIndex final : public TokenIndex {
public:
    explicit EcashTokenIndex(const KvStore &store) : m_writer(store) {}

    const GroupDef &TokenIdGroup() const override { return m_group; }

    std::unique_ptr<mem::MempoolTokenHook> MakeMempoolHook() override {
        return std::make_unique<mem::MempoolTokens>();
    }

    std::shared_ptr<const GroupAux>
    ConnectBlock(const KvStore &, WriteTxn &txn,
                 std::span<const index::IndexTx> txs) override {
        const ProcessedTokenTxBatch processed = m_writer.Insert(txn, txs);
        return std::make_shared<groups::TokenIdGroupAux>(
            groups::TokenIdGroupAux::FromBatch(txs, processed));
    }

    std::shared_ptr<const GroupAux>
    AuxFromDb(const KvStore &store, const ReadTxn &txn,
              std::span<const index::IndexTx> txs) const override {
        return std::make_shared<groups::TokenIdGroupAux>(
            groups::TokenIdGroupAux::FromDb(txs, store, txn));
    }

    void DisconnectBlock(const KvStore &, WriteTxn &txn,
                         std::span<const index::IndexTx> txs) override {
        m_writer.Delete(txn, txs);
    }

    TokenIdSubsAux SubsAux(const GroupAux *aux) const override {
        const auto *token_aux =
            dynamic_cast<const groups::TokenIdGroupAux *>(aux);
        return token_aux ? TokenIdSubsAux(*token_aux) : TokenIdSubsAux{};
    }

private:
    groups::TokenIdGroup m_group;
    TokenWriter m_writer;
};

} // namespace

std::unique_ptr<TokenIndex> MakeEcashTokenIndex(const KvStore &store) {
    return std::make_unique<EcashTokenIndex>(store);
}

void RegisterEcashTokenIndex() {
    RegisterTokenIndexFactory(MakeEcashTokenIndex);
}

} // namespace chronik::native::token_io
