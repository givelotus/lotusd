// Copyright (c) 2026 The Lotus developers
#include <wallet/v2_node_provider.h>

#include <lotus_v2/monetary.h>
#include <algorithm>
#include <limits>
#include <set>
#include <span>
#include <stdexcept>
#include <univalue.h>

namespace lotus::v2::wallet {
namespace {
    void Require(bool condition, const char *message) {
        if (!condition) throw std::runtime_error(message);
    }
    Result Fail(Result result, std::string &error, std::string_view message) {
        error.assign(message.substr(0, 1024));
        return result;
    }
    void Keys(const UniValue &value, const std::set<std::string> &expected) {
        Require(value.isObject() && value.getKeys().size() == expected.size() &&
                    std::set<std::string>(value.getKeys().begin(),
                                          value.getKeys().end()) == expected,
                "walletcontext unknown, duplicate or missing field");
    }
    uint64_t Number(const UniValue &value, uint64_t maximum) {
        Require(value.isNum(), "walletcontext integer required");
        const auto &text = value.getValStr();
        Require(!text.empty() && (text.size() == 1 || text.front() != '0'),
                "walletcontext noncanonical integer");
        uint64_t number = 0;
        for (char c : text) {
            Require(c >= '0' && c <= '9' && uint64_t(c - '0') <= maximum &&
                        number <= (maximum - uint64_t(c - '0')) / 10,
                    "walletcontext integer outside limit");
            number = number * 10 + uint64_t(c - '0');
        }
        return number;
    }
    std::string Hex(std::span<const uint8_t> bytes) {
        constexpr char digits[] = "0123456789abcdef";
        std::string text;
        text.reserve(2 * bytes.size());
        for (auto byte : bytes) {
            text += digits[byte >> 4];
            text += digits[byte & 15];
        }
        return text;
    }
    std::vector<uint8_t> Unhex(const UniValue &value, size_t maximum) {
        Require(value.isStr(), "walletcontext hex string required");
        const auto &text = value.get_str();
        Require(text.size() % 2 == 0 && text.size() / 2 <= maximum,
                "walletcontext hex exceeds bound");
        auto digit = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            throw std::runtime_error("walletcontext noncanonical hex");
        };
        std::vector<uint8_t> bytes;
        bytes.reserve(text.size() / 2);
        for (size_t i = 0; i < text.size(); i += 2)
            bytes.push_back((digit(text[i]) << 4) | digit(text[i + 1]));
        return bytes;
    }
    Hash HashOf(const UniValue &value) {
        auto bytes = Unhex(value, 32);
        Require(bytes.size() == 32, "walletcontext hash width");
        Hash hash{};
        std::copy(bytes.begin(), bytes.end(), hash.begin());
        return hash;
    }
    Header HeaderOf(const UniValue &value) {
        const auto bytes = Unhex(value, HEADER_SIZE);
        Header header;
        std::array<uint8_t, HEADER_SIZE> canonical{};
        Require(ParseHeader(bytes.data(), bytes.size(), header) &&
                    SerializeHeader(header, canonical) &&
                    std::equal(bytes.begin(), bytes.end(), canonical.begin(),
                               canonical.end()),
                "walletcontext header encoding");
        return header;
    }
    Coin CoinOf(const UniValue &value) {
        const auto bytes = Unhex(value, MAX_COIN_BYTES);
        Coin coin;
        // Use the same versioned, canonical CoinEntry decoder as authenticated
        // state storage, including paid fee share and effective expiration.
        Require(DecodeCoinBytes(bytes, coin) && !coin.output.legacy_script,
                "walletcontext invalid native CoinEntry");
        return coin;
    }
    CoinProof ProofOf(const UniValue &value) {
        Keys(value, {"presence", "coin", "bitmap", "siblings"});
        CoinProof proof;
        proof.presence = ProofPresence(Number(value["presence"], 2));
        if (!value["coin"].isNull()) proof.coin = CoinOf(value["coin"]);
        proof.bitmap = HashOf(value["bitmap"]);
        const auto &siblings = value["siblings"];
        Require(siblings.isArray() && siblings.size() <= 256,
                "walletcontext proof siblings bound");
        for (const auto &sibling : siblings.getValues())
            proof.siblings.push_back(HashOf(sibling));
        return proof;
    }
    bool SameHeader(const Header &a, const Header &b) {
        std::array<uint8_t, HEADER_SIZE> left{}, right{};
        return SerializeHeader(a, left) && SerializeHeader(b, right) && left == right;
    }
    ChainAnchor AnchorOf(const UniValue &value, const ChainProfile &profile,
                         const Profile &binding) {
        Require(HashOf(value["chain_id"]) == binding.chain_id &&
                    HashOf(value["genesis_id"]) == binding.genesis_id &&
                    HashOf(value["profile_digest"]) == binding.validation_digest,
                "walletcontext manifest profile mismatch");
        const auto tip = HeaderOf(value["tip_header"]);
        const auto height = Number(value["height"], UINT64_MAX - 1);
        const auto claimed_id = HashOf(value["tip"]);
        Hash actual_id{};
        Require(tip.height == height && BlockId(binding.chain_id, tip, actual_id) &&
                    actual_id == claimed_id,
                "walletcontext tip identity mismatch");
        const auto root = HashOf(value["utxo_root"]);
        const auto claimed_state = HashOf(value["state_root"]);
        const auto monetary_bytes = Unhex(value["monetary_bytes"], 56);
        const auto monetary = DecodeMonetaryState(monetary_bytes);
        const auto canonical_money = EncodeMonetaryState(monetary);
        Require(std::equal(monetary_bytes.begin(), monetary_bytes.end(),
                           canonical_money.begin(), canonical_money.end()) &&
                    tip.state_root == claimed_state &&
                    StateRoot(binding.chain_id, height, root, monetary) == claimed_state,
                "walletcontext state commitment mismatch");
        const auto &raw_history = value["history"];
        Require(raw_history.isArray() && raw_history.size() == (height >= 10 ? 11 : size_t(height) + 1),
                "walletcontext history bound");
        std::vector<Header> history;
        history.reserve(raw_history.size());
        for (const auto &raw : raw_history.getValues()) {
            auto header = HeaderOf(raw);
            Hash target{};
            Require(DecodeTarget(header.bits, profile.header.pow_limit, target),
                    "walletcontext noncanonical header target");
            history.push_back(header);
        }
        Require(!history.empty() && SameHeader(history.front(), tip),
                "walletcontext tip/history mismatch");
        const auto mtp = ParentMedianTime(profile.header, tip, history);
        Require(bool(mtp), "walletcontext unlinked or invalid history");
        return {binding, {claimed_id, root, height, *mtp}};
    }
} // namespace

NodePaymentChainProvider::NodePaymentChainProvider(ChainProfile profile,
                                                 NodeJsonlExchange exchange)
    : profile_(std::move(profile)), binding_(profile_.Binding()),
      exchange_(std::move(exchange)) {}

Result NodePaymentChainProvider::Context(const ChainAnchor *pinned,
                                        const Outpoint *point,
                                        ChainAnchor &out,
                                        std::optional<Coin> &coin,
                                        std::string &error) {
    try {
        if (!exchange_ || binding_.genesis_id == Hash{} || binding_.validation_digest == Hash{})
            return Fail(Result::Invalid, error, "walletcontext provider configuration unavailable");
        if (pinned && pinned->profile != binding_)
            return Fail(Result::Invalid, error, "walletcontext anchor profile mismatch");
        if (!next_id_)
            return Fail(Result::StorageError, error, "walletcontext request ids exhausted");
        const auto id = "walletcontext-" + std::to_string(next_id_++);
        UniValue request(UniValue::VOBJ);
        request.pushKV("id", id);
        request.pushKV("command", "walletcontext");
        request.pushKV("tip", pinned ? UniValue(Hex(pinned->snapshot.tip)) : UniValue());
        if (point) {
            UniValue query(UniValue::VOBJ);
            query.pushKV("txid", Hex(point->tx_id));
            query.pushKV("index", uint64_t(point->index));
            request.pushKV("outpoint", query);
        } else request.pushKV("outpoint", UniValue());
        const auto line = request.write() + '\n';
        Require(line.size() <= NODE_WALLET_REQUEST_LIMIT, "walletcontext request bound");
        std::string response, transport_error;
        if (!exchange_(line, response, transport_error))
            return Fail(Result::StorageError, error, transport_error.empty() ? "walletcontext transport failure" : transport_error);
        Require(!response.empty() && response.size() <= NODE_WALLET_RESPONSE_LIMIT &&
                    response.back() == '\n' && response.find('\n') == response.size() - 1 &&
                    response.find('\r') == std::string::npos,
                "walletcontext response must be one bounded JSONL frame");
        UniValue answer;
        Require(answer.read(std::string_view(response).substr(0, response.size() - 1)) &&
                    answer.isObject() && answer["id"].isStr() &&
                    answer["id"].get_str() == id && answer["ok"].isBool(),
                "walletcontext response framing or correlation mismatch");
        if (!answer["ok"].get_bool()) {
            Keys(answer, {"id", "ok", "result", "error"});
            Require(answer["result"].isStr() && answer["error"].isStr() &&
                        answer["error"].get_str().size() <= 1024,
                    "walletcontext failure encoding");
            const auto &result = answer["result"].get_str();
            const auto &message = answer["error"].get_str();
            if (result == "stale") return Fail(Result::Stale, error, message);
            if (result == "inconclusive") return Fail(Result::Inconclusive, error, message);
            if (result == "storage_error") return Fail(Result::StorageError, error, message);
            if (result == "invalid") return Fail(Result::Invalid, error, message);
            throw std::runtime_error("walletcontext unknown failure classification");
        }
        Keys(answer, {"id", "ok", "chain_id", "genesis_id", "profile_digest", "tip", "height", "utxo_root", "state_root", "monetary_bytes", "tip_header", "history", "proof"});
        const auto observed = AnchorOf(answer, profile_, binding_);
        if (pinned && observed != *pinned)
            return Fail(Result::Stale, error, "walletcontext chain anchor changed");
        std::optional<Coin> found;
        if (point) {
            const auto proof = ProofOf(answer["proof"]);
            Require(VerifyCoinProof(*point, proof, observed.snapshot.root),
                    "walletcontext coin proof verification failed");
            if (proof.coin)
                Require(proof.coin->creation_height <= observed.snapshot.height &&
                            proof.coin->creation_parent_mtp <= observed.snapshot.parent_mtp,
                        "walletcontext future coin metadata");
            if (proof.presence == ProofPresence::Present) found = proof.coin;
        } else Require(answer["proof"].isNull(), "walletcontext unsolicited proof");
        out = observed;
        coin = std::move(found);
        error.clear();
        return Result::Success;
    } catch (const std::exception &exception) {
        return Fail(Result::StorageError, error, exception.what());
    } catch (...) {
        return Fail(Result::StorageError, error, "walletcontext transport or parsing exception");
    }
}
Result NodePaymentChainProvider::ReadAnchor(const Profile &expected,
                                           ChainAnchor &out,
                                           std::string &error) {
    if (expected != binding_)
        return Fail(Result::Invalid, error, "walletcontext expected profile mismatch");
    ChainAnchor observed;
    std::optional<Coin> coin;
    const auto result = Context(nullptr, nullptr, observed, coin, error);
    if (result == Result::Success) out = observed;
    return result;
}
Result NodePaymentChainProvider::Lookup(const ChainAnchor &anchor,
                                       const Outpoint &point,
                                       std::optional<Coin> &out,
                                       std::string &error) {
    ChainAnchor observed;
    std::optional<Coin> coin;
    const auto result = Context(&anchor, &point, observed, coin, error);
    if (result == Result::Success) out = std::move(coin);
    return result;
}
Result NodePaymentChainProvider::Recheck(const ChainAnchor &anchor,
                                        std::string &error) {
    ChainAnchor observed;
    std::optional<Coin> coin;
    return Context(&anchor, nullptr, observed, coin, error);
}
Result NodePaymentChainProvider::Submit(const std::vector<uint8_t> &wire,
                                       const Hash &tip, Submission &out,
                                       std::string &error) {
    return ExchangeCommand("submittransaction", wire, {}, {}, tip, &out, nullptr, error);
}
Result NodePaymentChainProvider::Status(const Hash &id, const Hash &hash,
                                       const std::vector<uint8_t> &wire,
                                       TransactionState &out, std::string &error) {
    return ExchangeCommand("transactionstatus", wire, id, hash, {}, nullptr, &out, error);
}
Result NodePaymentChainProvider::ExchangeCommand(
    const std::string &command, const std::vector<uint8_t> &wire,
    const Hash &txid, const Hash &txhash, const Hash &tip,
    Submission *submission, TransactionState *status, std::string &error) {
    try {
        Require(exchange_ && next_id_, "node provider unavailable");
        Transaction tx;
        IdentityDigests identities;
        std::vector<uint8_t> canonical;
        Require(DecodeTransaction(wire, profile_.ordinary.transaction, tx, error) &&
                    EncodeTransaction(tx, profile_.ordinary.transaction, canonical, error) &&
                    canonical == wire && ComputeIdentities(tx,
                        profile_.ordinary.transaction, binding_.chain_id, identities, error),
                "outgoing transaction encoding invalid");
        if (status) Require(identities.txid == txid && identities.txhash == txhash,
                            "outgoing transaction identity mismatch");
        const auto id = "wallettransaction-" + std::to_string(next_id_++);
        UniValue request(UniValue::VOBJ);
        request.pushKV("id", id); request.pushKV("command", command);
        if (submission) {
            request.pushKV("wire", Hex(wire));
            request.pushKV("expected_tip", Hex(tip));
        } else {
            request.pushKV("txid", Hex(txid)); request.pushKV("txhash", Hex(txhash));
            request.pushKV("wire", Hex(wire));
        }
        const auto line = request.write() + '\n';
        Require(line.size() <= NODE_WALLET_REQUEST_LIMIT, "transaction request exceeds bound");
        std::string response;
        if (!exchange_(line, response, error))
            return Fail(Result::Inconclusive, error, "transaction exchange outcome unknown; recover persisted transaction");
        Require(!response.empty() && response.size() <= NODE_WALLET_RESPONSE_LIMIT &&
                    response.back() == '\n' && response.find('\n') == response.size() - 1 &&
                    response.find('\r') == std::string::npos, "transaction response framing invalid");
        UniValue answer;
        Require(answer.read(std::string_view(response).substr(0, response.size()-1)) &&
                    answer.isObject() && answer["id"].isStr() && answer["id"].get_str() == id &&
                    answer["ok"].isBool(), "transaction response correlation invalid");
        // A rejected command is not authoritative history or submission receipt.
        if (!answer["ok"].get_bool())
            return Fail(Result::Inconclusive, error, "node transaction command inconclusive");
        Require(HashOf(answer["txid"]) == identities.txid &&
                    HashOf(answer["txhash"]) == identities.txhash,
                "node transaction receipt identity mismatch");
        Require(answer["error"].isStr() && answer["error"].get_str().size() <= 1024,
                "transaction error encoding invalid");
        if (submission) {
            Keys(answer, {"id", "ok", "result", "txid", "txhash", "missing", "error"});
            Require(answer["result"].isStr(), "submission result required");
            const auto result = answer["result"].get_str();
            Require(std::set<std::string>{"accepted", "duplicate", "conflict", "missing_parents",
                        "invalid", "capacity_refused", "stale_tip", "inconclusive"}.count(result),
                    "unknown submission result");
            Submission observed{result, identities.txid, identities.txhash, {}};
            Require(answer["missing"].isArray() && answer["missing"].size() <= 4096,
                    "missing parents exceeds bound");
            for (const auto &point : answer["missing"].getValues()) {
                Keys(point, {"txid", "index"});
                observed.missing.push_back({HashOf(point["txid"]),
                    uint32_t(Number(point["index"], UINT32_MAX))});
            }
            *submission = std::move(observed);
        } else {
            const auto state = answer["state"].get_str();
            Require(std::set<std::string>{"pending", "confirmed", "conflicted", "unknown",
                        "inconclusive"}.count(state), "unknown transaction state");
            TransactionState observed{state, identities.txid, identities.txhash, {}, 0};
            if (state == "confirmed") {
                Keys(answer, {"id", "ok", "state", "txid", "txhash", "block_id", "height", "error"});
                observed.confirmation_block = HashOf(answer["block_id"]);
                observed.confirmation_height = Number(answer["height"], UINT64_MAX);
            } else Keys(answer, {"id", "ok", "state", "txid", "txhash", "error"});
            *status = observed;
        }
        error = answer["error"].get_str();
        return Result::Success;
    } catch (const std::exception &exception) {
        return Fail(Result::Inconclusive, error, exception.what());
    }
}
} // namespace lotus::v2::wallet
