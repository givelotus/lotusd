// Copyright (c) 2026 The Lotus developers
// One-shot native encrypted SQLite wallet. Chain authority is supplied solely
// through the bounded private node JSONL channel; this client opens no LevelDB.
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <iostream>
#include <key.h>
#include <lotus_v2/development_command.h>
#include <random.h>
#include <set>
#include <stdexcept>
#include <string_view>
#include <support/cleanse.h>
#include <univalue.h>
#include <util/translation.h>
#include <wallet/v2_node_provider.h>
#include <wallet/v2_payment.h>
#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif
const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;
namespace {
using namespace lotus::v2;
using namespace lotus::v2::wallet;
using V2Hash = lotus::v2::Hash;
constexpr size_t PUBLIC_REQUEST_LIMIT = 1 << 20;
constexpr size_t PUBLIC_RESPONSE_LIMIT = 4 << 20;
constexpr size_t PASSPHRASE_LIMIT = 4096;
void Require(bool value, const char *reason) {
    if (!value) throw std::runtime_error(reason);
}
void Keys(const UniValue &value, const std::set<std::string> &keys) {
    Require(value.isObject() && value.getKeys().size() == keys.size() &&
                std::set<std::string>(value.getKeys().begin(),
                                      value.getKeys().end()) == keys,
            "unknown, duplicate or missing wallet request field");
}
uint64_t Decimal(std::string_view s, uint64_t maximum = UINT64_MAX) {
    Require(!s.empty() && (s.size() == 1 || s.front() != '0'),
            "canonical unsigned decimal required");
    uint64_t value = 0;
    for (const char c : s) {
        Require(c >= '0' && c <= '9', "canonical unsigned decimal required");
        const uint64_t digit = uint64_t(c - '0');
        Require(digit <= maximum && value <= (maximum - digit) / 10,
                "unsigned decimal out of range");
        value = value * 10 + digit;
    }
    return value;
}
uint64_t Amount(const UniValue &value) {
    Require(value.isStr(), "amount and fee must be decimal strings");
    return Decimal(value.get_str());
}
uint64_t Index(const UniValue &value, uint64_t maximum) {
    Require(value.isStr() || value.isNum(),
            "structural index must be an unsigned integer");
    return Decimal(value.getValStr(), maximum);
}
std::vector<uint8_t> Bytes(const UniValue &value, size_t maximum = 8192) {
    Require(value.isStr(), "lowercase hex string required");
    const auto &s = value.get_str();
    Require(s.size() % 2 == 0 && s.size() / 2 <= maximum,
            "hex length exceeds bound");
    auto digit = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("lowercase hex required");
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2)
        out.push_back(uint8_t((digit(s[i]) << 4) | digit(s[i + 1])));
    return out;
}
V2Hash HashValue(const UniValue &value) {
    auto bytes = Bytes(value, 32);
    Require(bytes.size() == 32, "32-byte hash required");
    V2Hash hash{};
    std::copy(bytes.begin(), bytes.end(), hash.begin());
    return hash;
}
template <typename T> std::string Hex(const T &bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        out += digits[byte >> 4];
        out += digits[byte & 15];
    }
    return out;
}
Output Recipient(const UniValue &value) {
    Keys(value, {"flags", "value", "branches", "paths"});
    Output out;
    out.flags = uint8_t(Index(value["flags"], 255));
    out.value = Amount(value["value"]);
    Require(out.flags == 0,
            "recipient must be an explicit native non-burn output");
    Require(value["branches"].isArray() &&
                value["branches"].size() <= MAX_OUTPUT_BRANCHES &&
                value["paths"].isArray() &&
                value["paths"].size() <= MAX_OUTPUT_PATHS,
            "recipient policy bounds");
    for (const auto &root : value["branches"].getValues())
        out.branches.push_back(HashValue(root));
    for (const auto &raw : value["paths"].getValues()) {
        Require(raw.isArray() && raw.size() <= MAX_OUTPUT_BRANCHES,
                "recipient path bounds");
        std::vector<uint8_t> path;
        for (const auto &index : raw.getValues())
            path.push_back(uint8_t(Index(index, 255)));
        out.paths.push_back(std::move(path));
    }
    std::vector<uint8_t> wire;
    std::string error;
    Require(EncodeOutput(out, wire, error),
            "recipient is not a canonical output");
    return out;
}
UniValue OutputJson(const Output &output) {
    UniValue out(UniValue::VOBJ), branches(UniValue::VARR),
        paths(UniValue::VARR);
    out.pushKV("flags", int(output.flags));
    out.pushKV("value", std::to_string(output.value));
    for (const auto &root : output.branches)
        branches.push_back(Hex(root));
    for (const auto &path : output.paths) {
        UniValue row(UniValue::VARR);
        for (uint8_t index : path)
            row.push_back(int(index));
        paths.push_back(row);
    }
    out.pushKV("branches", branches);
    out.pushKV("paths", paths);
    return out;
}
const char *Name(Result result) {
    switch (result) {
        case Result::Success:
            return "success";
        case Result::Invalid:
            return "invalid";
        case Result::Locked:
            return "locked";
        case Result::Stale:
            return "stale";
        case Result::InsufficientFunds:
            return "insufficient_funds";
        case Result::Inconclusive:
            return "inconclusive";
        case Result::StorageError:
            return "storage_error";
    }
    return "storage_error";
}
struct Options {
    std::string manifest, home, command;
    int node = -1, passphrase = -1;
    uint64_t timeout = 0;
};
Options Arguments(int argc, char **argv) {
    Require(argc >= 6,
            "usage: lotus-v2-wallet-client MANIFEST WALLET_HOME COMMAND "
            "--node-fd=N --timeout-ms=N [--passphrase-fd=N]");
    Options options;
    options.manifest = argv[1];
    options.home = argv[2];
    options.command = argv[3];
    bool node = false, passphrase = false, timeout = false;
    for (int i = 4; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg.starts_with("--node-fd=") && !node) {
            node = true;
            options.node = int(Decimal(arg.substr(10), INT_MAX));
        } else if (arg.starts_with("--passphrase-fd=") && !passphrase) {
            passphrase = true;
            options.passphrase = int(Decimal(arg.substr(16), INT_MAX));
        } else if (arg.starts_with("--timeout-ms=") && !timeout) {
            timeout = true;
            options.timeout = Decimal(arg.substr(13), 60000);
        } else
            throw std::runtime_error(
                "unknown or repeated wallet client option");
    }
    Require(node && timeout && options.timeout > 0,
            "explicit positive timeout and node FD required");
    Require(options.node > 2,
            "node FD must be separate from standard input/output/error");
    const bool secret =
        options.command == "create" || options.command == "sign" || options.command == "pay";
    Require(secret == (options.passphrase >= 0),
            "passphrase FD required only for create/sign/pay");
    Require(options.passphrase < 0 ||
                (options.passphrase > 2 && options.passphrase != options.node),
            "passphrase FD aliases a public channel");
    return options;
}
void RequestShape(const std::string &command, const UniValue &request) {
    if (command == "create" || command == "info" || command == "reconcile")
        Keys(request, {});
    else if (command == "register")
        Keys(request, {"script", "proof", "root"});
    else if (command == "track")
        Keys(request, {"prev_txid", "prev_index"});
    else if (command == "prepare" || command == "sign" || command == "pay")
        Keys(request, {"recipient", "fee"});
    else if (command == "abandon" || command == "broadcast" || command == "status")
        Keys(request, {"txid"});
    else if (command == "pending")
        Keys(request, {});
    else if (command == "export")
        Keys(request, {"txid", "max_bytes"});
    else
        throw std::runtime_error("unknown wallet client command");
}
#ifndef _WIN32
using Clock = std::chrono::steady_clock;
struct Deadline {
    Clock::time_point end;
    explicit Deadline(uint64_t ms)
        : end(Clock::now() + std::chrono::milliseconds(ms)) {}
    int Remaining() const {
        const auto left = end - Clock::now();
        if (left <= Clock::duration::zero()) return 0;
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(left).count();
        return int(std::min<int64_t>(INT_MAX, ms + 1));
    }
};
void Wait(int fd, short events, const Deadline &deadline) {
    while (true) {
        const int timeout = deadline.Remaining();
        Require(timeout > 0, "wallet client I/O deadline");
        pollfd item{fd, events, 0};
        const int result = poll(&item, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        Require(result > 0, "wallet client I/O deadline or poll failure");
        Require(!(item.revents & (POLLNVAL | POLLERR)),
                "wallet client FD failure");
        // Read HUP can carry a final response/EOF. Writable HUP is terminal.
        Require((item.revents & events) ||
                    ((events & POLLIN) && (item.revents & POLLHUP)),
                "wallet client FD closed");
        return;
    }
}
void Nonblocking(int fd) {
    const int flags = fcntl(fd, F_GETFL);
    Require(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0,
            "wallet client FD setup failed");
}
// Standard streams are borrowed from the controller. Their open file
// descriptions can be shared across processes, so restore every original flag
// on success and on exceptions before returning control to the caller.
class ScopedNonblocking {
public:
    explicit ScopedNonblocking(int fd) : fd_(fd), flags_(fcntl(fd, F_GETFL)) {
        Require(flags_ >= 0 && fcntl(fd_, F_SETFL, flags_ | O_NONBLOCK) >= 0,
                "wallet client FD setup failed");
    }
    ScopedNonblocking(const ScopedNonblocking &) = delete;
    ScopedNonblocking &operator=(const ScopedNonblocking &) = delete;
    ~ScopedNonblocking() {
        while (fcntl(fd_, F_SETFL, flags_) < 0 && errno == EINTR) {}
    }
private:
    const int fd_;
    const int flags_;
};
void NodeSocket(int fd) {
    int type = 0;
    socklen_t length = sizeof(type);
    Require(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
                type == SOCK_STREAM,
            "private node FD must be a connected stream socket");
    sockaddr_storage local{}, peer{};
    length = sizeof(local);
    Require(getsockname(fd, reinterpret_cast<sockaddr *>(&local), &length) ==
                    0 &&
                local.ss_family == AF_UNIX,
            "node FD must be a private Unix socketpair endpoint");
    length = sizeof(peer);
    Require(getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &length) ==
                    0 &&
                peer.ss_family == AF_UNIX,
            "node FD is not connected");
#ifdef SO_NOSIGPIPE
    const int enabled = 1;
    Require(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                       sizeof(enabled)) == 0,
            "node FD signal setup failed");
#endif
    Nonblocking(fd);
}
void Write(int fd, std::string_view bytes, const Deadline &deadline,
           bool socket = false) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        Wait(fd, POLLOUT, deadline);
        ssize_t n;
        if (socket) {
            int flags = MSG_DONTWAIT;
#ifdef MSG_NOSIGNAL
            flags |= MSG_NOSIGNAL;
#endif
            n = send(fd, bytes.data() + offset, bytes.size() - offset, flags);
        } else
            n = write(fd, bytes.data() + offset, bytes.size() - offset);
        if (n < 0 &&
            (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        Require(n > 0, "wallet client FD write failed");
        offset += size_t(n);
    }
}
std::string PublicRequest(const Deadline &deadline) {
    std::string input;
    std::array<char, 4096> chunk{};
    const ScopedNonblocking nonblocking(STDIN_FILENO);
    while (true) {
        Wait(STDIN_FILENO, POLLIN, deadline);
        const auto n = read(
            STDIN_FILENO, chunk.data(),
            std::min(chunk.size(), PUBLIC_REQUEST_LIMIT + 1 - input.size()));
        if (n < 0 &&
            (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        Require(n >= 0, "public request read failed");
        if (!n) break;
        Require(size_t(n) <= PUBLIC_REQUEST_LIMIT - input.size(),
                "public request exceeds capacity");
        input.append(chunk.data(), size_t(n));
    }
    return input;
}
struct Secret {
    SecureString bytes;
    ~Secret() {
        if (!bytes.empty()) memory_cleanse(bytes.data(), bytes.size());
    }
};
void Passphrase(int fd, const Deadline &deadline, Secret &secret) {
    Require(isatty(fd) == 0, "private passphrase FD must not be a terminal");
    Nonblocking(fd);
    secret.bytes.reserve(PASSPHRASE_LIMIT);
    // Secure allocator handles growth/free; the temporary chunk is cleansed
    // on every read, including exceptions and the over-cap byte.
    struct Chunk {
        std::array<char, 256> bytes{};
        ~Chunk() { memory_cleanse(bytes.data(), bytes.size()); }
    } chunk;
    while (true) {
        Wait(fd, POLLIN, deadline);
        const auto n =
            read(fd, chunk.bytes.data(),
                 std::min(chunk.bytes.size(),
                          PASSPHRASE_LIMIT + 1 - secret.bytes.size()));
        if (n < 0 &&
            (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        Require(n >= 0, "private passphrase read failed");
        if (!n) break;
        Require(size_t(n) <= PASSPHRASE_LIMIT - secret.bytes.size(),
                "private passphrase exceeds capacity");
        secret.bytes.append(chunk.bytes.data(), size_t(n));
        memory_cleanse(chunk.bytes.data(), chunk.bytes.size());
    }
    Require(!secret.bytes.empty(), "nonempty passphrase required");
}
class NodeChannel {
    int fd_;
    const Deadline &deadline_;
    bool busy_ = false, broken_ = false;

public:
    NodeChannel(int fd, const Deadline &deadline)
        : fd_(fd), deadline_(deadline) {
        NodeSocket(fd);
    }
    bool Exchange(std::string_view request, std::string &response,
                  std::string &error) {
        if (busy_ || broken_) {
            error = "private node channel unavailable";
            return false;
        }
        struct Busy {
            bool &flag;
            explicit Busy(bool &v) : flag(v) { flag = true; }
            ~Busy() { flag = false; }
        } busy(busy_);
        try {
            Require(!request.empty() &&
                        request.size() <= NODE_WALLET_REQUEST_LIMIT &&
                        request.back() == '\n' &&
                        request.find('\n') == request.size() - 1,
                    "invalid private node request frame");
            UniValue outgoing;
            Require(outgoing.read(std::string(request)),
                    "invalid private node request JSON");
            const auto command = outgoing["command"].get_str();
            if (command == "walletcontext") Keys(outgoing, {"id", "command", "tip", "outpoint"});
            else if (command == "submittransaction") Keys(outgoing, {"id", "command", "wire", "expected_tip"});
            else if (command == "transactionstatus") Keys(outgoing, {"id", "command", "txid", "txhash", "wire"});
            else throw std::runtime_error("private node command not allowed");
            Require(outgoing["id"].isStr() &&
                        !outgoing["id"].get_str().empty() &&
                        outgoing["id"].get_str().size() <= 64 &&
                        (command == "walletcontext" || command == "submittransaction" || command == "transactionstatus"),
                    "private node request identity");
            const auto id = outgoing["id"].get_str();
            Write(fd_, request, deadline_, true);
            std::string line;
            std::array<char, 4096> chunk{};
            while (true) {
                Wait(fd_, POLLIN, deadline_);
                const auto n =
                    recv(fd_, chunk.data(),
                         std::min(chunk.size(),
                                  NODE_WALLET_RESPONSE_LIMIT + 1 - line.size()),
                         MSG_DONTWAIT);
                if (n < 0 &&
                    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                    continue;
                Require(n > 0, "private node response EOF/read failure");
                Require(size_t(n) <= NODE_WALLET_RESPONSE_LIMIT - line.size(),
                        "private node response exceeds capacity");
                line.append(chunk.data(), size_t(n));
                const auto newline = line.find('\n');
                if (newline == std::string::npos) continue;
                Require(newline + 1 == line.size(),
                        "private node channel must return exactly one JSONL "
                        "response");
                UniValue incoming;
                Require(incoming.read(line) && incoming.isObject(),
                        "invalid private node response JSON");
                Require(std::count(incoming.getKeys().begin(),
                                   incoming.getKeys().end(), "id") == 1 &&
                            incoming["id"].isStr() &&
                            incoming["id"].get_str() == id &&
                            incoming["ok"].isBool(),
                        "private node response ID/event mismatch");
                response = std::move(line);
                error.clear();
                return true;
            }
        } catch (const std::exception &failure) {
            broken_ = true;
            error = failure.what();
            return false;
        }
    }
};
#endif
#ifndef _WIN32
bool SameFdObject(int a, int b) {
    struct stat x{}, y{};
    Require(fstat(a, &x) == 0 && fstat(b, &y) == 0,
            "wallet client FD is unavailable");
    return x.st_dev == y.st_dev && x.st_ino == y.st_ino;
}
void Channels(const Options &options) {
    for (int fd = 0; fd <= 2; ++fd)
        Require(!SameFdObject(options.node, fd),
                "node FD aliases a public channel");
    if (options.passphrase >= 0) {
        for (int fd = 0; fd <= 2; ++fd)
            Require(!SameFdObject(options.passphrase, fd),
                    "passphrase FD aliases a public channel");
        Require(!SameFdObject(options.passphrase, options.node),
                "passphrase FD aliases node channel");
    }
}
struct Fds {
    int node, secret;
    ~Fds() {
        if (secret >= 0) close(secret);
        if (node >= 0) close(node);
    }
};
void SubmissionFields(UniValue &answer, const Submission &receipt) {
    answer.pushKV("submission", receipt.result);
    UniValue missing(UniValue::VARR);
    for (const auto &point : receipt.missing) {
        UniValue item(UniValue::VOBJ);
        item.pushKV("txid", Hex(point.tx_id));
        item.pushKV("index", uint64_t(point.index));
        missing.push_back(item);
    }
    answer.pushKV("missing", missing);
}
UniValue Run(const Options &options, const Deadline &deadline,
             bool &sign_outcome_ambiguous) {
    Channels(options);
    Fds fds{options.node, options.passphrase};
    NodeChannel channel(options.node, deadline);
    UniValue request;
    Require(request.read(PublicRequest(deadline)),
            "one public JSON object required");
    RequestShape(options.command, request);
    DevelopmentManifest manifest;
    std::string error;
    Require(LoadDevelopmentManifest(options.manifest, manifest, error),
            "development manifest could not be parsed");
    ChainProfile profile{manifest.hp, manifest.op, manifest.mp, manifest.cp};
    NodePaymentChainProvider provider(profile, [&](std::string_view bytes,
                                                   std::string &response,
                                                   std::string &failure) {
        return channel.Exchange(bytes, response, failure);
    });
    std::unique_ptr<Wallet> wallet;
    UniValue answer(UniValue::VOBJ);
    Result result = Result::Success;
    const auto path = fs::PathFromString(options.home);
    if (options.command == "create") {
        Secret passphrase;
        Passphrase(options.passphrase, deadline, passphrase);
        Require(Wallet::Create(path, profile.Binding(), passphrase.bytes,
                               wallet, error),
                "encrypted wallet creation failed");
        answer.pushKV("public_key", Hex(wallet->PublicKey()));
    } else {
        Require(Wallet::Open(path, profile.Binding(), wallet, error),
                "encrypted wallet open failed");
        if (options.command == "info") {
            answer.pushKV("public_key", Hex(wallet->PublicKey()));
            answer.pushKV("chain_id", Hex(wallet->Binding().chain_id));
            answer.pushKV("genesis_id", Hex(wallet->Binding().genesis_id));
            answer.pushKV("profile_digest",
                          Hex(wallet->Binding().validation_digest));
            Output output;
            std::string unused;
            const bool registered = wallet->PaymentOutput(0, output, unused);
            answer.pushKV("payment_policy_registered", registered);
            if (registered) {
                answer.pushKV("payment_output", OutputJson(output));
                std::vector<uint8_t> encoded;
                Require(EncodeOutput(output, encoded, unused),
                        "registered Payment output encoding failed");
                answer.pushKV("payment_output_hex", Hex(encoded));
            }
        } else if (options.command == "register") {
            const auto script = Bytes(request["script"]);
            Require(request["proof"].isArray() && request["proof"].size() == 0,
                    "Payment proof must be empty");
            Require(BranchLeaf(script) == HashValue(request["root"]),
                    "Payment root mismatch");
            if (!wallet->RegisterPayment(script, {}, error))
                result = Result::Invalid;
            else
                answer.pushKV("policy_root", Hex(BranchLeaf(script)));
        } else if (options.command == "track") {
            result = PaymentEngine::TrackFunding(
                *wallet, profile, provider,
                {HashValue(request["prev_txid"]),
                 uint32_t(Index(request["prev_index"], UINT32_MAX))},
                error);
        } else if (options.command == "broadcast") {
            Submission receipt;
            result = PaymentEngine::Broadcast(*wallet, profile, provider,
                                              HashValue(request["txid"]), receipt, error);
            if (result == Result::Success) {
                SubmissionFields(answer, receipt);
                answer.pushKV("txid", Hex(receipt.txid));
                answer.pushKV("txhash", Hex(receipt.txhash));
            }
        } else if (options.command == "status") {
            TransactionState state;
            result = PaymentEngine::Status(*wallet, profile, provider,
                                           HashValue(request["txid"]), state, error);
            if (result == Result::Success) {
                answer.pushKV("state", state.state);
                answer.pushKV("txid", Hex(state.txid));
                answer.pushKV("txhash", Hex(state.txhash));
                if (state.state == "confirmed") {
                    answer.pushKV("block_id", Hex(state.confirmation_block));
                    answer.pushKV("height", std::to_string(state.confirmation_height));
                }
            }
        } else if (options.command == "abandon") {
            if (!wallet->Abandon(HashValue(request["txid"]), error))
                result = Result::Invalid;
        } else if (options.command == "pending") {
            std::vector<V2Hash> ids;
            if (!wallet->ListOutgoing(ids, error))
                result = Result::StorageError;
            else {
                UniValue pending(UniValue::VARR);
                for (const auto &id : ids)
                    pending.push_back(Hex(id));
                answer.pushKV("pending", pending);
            }
        } else if (options.command == "export") {
            const auto txid = HashValue(request["txid"]);
            const auto cap = Index(request["max_bytes"], 1 << 20);
            Require(cap > 0, "positive export byte cap required");
            std::vector<uint8_t> wire;
            if (!wallet->ExportOutgoing(txid, size_t(cap), wire, error))
                result = Result::Invalid;
            else {
                Transaction tx;
                std::vector<uint8_t> canonical;
                IdentityDigests identities;
                if (!DecodeTransaction(wire, profile.ordinary.transaction, tx,
                                       error) ||
                    !EncodeTransaction(tx, profile.ordinary.transaction,
                                       canonical, error) ||
                    canonical != wire ||
                    !ComputeIdentities(tx, profile.ordinary.transaction,
                                       profile.header.chain_id, identities,
                                       error) ||
                    identities.txid != txid) {
                    result = Result::StorageError;
                    error = "persisted outgoing transaction identity mismatch";
                } else {
                    answer.pushKV("wire", Hex(wire));
                    answer.pushKV("txid", Hex(identities.txid));
                    answer.pushKV("txhash", Hex(identities.txhash));
                }
            }
        } else if (options.command == "reconcile") {
            Reconciled state;
            result = PaymentEngine::Reconcile(*wallet, profile, provider, state,
                                              error);
            if (result == Result::Success) {
                answer.pushKV("tip", Hex(state.chain.tip));
                answer.pushKV("utxo_root", Hex(state.chain.root));
                answer.pushKV("height", std::to_string(state.chain.height));
                answer.pushKV("parent_mtp",
                              std::to_string(state.chain.parent_mtp));
                UniValue coins(UniValue::VARR);
                for (const auto &coin : state.coins) {
                    UniValue item(UniValue::VOBJ);
                    item.pushKV("prev_txid", Hex(coin.outpoint.tx_id));
                    item.pushKV("prev_index",
                                std::to_string(coin.outpoint.index));
                    item.pushKV("present", coin.present);
                    item.pushKV("reserved", coin.reserved);
                    item.pushKV("mature", coin.mature);
                    item.pushKV("value", std::to_string(coin.value));
                    coins.push_back(item);
                }
                answer.pushKV("coins", coins);
            }
        } else {
            const auto recipient = Recipient(request["recipient"]);
            const auto fee = Amount(request["fee"]);
            PaymentPlan plan;
            result = PaymentEngine::Prepare(*wallet, profile, provider,
                                            recipient, fee, plan, error);
            if (result == Result::Success) {
                if (options.command == "prepare") {
                    std::vector<uint8_t> wire;
                    if (!EncodeTransaction(plan.UnsignedTransaction(),
                                           profile.ordinary.transaction, wire,
                                           error))
                        result = Result::Invalid;
                    else {
                        answer.pushKV("unsigned_wire", Hex(wire));
                        answer.pushKV("tip", Hex(plan.Anchor().tip));
                        answer.pushKV("utxo_root", Hex(plan.Anchor().root));
                        answer.pushKV("height",
                                      std::to_string(plan.Anchor().height));
                        answer.pushKV("parent_mtp",
                                      std::to_string(plan.Anchor().parent_mtp));
                        answer.pushKV("fee", std::to_string(plan.Fee()));
                    }
                } else {
                    Secret passphrase;
                    Passphrase(options.passphrase, deadline, passphrase);
                    if (!wallet->Unlock(passphrase.bytes, error))
                        result = Result::Locked;
                    else {
                        struct Lock {
                            Wallet &wallet;
                            ~Lock() { wallet.Lock(); }
                        } lock{*wallet};
                        ExportedPayment payment;
                        // A thrown/StorageError result may follow SQLite's
                        // durable commit; never describe it as known unsigned.
                        sign_outcome_ambiguous = true;
                        result = PaymentEngine::SignAndReserve(
                            *wallet, profile, provider, plan, payment, error);
                        if (result != Result::Success &&
                            result != Result::StorageError)
                            sign_outcome_ambiguous = false;
                        if (result == Result::Success) {
                            answer.pushKV("wire", Hex(payment.wire));
                            answer.pushKV("txid", Hex(payment.txid));
                            answer.pushKV("txhash", Hex(payment.txhash));
                            answer.pushKV("digest", Hex(payment.digest));
                            if (options.command == "pay") {
                                Submission receipt;
                                result = PaymentEngine::Broadcast(*wallet, profile, provider,
                                                                  payment.txid, receipt, error);
                                if (result == Result::Success)
                                    SubmissionFields(answer, receipt);
                            }
                        }
                    }
                }
            }
        }
    }
    wallet->Lock();
    answer.pushKV("result",
                  result == Result::StorageError && sign_outcome_ambiguous
                      ? "outcome_unknown"
                      : Name(result));
    if (!error.empty()) {
        if (error.size() > 1024) error.resize(1024);
        answer.pushKV("error", error);
    }
    Require(answer.write().size() + 1 <= PUBLIC_RESPONSE_LIMIT,
            "public result exceeds local capacity");
    return answer;
}
#endif
} // namespace
int main(int argc, char **argv) {
#ifdef _WIN32
    (void)argc;
    (void)argv;
    std::cout << "{\"result\":\"setup_error\",\"error\":\"private FD wallet "
                 "client is unavailable on this platform\"}\n";
    return 1;
#else
    // A parse/setup error still has a finite output deadline. A valid explicit
    // --timeout-ms replaces this operational fallback before any wallet access.
    Deadline deadline(1000);
    UniValue answer(UniValue::VOBJ);
    int code = 1;
    bool ecc = false, sign_outcome_ambiguous = false;
    try {
        Require(std::signal(SIGPIPE, SIG_IGN) != SIG_ERR,
                "wallet client signal setup failed");
        const auto options = Arguments(argc, argv);
        deadline = Deadline(options.timeout);
        RandomInit();
        ECC_Start();
        ecc = true;
        answer = Run(options, deadline, sign_outcome_ambiguous);
        const auto status = answer["result"].get_str();
        code = status == "success"           ? 0
               : status == "outcome_unknown" ? 5
               : status == "storage_error"   ? 4
                                             : 2;
    } catch (const std::exception &failure) {
        answer = UniValue(UniValue::VOBJ);
        answer.pushKV("result", sign_outcome_ambiguous ? "outcome_unknown"
                                                       : "setup_error");
        std::string error =
            sign_outcome_ambiguous
                ? "signing may have persisted; recover via pending/export"
                : failure.what();
        if (error.size() > 1024) error.resize(1024);
        answer.pushKV("error", error);
        code = sign_outcome_ambiguous ? 5 : 1;
    }
    if (ecc) ECC_Stop();
    // No second JSON/error is emitted if output fails after a signed payment
    // was durably reserved. The controller must treat a lost result as unknown
    // and recover via pending/export, never infer that signing did not happen.
    try {
        const ScopedNonblocking nonblocking(STDOUT_FILENO);
        Write(STDOUT_FILENO, answer.write() + "\n", deadline);
    } catch (...) {
        return sign_outcome_ambiguous ? 5 : 4;
    }
    return code;
#endif
}
