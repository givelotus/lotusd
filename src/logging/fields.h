// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_FIELDS_H
#define BITCOIN_LOGGING_FIELDS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

/**
 * The structured log field vocabulary: the only keys a log event can carry.
 *
 * Every field is declared once, here, with its value type, its generic
 * snake_case name (used by text, logfmt, json, json-gcp, and as
 * LOTUS_<NAME> by journald) and its name in the Elastic Common Schema and
 * in the OpenTelemetry semantic conventions where those define one. A
 * field without a standard name is lotus.<name> in ECS and stays an
 * attribute named <name> elsewhere. Call sites name fields through the
 * typed keys in BCLog::LogField (e.g. LogField::PeerId), so a free-form
 * string key does not compile and a new field has to be added here, where
 * reviewers see it. Keys are small integers: a call site stores the id and
 * the value; names are looked up on the logger thread.
 *
 * Core fields (time, level, category, thread, source location, message)
 * are captured by the logger itself and are not in this table.
 *
 * Standard names (ECS 8.11 and OpenTelemetry semantic conventions 1.44;
 * see doc/logging-api.md):
 *  - Addr is a remote peer, not necessarily a network sender. ECS therefore
 *    keeps it custom (lotus.addr) rather than claiming source.address.
 *    It may contain host:port, so OTel keeps it custom too. PeerAddress and
 *    PeerPort map separately to network.peer.address / network.peer.port.
 *  - network.direction: ECS values include "inbound" and "outbound".
 *  - HttpUserAgent is the HTTP header; generic P2P UserAgent stays custom.
 *  - error.message: ECS only; OTel deprecated its generic error.message.
 *  - event.reason: ECS ("reason why this event happened").
 *  - event.duration: ECS, in nanoseconds (encoders convert).
 *  - Path is a full filesystem path (file.path in ECS and OTel).
 *  - Method is a recognized RPC method or _OTHER (OTel rpc.method).
 *    OriginalMethod preserves the raw name (rpc.method_original).
 */
#define BCLOG_FIELDS(X)                                                        \
    /* Id, generic name, type, ECS name, OTel name */                          \
    X(PeerId, peer_id, INT, "", "")                                            \
    X(Addr, addr, STRING, "", "")                                              \
    X(PeerAddress, peer_address, STRING, "", "network.peer.address")           \
    X(PeerPort, peer_port, INT, "", "network.peer.port")                       \
    X(Network, network, STRING, "", "")                                        \
    X(Direction, direction, STRING, "network.direction", "")                   \
    X(Transport, transport, STRING, "", "")                                    \
    X(ConnType, conn_type, STRING, "", "")                                     \
    X(UserAgent, user_agent, STRING, "", "")                                   \
    X(HttpUserAgent, http_user_agent, STRING, "user_agent.original",           \
      "user_agent.original")                                                   \
    X(Version, version, INT, "", "")                                           \
    X(Services, services, STRING, "", "")                                      \
    X(MsgType, msg_type, STRING, "", "")                                       \
    X(BlockHash, block_hash, HASH, "", "")                                     \
    X(Height, height, INT, "", "")                                             \
    X(TxId, txid, HASH, "", "")                                                \
    X(Bytes, bytes, UINT, "", "")                                              \
    X(DroppedLines, dropped_lines, UINT, "", "")                               \
    X(Count, count, UINT, "", "")                                              \
    X(ShortId, short_id, UINT, "", "")                                         \
    X(Peers, peers, UINT, "", "")                                              \
    X(Missing, missing, UINT, "", "")                                          \
    X(AmountSats, amount_sats, INT, "", "")                                    \
    X(Method, method, STRING, "", "rpc.method")                                \
    X(OriginalMethod, original_method, STRING, "", "rpc.method_original")      \
    X(Error, error, STRING, "error.message", "")                               \
    X(Reason, reason, STRING, "event.reason", "")                              \
    X(DurationUs, duration_us, DURATION, "event.duration", "")                 \
    X(Path, path, STRING, "file.path", "file.path")                            \
    X(Wallet, wallet, STRING, "", "")                                          \
    X(Name, name, STRING, "", "")                                              \
    X(Value, value, STRING, "", "")                                            \
    X(RpcUser, rpc_user, STRING, "", "") \
    X(DatabaseVersion, database_version, STRING, "", "")                       \
    X(ErrorCode, error_code, INT, "", "") \
    X(FeeRate, fee_rate, STRING, "", "") \
    X(ElapsedMs, elapsed_ms, FLOAT, "", "") \
    X(LogPrefix, log_prefix, STRING, "", "") \
    X(SourceFunction, source_function, STRING, "", "") \
    X(Log2Work, log2_work, FLOAT, "", "") \
    X(ChainTxCount, chain_tx_count, UINT, "", "") \
    X(BlockTime, block_time, STRING, "", "") \
    X(BlockTimeSeconds, block_time_seconds, INT, "", "") \
    X(VerificationProgress, verification_progress, FLOAT, "", "") \
    X(UTXOCacheMiB, utxo_cache_mib, FLOAT, "", "") \
    X(UTXOCacheCoins, utxo_cache_coins, UINT, "", "") \
    X(UTXOCacheBytes, utxo_cache_bytes, UINT, "", "") \
    X(ChainstateRole, chainstate_role, STRING, "", "") \
    X(VerificationDepth, verification_depth, INT, "", "") \
    X(VerificationLevel, verification_level, INT, "", "") \
    X(ProgressPercent, progress_percent, INT, "", "") \
    X(TriggerOption, trigger_option, STRING, "", "") \
    X(ConfigOption, config_option, STRING, "", "") \
    X(ConfigEnabled, config_enabled, BOOL, "", "") \
    X(ForkBaseHeight, fork_base_height, INT, "", "") \
    X(ForkBaseHash, fork_base_hash, HASH, "", "") \
    X(ForkTipHeight, fork_tip_height, INT, "", "") \
    X(ForkTipHash, fork_tip_hash, HASH, "", "") \
    X(HeaderProgressPercent, header_progress_percent, FLOAT, "", "") \
    X(ReceivedTimeDifferenceSeconds, received_time_difference_seconds, UINT, "", "") \
    X(MempoolImportSucceededCount, mempool_import_succeeded_count, UINT, "", "") \
    X(MempoolImportFailedCount, mempool_import_failed_count, UINT, "", "") \
    X(MempoolImportExpiredCount, mempool_import_expired_count, UINT, "", "") \
    X(MempoolImportPresentCount, mempool_import_present_count, UINT, "", "") \
    X(MempoolImportWaitingBroadcastCount, mempool_import_waiting_broadcast_count, UINT, "", "") \
    X(MempoolCopySeconds, mempool_copy_seconds, FLOAT, "", "") \
    X(MempoolDumpSeconds, mempool_dump_seconds, FLOAT, "", "") \
    X(DatabaseCacheMiB, database_cache_mib, FLOAT, "", "") \
    X(UnusedMempoolCacheMiB, unused_mempool_cache_mib, FLOAT, "", "") \
    X(Subnet, subnet, STRING, "", "") \
    X(DatabaseOperationMs, database_operation_ms, INT, "", "") \
    X(MaxOpenFiles, max_open_files, INT, "", "") \
    X(DefaultOpenFiles, default_open_files, INT, "", "") \
    X(ObfuscationKey, obfuscation_key, STRING, "", "") \
    X(ConfigSectionPrefix, config_section_prefix, STRING, "", "") \
    X(LostNewAddressCount, lost_new_address_count, INT, "", "") \
    X(LostTriedAddressCount, lost_tried_address_count, INT, "", "") \
    X(NewBucketIndex, new_bucket_index, INT, "", "") \
    X(NewBucketPosition, new_bucket_position, INT, "", "") \
    X(TriedBucketIndex, tried_bucket_index, INT, "", "") \
    X(TriedBucketPosition, tried_bucket_position, INT, "", "") \
    X(MappedAS, mapped_as, UINT, "", "") \
    X(ExistingAddr, existing_addr, STRING, "", "") \
    X(CandidateCount, candidate_count, UINT, "", "") \
    X(TriedAddressCount, tried_address_count, INT, "", "") \
    X(NewAddressCount, new_address_count, INT, "", "") \
    X(BestBlockHash, best_block_hash, HASH, "", "") \
    X(FileNumber, file_number, INT, "", "") \
    X(ExpectedBlockHash, expected_block_hash, HASH, "", "") \
    X(DatabaseKeyPrefix, database_key_prefix, STRING, "", "") \
    X(IndexStartHeight, index_start_height, INT, "", "") \
    X(IndexStopHeight, index_stop_height, INT, "", "") \
    X(MessageText, message_text, STRING, "", "") \
    X(Caption, caption, STRING, "", "") \
    X(Directory, directory, STRING, "", "") \
    X(StartupTime, startup_time, STRING, "", "") \
    X(ChainstateDescription, chainstate_description, STRING, "", "") \
    X(MinimumChainWorkHex, minimum_chain_work_hex, STRING, "", "") \
    X(ExpectedMinimumChainWorkHex, expected_minimum_chain_work_hex, STRING, "", "") \
    X(PruneTargetMiB, prune_target_mib, UINT, "", "") \
    X(ASMapLengthBytes, asmap_length_bytes, INT, "", "") \
    X(ASMapHash, asmap_hash, HASH, "", "") \
    X(FileOffset, file_offset, UINT, "", "") \
    X(RequestedConnectionLimit, requested_connection_limit, INT, "", "") \
    X(ConnectionLimit, connection_limit, INT, "", "") \
    X(FileDescriptorLimit, file_descriptor_limit, INT, "", "") \
    X(DataDirectoryArgument, data_directory_argument, STRING, "", "") \
    X(InputIndex, input_index, UINT, "", "") \
    X(TxHash, tx_hash, HASH, "", "") \
    X(CacheAllocatedMiB, cache_allocated_mib, UINT, "", "") \
    X(CacheRequestedMiB, cache_requested_mib, UINT, "", "") \
    X(CacheCapacity, cache_capacity, UINT, "", "") \
    X(CacheSizeBytes, cache_size_bytes, INT, "", "") \
    X(CacheBudgetBytes, cache_budget_bytes, INT, "", "") \
    X(CoinsTipCacheBudgetMiB, coins_tip_cache_budget_mib, FLOAT, "", "") \
    X(BugReportURL, bug_report_url, STRING, "", "") \
    X(ExpectedChainTxCount, expected_chain_tx_count, UINT, "", "") \
    X(SHA256Implementation, sha256_implementation, STRING, "", "") \
    X(ScriptWorkerThreads, script_worker_threads, INT, "", "") \
    X(SourcePath, source_path, STRING, "", "") \
    X(DestinationPath, destination_path, STRING, "", "") \
    X(CertificateAction, certificate_action, STRING, "", "") \
    X(CertificatePath, certificate_path, STRING, "", "") \
    X(KeyPath, key_path, STRING, "", "") \
    X(ServerName, server_name, STRING, "", "") \
    X(CertificateValidityDays, certificate_validity_days, INT, "", "") \
    X(ListenAddress, listen_address, STRING, "", "") \
    X(ListenPort, listen_port, INT, "", "") \
    X(PublicPrefixes, public_prefixes, STRING, "", "") \
    X(HttpPath, http_path, STRING, "", "") \
    X(CoroutineWorkerThreads, coroutine_worker_threads, INT, "", "") \
    X(IOThreads, io_threads, INT, "", "") \
    X(ListenerKind, listener_kind, STRING, "", "") \
    X(BlockFileInfo, block_file_info, STRING, "", "") \
    X(FileBlocks, file_blocks, UINT, "", "") \
    X(BlockFileBytes, block_file_bytes, UINT, "", "") \
    X(UndoFileBytes, undo_file_bytes, UINT, "", "") \
    X(FileFirstHeight, file_first_height, UINT, "", "") \
    X(FileLastHeight, file_last_height, UINT, "", "") \
    X(FileFirstTimeSeconds, file_first_time_seconds, UINT, "", "") \
    X(FileLastTimeSeconds, file_last_time_seconds, UINT, "", "") \
    X(LocalScore, local_score, INT, "", "") \
    X(InflightState, inflight_state, STRING, "", "") \
    X(InflightBytes, inflight_bytes, UINT, "", "") \
    X(InflightLimitBytes, inflight_limit_bytes, UINT, "", "") \
    X(WaitSeconds, wait_seconds, INT, "", "") \
    X(NetworkActive, network_active, BOOL, "", "") \
    X(WaitMilliseconds, wait_milliseconds, INT, "", "") \
    X(SocketDescriptor, socket_descriptor, UINT, "", "") \
    X(SnapshotCoinsProcessed, snapshot_coins_processed, INT, "", "") \
    X(ExpectedSnapshotHash, expected_snapshot_hash, HASH, "", "") \
    X(SnapshotHash, snapshot_hash, HASH, "", "") \
    X(BlockIndexDescription, block_index_description, STRING, "", "") \
    X(SnapshotCacheMB, snapshot_cache_mb, UINT, "", "") \
    X(SnapshotProgressPercent, snapshot_progress_percent, FLOAT, "", "") \
    X(ImportedBlockCount, imported_block_count, INT, "", "") \
    X(ElapsedMilliseconds, elapsed_milliseconds, INT, "", "") \
    X(ClientName, client_name, STRING, "", "") \
    X(ClientVersion, client_version, STRING, "", "") \
    X(SigChecks, sig_checks, UINT, "", "")

namespace BCLog {

/** How a field's value is stored and rendered */
enum class FieldType : uint8_t {
    //! Signed integer (JSON number)
    INT,
    //! Unsigned integer (JSON number)
    UINT,
    //! Floating point (JSON number)
    FLOAT,
    //! true/false
    BOOL,
    //! Text (JSON string); also values rendered as text (addresses...)
    STRING,
    //! 256-bit hash, rendered as 64 lowercase hex digits (as in RPC)
    HASH,
    //! A duration; the generic unit is microseconds (JSON number)
    DURATION,
};

enum class FieldId : uint16_t {
#define BCLOG_FIELD_ID(id, name, type, ecs, otel) id,
    BCLOG_FIELDS(BCLOG_FIELD_ID)
#undef BCLOG_FIELD_ID
        COUNT
};

struct FieldInfo {
    //! Generic snake_case name
    std::string_view name;
    FieldType type;
    //! ECS name, or "" (then lotus.<name>)
    std::string_view ecs;
    //! OpenTelemetry semantic convention name, or "" (then <name>)
    std::string_view otel;
};

inline constexpr std::array<FieldInfo, size_t(FieldId::COUNT)> FIELDS{{
#define BCLOG_FIELD_INFO(id, name, type, ecs, otel)                            \
    FieldInfo{#name, FieldType::type, ecs, otel},
    BCLOG_FIELDS(BCLOG_FIELD_INFO)
#undef BCLOG_FIELD_INFO
}};

inline constexpr const FieldInfo &GetFieldInfo(FieldId id) {
    return FIELDS[size_t(id)];
}

/** A typed key: the only way to name a field at a call site */
template <FieldType T> struct FieldKey {
    const FieldId id;
    consteval explicit FieldKey(FieldId value) : id{value} {
        if (size_t(value) >= FIELDS.size() || GetFieldInfo(value).type != T) {
            throw "Invalid typed log field key";
        }
    }
};

/** The keys, e.g. LogField::PeerId */
namespace LogField {
#define BCLOG_FIELD_KEY(id, name, type, ecs, otel)                             \
    inline constexpr FieldKey<FieldType::type> id{FieldId::id};
    BCLOG_FIELDS(BCLOG_FIELD_KEY)
#undef BCLOG_FIELD_KEY
} // namespace LogField

} // namespace BCLog

#endif // BITCOIN_LOGGING_FIELDS_H
