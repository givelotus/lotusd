// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrdb.h>

#include <addrman.h>
#include <chainparams.h>
#include <clientversion.h>
#include <common/args.h>
#include <hash.h>
#include <logging.h>
#include <logging/timer.h>
#include <netbase.h>
#include <random.h>
#include <streams.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/settings.h>
#include <util/translation.h>

#include <cstdint>

static const char *BANMAN_JSON_VERSION_KEY{"version"};

CBanEntry::CBanEntry(const UniValue &json)
    : nVersion(json[BANMAN_JSON_VERSION_KEY].getInt<int>()),
      nCreateTime(json["ban_created"].getInt<int64_t>()),
      nBanUntil(json["banned_until"].getInt<int64_t>()) {}

UniValue CBanEntry::ToJson() const {
    UniValue json(UniValue::VOBJ);
    json.pushKV(BANMAN_JSON_VERSION_KEY, nVersion);
    json.pushKV("ban_created", nCreateTime);
    json.pushKV("banned_until", nBanUntil);
    return json;
}

namespace {

static const char *BANMAN_JSON_ADDR_KEY = "address";

/**
 * Convert a `banmap_t` object to a JSON array.
 * @param[in] bans Bans list to convert.
 * @return a JSON array, similar to the one returned by the `listbanned` RPC.
 *     Suitable for passing to `BanMapFromJson()`.
 */
UniValue BanMapToJson(const banmap_t &bans) {
    UniValue bans_json(UniValue::VARR);
    for (const auto &it : bans) {
        const auto &address = it.first;
        const auto &ban_entry = it.second;
        UniValue j = ban_entry.ToJson();
        j.pushKV(BANMAN_JSON_ADDR_KEY, address.ToString());
        bans_json.push_back(j);
    }
    return bans_json;
}

/**
 * Convert a JSON array to a `banmap_t` object.
 * @param[in] bans_json JSON to convert, must be as returned by
 *     `BanMapToJson()`.
 * @param[out] bans Bans list to create from the JSON.
 * @throws std::runtime_error if the JSON does not have the expected fields or
 *     they contain unparsable values.
 */
void BanMapFromJson(const UniValue &bans_json, banmap_t &bans) {
    for (const auto &ban_entry_json : bans_json.getValues()) {
        const int version{
            ban_entry_json[BANMAN_JSON_VERSION_KEY].getInt<int>()};
        if (version != CBanEntry::CURRENT_VERSION) {
            LogInfoEvent(
                BCLog::ALL, "ban_database_entry_version_unsupported",
                "Dropping entry with unknown version ({version}) from ban list")
                .Field(BCLog::LogField::Version, version);
            continue;
        }
        CSubNet subnet;
        const auto &subnet_str = ban_entry_json[BANMAN_JSON_ADDR_KEY].get_str();
        if (!LookupSubNet(subnet_str, subnet)) {
            LogInfoEvent(
                BCLog::ALL, "ban_database_entry_subnet_invalid",
                "Dropping entry with unparseable address or subnet ({subnet}) from ban list")
                .Field(BCLog::LogField::Subnet, subnet_str);
            continue;
        }
        bans.insert_or_assign(subnet, CBanEntry{ban_entry_json});
    }
}

class DbNotFoundError : public std::exception {
    using std::exception::exception;
};

template <typename Stream, typename Data>
bool SerializeDB(const CChainParams &chainParams, Stream &stream,
                 const Data &data) {
    // Write and commit header, data
    try {
        HashedSourceWriter hashwriter{stream};
        hashwriter << chainParams.DiskMagic() << data;
        stream << hashwriter.GetHash();
    } catch (const std::exception &e) {
        LogErrorEvent(BCLog::ALL, "address_database_serialize_failed",
                      "{source_function}: Serialize or I/O error - {error}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Error, e.what());
        return false;
    }

    return true;
}

template <typename Data>
bool SerializeFileDB(const CChainParams &chainParams, const std::string &prefix,
                     const fs::path &path, const Data &data) {
    // Generate random temporary filename
    const uint16_t randv{FastRandomContext().rand<uint16_t>()};
    std::string tmpfn = strprintf("%s.%04x", prefix, randv);

    // open temp output file
    fs::path pathTmp = gArgs.GetDataDirNet() / tmpfn;
    FILE *file = fsbridge::fopen(pathTmp, "wb");
    AutoFile fileout{file};
    if (fileout.IsNull()) {
        fileout.fclose();
        remove(pathTmp);
        LogErrorEvent(BCLog::ALL, "address_database_open_failed",
                      "{source_function}: Failed to open file {path}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Path, fs::PathToString(pathTmp));
        return false;
    }

    // Serialize
    if (!SerializeDB(chainParams, fileout, data)) {
        fileout.fclose();
        remove(pathTmp);
        return false;
    }
    if (!FileCommit(fileout.Get())) {
        fileout.fclose();
        remove(pathTmp);
        LogErrorEvent(BCLog::ALL, "address_database_flush_failed",
                      "{source_function}: Failed to flush file {path}")
            .Field(BCLog::LogField::SourceFunction, __func__)
            .Field(BCLog::LogField::Path, fs::PathToString(pathTmp));
        return false;
    }
    fileout.fclose();

    // replace existing file, if any, with new file
    if (!RenameOver(pathTmp, path)) {
        remove(pathTmp);
        LogErrorEvent(BCLog::ALL, "address_database_rename_failed",
                      "{source_function}: Rename-into-place failed")
            .Field(BCLog::LogField::SourceFunction, __func__);
        return false;
    }

    return true;
}

template <typename Stream, typename Data>
void DeserializeDB(const CChainParams &chainParams, Stream &stream, Data &&data,
                   bool fCheckSum = true) {
    HashVerifier verifier{stream};
    // de-serialize file header (network specific magic number) and ..
    uint8_t pchMsgTmp[4];
    verifier >> pchMsgTmp;
    // ... verify the network matches ours
    if (memcmp(pchMsgTmp, std::begin(chainParams.DiskMagic()),
               sizeof(pchMsgTmp))) {
        throw std::runtime_error{"Invalid network magic number"};
    }

    // de-serialize data
    verifier >> data;

    // verify checksum
    if (fCheckSum) {
        uint256 hashTmp;
        stream >> hashTmp;
        if (hashTmp != verifier.GetHash()) {
            throw std::runtime_error{"Checksum mismatch, data corrupted"};
        }
    }
}

template <typename Data>
void DeserializeFileDB(const CChainParams &chainParams, const fs::path &path,
                       Data &&data) {
    FILE *file = fsbridge::fopen(path, "rb");
    AutoFile filein{file};
    if (filein.IsNull()) {
        throw DbNotFoundError{};
    }

    DeserializeDB(chainParams, filein, data);
}

} // namespace

CBanDB::CBanDB(fs::path ban_list_path, const CChainParams &_chainParams)
    : m_banlist_dat(ban_list_path + ".dat"),
      m_banlist_json(ban_list_path + ".json"), chainParams(_chainParams) {}

bool CBanDB::Write(const banmap_t &banSet) {
    std::vector<std::string> errors;
    if (util::WriteSettings(m_banlist_json, {{JSON_KEY, BanMapToJson(banSet)}},
                            errors)) {
        return true;
    }

    for (const auto &err : errors) {
        LogErrorEvent(BCLog::ALL, "ban_database_write_failed", "{error}")
            .Field(BCLog::LogField::Error, err);
    }
    return false;
}

bool CBanDB::Read(banmap_t &banSet, bool &dirty) {
    // If the JSON banlist does not exist, then try to read the non-upgraded
    // banlist.dat.
    // TODO: stop supporting banlist.dat after v0.34.0. See:
    //       https://github.com/bitcoin/bitcoin/pull/22570
    if (!fs::exists(m_banlist_json)) {
        // If this succeeds then we need to flush to disk in order to create the
        // JSON banlist.
        dirty = true;
        try {
            DeserializeFileDB(chainParams, m_banlist_dat,
                              WithParams(CAddress::V1_DISK, banSet));
        } catch (const std::exception &) {
            LogInfoEvent(BCLog::ALL, "ban_database_legacy_file_unavailable",
                         "Missing or invalid file {path:fsq}")
                .Field(BCLog::LogField::Path, fs::PathToString(m_banlist_dat));
            return false;
        }
        return true;
    }

    dirty = false;

    std::map<std::string, util::SettingsValue> settings;
    std::vector<std::string> errors;

    if (!util::ReadSettings(m_banlist_json, settings, errors)) {
        for (const auto &err : errors) {
            LogInfoEvent(BCLog::ALL, "ban_database_load_failed",
                         "Cannot load banlist {path}: {error}")
                .Field(BCLog::LogField::Path, fs::PathToString(m_banlist_json))
                .Field(BCLog::LogField::Error, err);
        }
        return false;
    }

    try {
        BanMapFromJson(settings[JSON_KEY], banSet);
    } catch (const std::runtime_error &e) {
        LogInfoEvent(BCLog::ALL, "ban_database_parse_failed",
                     "Cannot parse banlist {path}: {error}")
            .Field(BCLog::LogField::Path, fs::PathToString(m_banlist_json))
            .Field(BCLog::LogField::Error, e.what());
        return false;
    }

    return true;
}

bool DumpPeerAddresses(const CChainParams &chainParams, const ArgsManager &args,
                       const AddrMan &addr) {
    const auto pathAddr = args.GetDataDirNet() / "peers.dat";
    return SerializeFileDB(chainParams, "peers", pathAddr, addr);
}

void ReadFromStream(const CChainParams &chainParams, AddrMan &addr,
                    DataStream &ssPeers) {
    DeserializeDB(chainParams, ssPeers, addr, false);
}

util::Result<std::unique_ptr<AddrMan>>
LoadAddrman(const CChainParams &chainparams, const std::vector<bool> &asmap,
            const ArgsManager &args) {
    auto check_addrman = std::clamp<int32_t>(
        args.GetIntArg("-checkaddrman", DEFAULT_ADDRMAN_CONSISTENCY_CHECKS), 0,
        1000000);
    auto addrman{
        std::make_unique<AddrMan>(asmap, /*deterministic=*/false,
                                  /*consistency_check_ratio=*/check_addrman)};

    int64_t nStart = GetTimeMillis();
    const auto path_addr{args.GetDataDirNet() / "peers.dat"};
    try {
        DeserializeFileDB(chainparams, path_addr, *addrman);
        LogInfoEvent(
            BCLog::ALL, "address_database_loaded",
            "Loaded {count} addresses from peers.dat  {database_operation_ms}ms")
            .Field(BCLog::LogField::Count, addrman->size())
            .Field(BCLog::LogField::DatabaseOperationMs,
                   GetTimeMillis() - nStart);
    } catch (const DbNotFoundError &) {
        // Addrman can be in an inconsistent state after failure, reset it
        addrman = std::make_unique<AddrMan>(
            asmap, /*deterministic=*/false,
            /*consistency_check_ratio=*/check_addrman);
        LogInfoEvent(
            BCLog::ALL, "address_database_file_missing",
            "Creating peers.dat because the file was not found ({path:fsq})")
            .Field(BCLog::LogField::Path, fs::PathToString(path_addr));
        DumpPeerAddresses(chainparams, args, *addrman);
    } catch (const InvalidAddrManVersionError &) {
        if (!RenameOver(path_addr, fs::path(path_addr) + ".bak")) {
            return util::Error{
                strprintf(_("Failed to rename invalid peers.dat file. "
                            "Please move or delete it and try again."))};
        }
        // Addrman can be in an inconsistent state after failure, reset it
        addrman = std::make_unique<AddrMan>(
            asmap, /*deterministic=*/false,
            /*consistency_check_ratio=*/check_addrman);
        LogInfoEvent(
            BCLog::ALL, "address_database_version_unsupported",
            "Creating new peers.dat because the file version was not compatible ({path:fsq}). Original backed up to peers.dat.bak")
            .Field(BCLog::LogField::Path, fs::PathToString(path_addr));
        DumpPeerAddresses(chainparams, args, *addrman);
    } catch (const std::exception &e) {
        return util::Error{strprintf(
            _("Invalid or corrupt peers.dat (%s). If you believe this is a "
              "bug, please report it to %s. As a workaround, you can move the "
              "file (%s) out of the way (rename, move, or delete) to have a "
              "new one created on the next start."),
            e.what(), PACKAGE_BUGREPORT,
            fs::quoted(fs::PathToString(path_addr)))};
    }

    // std::move should be unneccessary but is temporarily needed to work
    // around clang bug
    // (https://github.com/bitcoin/bitcoin/pull/25977#issuecomment-1564350880)
    return {std::move(addrman)};
}

void DumpAnchors(const CChainParams &chainParams,
                 const fs::path &anchors_db_path,
                 const std::vector<CAddress> &anchors) {
    LOG_TIME_SECONDS(strprintf(
        "Flush %d outbound block-relay-only peer addresses to anchors.dat",
        anchors.size()));
    SerializeFileDB(chainParams, "anchors", anchors_db_path,
                    WithParams(CAddress::V2_DISK, anchors));
}

std::vector<CAddress> ReadAnchors(const CChainParams &chainParams,
                                  const fs::path &anchors_db_path) {
    std::vector<CAddress> anchors;
    try {
        DeserializeFileDB(chainParams, anchors_db_path,
                          WithParams(CAddress::V2_DISK, anchors));
        LogInfoEvent(BCLog::ALL, "anchor_database_loaded",
                     "Loaded {count} addresses from {name:fsq}")
            .Field(BCLog::LogField::Count, anchors.size())
            .Field(BCLog::LogField::Name,
                   fs::PathToString(anchors_db_path.filename()));
    } catch (const std::exception &) {
        anchors.clear();
    }

    fs::remove(anchors_db_path);
    return anchors;
}
