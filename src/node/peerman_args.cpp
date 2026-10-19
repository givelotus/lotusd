#include <node/peerman_args.h>

#include <common/args.h>
#include <net_processing.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <limits>

namespace node {

void ApplyArgsManOptions(const ArgsManager &argsman,
                         PeerManager::Options &options) {
    if (auto value{argsman.GetIntArg("-maxorphantx")}) {
        options.max_orphan_txs = uint32_t(std::clamp<int64_t>(
            *value, 0, std::numeric_limits<uint32_t>::max()));
    }

    if (auto value{argsman.GetIntArg("-blockreconstructionextratxn")}) {
        options.max_extra_txs = uint32_t(std::clamp<int64_t>(
            *value, 0, std::numeric_limits<uint32_t>::max()));
    }

    if (auto value{argsman.GetBoolArg("-capturemessages")}) {
        options.capture_messages = *value;
    }

    if (auto value{argsman.GetBoolArg("-blocksonly")}) {
        options.ignore_incoming_txs = *value;
    }

    if (auto value{argsman.GetIntArg("-maxaddrtosend")}) {
        options.max_addr_to_send = size_t(std::max(int64_t{0}, *value));
    }

    if (auto value{argsman.GetIntArg("-blockmessagecache")}) {
        options.block_message_cache_bytes =
            size_t(std::clamp<int64_t>(*value, 0, 65536)) << 20;
    }

    if (auto value{argsman.GetIntArg("-txrelaytick")}) {
        options.txrelay_tick = std::chrono::milliseconds{
            std::clamp<int64_t>(*value, count_milliseconds(MIN_TXRELAY_TICK),
                                count_milliseconds(MAX_TXRELAY_TICK))};
    }

    if (auto value{argsman.GetIntArg("-txrelayfanoutmin")}) {
        options.txrelay_fanout_min =
            size_t(std::clamp<int64_t>(*value, 0, 1000));
    }
    if (auto value{argsman.GetArg("-txrelayfanoutpct")}) {
        int64_t millionths{0};
        if (ParseFixedPoint(*value, 6, &millionths)) {
            options.txrelay_fanout_pct =
                std::clamp(double(millionths) / 1e6, 0.0, 1.0);
        }
    }
    if (auto value{argsman.GetIntArg("-txrelayfanoutmax")}) {
        options.txrelay_fanout_max =
            size_t(std::clamp<int64_t>(*value, 0, 100000));
    }
    if (auto value{argsman.GetIntArg("-txrelayratemax")}) {
        options.txrelay_rate_max = uint64_t(std::max<int64_t>(*value, 1));
    }

    if (auto value{argsman.GetIntArg("-avacooldown")}) {
        options.avalanche_cooldown = std::max(int64_t{0}, *value);
    }

    if (auto value{argsman.GetIntArg("-avalanchepeerreplacementcooldown")}) {
        options.avalanche_peer_replacement_cooldown =
            std::max(int64_t{0}, *value);
    }
}

} // namespace node
