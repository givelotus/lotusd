// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Minimal route set of chronik-http server.rs; the query layer adds the rest.

#include <chronik/native/routes.h>

#include <chronik/native/index/blocks.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/proto.h>

namespace chronik::native {

namespace {

/** Port of QueryBlocks::blockchain_info. */
proto::BlockchainInfo BlockchainInfo(const IndexerImpl &indexer) {
    IndexerSnapshot snap = indexer.Snapshot();
    const std::optional<index::DbBlock> tip =
        index::BlockReader(snap.Store(), snap.Txn()).Tip();
    proto::BlockchainInfo info;
    if (tip) {
        info.set_tip_hash(
            std::string(reinterpret_cast<const char *>(tip->hash.b.data()),
                        tip->hash.b.size()));
        info.set_tip_height(tip->height);
    } else {
        info.set_tip_hash(std::string(32, '\0'));
        info.set_tip_height(-1);
    }
    return info;
}

} // namespace

void RegisterCoreRoutes(Router &router, const RouteContext &ctx) {
    const IndexerImpl *indexer = &ctx.indexer;
    const Host *host = &ctx.host;
    router.Get("/blockchain-info",
               [indexer](const HttpRequest &, const PathParams &) {
                   return HttpResponse::Protobuf(BlockchainInfo(*indexer));
               });
    router.Get("/chronik-info", [host](const HttpRequest &, const PathParams &) {
        proto::ChronikInfo info;
        info.set_version(host->FormatFullVersion());
        return HttpResponse::Protobuf(info);
    });
}

} // namespace chronik::native
