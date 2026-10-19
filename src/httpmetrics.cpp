// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpmetrics.h>

#include <httpserver.h>
#include <logging.h>
#include <node/metrics.h>
#include <rpc/protocol.h>

#include <string>

static bool HTTPReqMetrics(Config &, HTTPRequest *req, const std::string &) {
    node::NodeMetrics *m{node::GetNodeMetrics()};
    if (req->GetRequestMethod() != HTTPRequest::GET &&
        req->GetRequestMethod() != HTTPRequest::HEAD) {
        req->WriteHeader("Allow", "GET, HEAD");
        req->WriteReply(HTTP_BAD_METHOD);
        return false;
    }
    if (!m) {
        req->WriteReply(HTTP_SERVICE_UNAVAILABLE);
        return false;
    }
    req->WriteHeader("Content-Type",
                     "text/plain; version=0.0.4; charset=utf-8");
    req->WriteHeader("Cache-Control", "no-store");
    req->WriteReply(HTTP_OK, m->registry.Render(METRICS_MIN_SCRAPE_INTERVAL));
    return true;
}

void StartHTTPMetrics() {
    node::StartNodeMetrics();
    RegisterHTTPHandler("/metrics", true, HTTPReqMetrics);
    LogPrintf("Serving metrics at /metrics on the RPC listeners\n");
}

void StopHTTPMetrics() {
    UnregisterHTTPHandler("/metrics", true);
    node::StopNodeMetrics();
}
