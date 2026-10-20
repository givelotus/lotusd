// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Report Chronik's HTTP and WebSocket activity to the node's /metrics.
//!
//! The node's metrics live in C++ (node/metrics.h); these call into them
//! through chronik-bridge. Unit tests of this crate run without the node
//! linked in, so the calls compile to nothing under `cfg(test)`.

/// Count a request: its route template ("" if none matched), the response
/// status and the time taken.
#[cfg(not(test))]
pub(crate) fn record_request(route: &str, status: u16, nanos: u64) {
    chronik_bridge::ffi::metrics_chronik_request(route, status, nanos);
}

/// Add `delta` to the open WebSocket connections.
#[cfg(not(test))]
pub(crate) fn add_ws_connections(delta: i32) {
    chronik_bridge::ffi::metrics_chronik_ws_connections(delta);
}

/// Add `delta` to the active WebSocket subscriptions.
#[cfg(not(test))]
pub(crate) fn add_ws_subscriptions(delta: i32) {
    chronik_bridge::ffi::metrics_chronik_ws_subscriptions(delta);
}

#[cfg(test)]
pub(crate) fn record_request(_route: &str, _status: u16, _nanos: u64) {}

#[cfg(test)]
pub(crate) fn add_ws_connections(_delta: i32) {}

#[cfg(test)]
pub(crate) fn add_ws_subscriptions(_delta: i32) {}
