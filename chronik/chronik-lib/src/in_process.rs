// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Serving /chronik on the node's HTTP server: [`InProcessServer`] receives
//! the requests and WebSocket sessions the HTTP server accepted (through its
//! `ChronikInProcessHandlers`, see `src/httpserver.h`) and runs them on
//! Chronik's tokio runtime, with the client address the HTTP server saw.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

use chronik_http::{
    in_process::{InProcessChronik, InProcessWsSender},
    ws::InProcessWsSink,
};
use chronik_util::log_chronik;
use cxx::UniquePtr;
use tokio::runtime::Handle;

use crate::ffi;

// SAFETY: the C++ completion may be called once, from any thread.
#[allow(unsafe_code)]
unsafe impl Send for ffi::InProcessHttpDone {}
// SAFETY: InProcessWebSocket (src/httpserver.h) is thread-safe.
#[allow(unsafe_code)]
unsafe impl Send for ffi::InProcessWsSink {}
#[allow(unsafe_code)]
unsafe impl Sync for ffi::InProcessWsSink {}

impl std::fmt::Debug for ffi::InProcessHttpDone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InProcessHttpDone")
    }
}

impl std::fmt::Debug for ffi::InProcessWsSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InProcessWsSink")
    }
}

/// What [`InProcessServer`] serves with, until Chronik is interrupted.
#[derive(Clone, Debug)]
pub(crate) struct Served {
    pub(crate) runtime: Handle,
    pub(crate) chronik: InProcessChronik,
}

/// Shared between [`InProcessServer`] and [`crate::bridge::Chronik`], which
/// clears it before it shuts the runtime down.
pub(crate) type ServedRef = Arc<Mutex<Option<Served>>>;

/// Chronik's endpoints for the node's HTTP server.
#[derive(Debug)]
pub struct InProcessServer {
    served: ServedRef,
}

/// Receiving side of an in-process WebSocket session.
#[derive(Debug)]
pub struct InProcessWsSession {
    sender: Mutex<Option<InProcessWsSender>>,
    sink: Arc<CppSink>,
}

#[derive(Debug)]
struct CppSink(UniquePtr<ffi::InProcessWsSink>);

impl CppSink {
    fn close(&self) {
        self.0.close();
    }
}

/// The session's handle on the sink; [`InProcessWsSession`] keeps another to
/// close an overrun session.
struct SharedSink(Arc<CppSink>);

impl InProcessWsSink for SharedSink {
    fn send_binary(&self, msg: Vec<u8>) {
        self.0 .0.send_binary(&msg);
    }

    fn close(&self) {
        self.0.close();
    }
}

fn to_pairs(headers: Vec<ffi::InProcessHeader>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect()
}

fn parse_peer_ip(peer_ip: &str) -> IpAddr {
    peer_ip.parse().unwrap_or_else(|_| {
        log_chronik!("Unparsable in-process peer address {peer_ip:?}\n");
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    })
}

impl InProcessServer {
    pub(crate) fn new(served: ServedRef) -> Self {
        InProcessServer { served }
    }

    fn served(&self) -> Option<Served> {
        self.served.lock().unwrap().clone()
    }

    /// See [`ffi::InProcessServer::http`].
    pub fn http(
        &self,
        method: String,
        target: String,
        headers: Vec<ffi::InProcessHeader>,
        body: &[u8],
        peer_ip: &str,
        done: UniquePtr<ffi::InProcessHttpDone>,
    ) {
        let Some(served) = self.served() else {
            // Dropping `done` answers 503.
            return;
        };
        let body = body.to_vec();
        let peer_ip = parse_peer_ip(peer_ip);
        let headers = to_pairs(headers);
        served.runtime.spawn(async move {
            let response = served
                .chronik
                .handle_http(&method, &target, headers, body, peer_ip)
                .await;
            let headers = response
                .headers
                .into_iter()
                .map(|(name, value)| ffi::InProcessHeader { name, value })
                .collect::<Vec<_>>();
            done.complete(response.status, &headers, &response.body);
        });
    }

    /// See [`ffi::InProcessServer::ws_check`].
    pub fn ws_check(
        &self,
        method: String,
        target: String,
        headers: Vec<ffi::InProcessHeader>,
        extra: &mut Vec<ffi::InProcessHeader>,
    ) -> bool {
        let Some(served) = self.served() else {
            return false;
        };
        let headers = to_pairs(headers);
        match served
            .chronik
            .ws_upgrade_headers(&method, &target, &headers)
        {
            Some(headers) => {
                extra.extend(
                    headers
                        .into_iter()
                        .map(|(name, value)| ffi::InProcessHeader { name, value }),
                );
                true
            }
            None => false,
        }
    }

    /// See [`ffi::InProcessServer::ws_open`].
    pub fn ws_open(
        &self,
        peer_ip: &str,
        sink: UniquePtr<ffi::InProcessWsSink>,
    ) -> Box<InProcessWsSession> {
        let sink = Arc::new(CppSink(sink));
        let Some(served) = self.served() else {
            sink.close();
            return Box::new(InProcessWsSession {
                sender: Mutex::new(None),
                sink,
            });
        };
        let (sender, session) = served
            .chronik
            .open_ws(parse_peer_ip(peer_ip), Box::new(SharedSink(Arc::clone(&sink))));
        served.runtime.spawn(session);
        Box::new(InProcessWsSession {
            sender: Mutex::new(Some(sender)),
            sink,
        })
    }
}

impl InProcessWsSession {
    fn deliver(&self, send: impl FnOnce(&InProcessWsSender) -> bool) {
        let mut sender = self.sender.lock().unwrap();
        let Some(tx) = sender.as_ref() else {
            return;
        };
        if !send(tx) {
            // Session ended, or the client is too far ahead of Chronik.
            *sender = None;
            self.sink.close();
        }
    }

    /// See [`ffi::InProcessWsSession::on_binary`].
    pub fn on_binary(&self, msg: &[u8]) {
        self.deliver(|tx| tx.try_send_binary(msg.to_vec()));
    }

    /// See [`ffi::InProcessWsSession::on_text`].
    pub fn on_text(&self) {
        self.deliver(|tx| tx.try_send_text());
    }

    /// See [`ffi::InProcessWsSession::on_closed`].
    pub fn on_closed(&self) {
        // Ends the session: its receiver sees the channel closed.
        self.sender.lock().unwrap().take();
    }
}
