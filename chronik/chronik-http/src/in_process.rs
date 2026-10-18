// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Module for [`InProcessChronik`]: Chronik's endpoints for requests and
//! WebSocket sessions accepted by the node's HTTP server (`/chronik`), which
//! hands over the real client address it saw on its socket.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
};

use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, ws},
    http::{header, Request, StatusCode},
    Router,
};
use tokio::sync::mpsc;
use tower_service::Service;

use crate::{
    server::{ChronikIndexerRef, ChronikSettings},
    subscription_limits::SubscriptionLimiterRef,
    ws::{handle_subscribe_socket, InProcessWs, InProcessWsSink, WsTransport},
};

/// Client messages an in-process WebSocket session may have queued before
/// Chronik reads them; a client that gets further ahead is disconnected.
pub const IN_PROCESS_WS_QUEUE: usize = 1024;

/// CORS headers of the WebSocket upgrade response (same as
/// [`tower_http::cors::CorsLayer`] gives Chronik's own listener).
const CORS_VARY: &str =
    "origin, access-control-request-method, access-control-request-headers";

/// Where the client messages of an in-process WebSocket session go;
/// dropping it ends the session.
#[derive(Debug)]
pub struct InProcessWsSender(mpsc::Sender<ws::Message>);

impl InProcessWsSender {
    /// Queue a binary client message; false if the session ended or the
    /// client is [`IN_PROCESS_WS_QUEUE`] messages ahead of Chronik.
    pub fn try_send_binary(&self, msg: Vec<u8>) -> bool {
        self.0.try_send(ws::Message::Binary(msg)).is_ok()
    }

    /// Queue a text client message (which Chronik rejects), like
    /// [`InProcessWsSender::try_send_binary`].
    pub fn try_send_text(&self) -> bool {
        self.0.try_send(ws::Message::Text(String::new())).is_ok()
    }
}

/// A response of [`InProcessChronik::handle_http`].
#[derive(Debug)]
pub struct InProcessResponse {
    /// HTTP status code
    pub status: u16,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Full response body
    pub body: Vec<u8>,
}

/// Chronik's HTTP router and WebSocket session settings, for the node's HTTP
/// server.
#[derive(Clone)]
pub struct InProcessChronik {
    router: Router,
    indexer: ChronikIndexerRef,
    settings: ChronikSettings,
    subscription_limiter: SubscriptionLimiterRef,
}

impl std::fmt::Debug for InProcessChronik {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessChronik").finish_non_exhaustive()
    }
}

impl InProcessChronik {
    pub(crate) fn new(
        router: Router,
        indexer: ChronikIndexerRef,
        settings: ChronikSettings,
        subscription_limiter: SubscriptionLimiterRef,
    ) -> Self {
        InProcessChronik {
            router,
            indexer,
            settings,
            subscription_limiter,
        }
    }

    /// Settings of the WebSocket sessions (the HTTP server sends the pings).
    pub fn settings(&self) -> &ChronikSettings {
        &self.settings
    }

    /// Serve one request with Chronik's router. `target` has the `/chronik`
    /// prefix removed; `peer_ip` is the client's address, given to handlers
    /// like the client address of a direct connection.
    pub async fn handle_http(
        &self,
        method: &str,
        target: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        peer_ip: IpAddr,
    ) -> InProcessResponse {
        let mut builder = Request::builder().method(method).uri(target);
        for (name, value) in &headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let mut request = match builder.body(Body::from(body)) {
            Ok(request) => request,
            Err(err) => {
                return InProcessResponse {
                    status: StatusCode::BAD_REQUEST.as_u16(),
                    headers: vec![(
                        header::CONTENT_TYPE.to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    )],
                    body: format!("Invalid request: {err}").into_bytes(),
                };
            }
        };
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer_ip, 0)));
        let mut router = self.router.clone();
        let response = match router.call(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        let (parts, body) = response.into_parts();
        let body = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(body) => body.to_vec(),
            Err(_) => {
                return InProcessResponse {
                    status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    headers: vec![],
                    body: vec![],
                };
            }
        };
        InProcessResponse {
            status: parts.status.as_u16(),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.to_string(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            body,
        }
    }

    /// Whether an upgrade request is a valid WebSocket upgrade of Chronik's
    /// `/ws` endpoint (the checks of [`axum::extract::WebSocketUpgrade`]).
    /// Returns the extra headers of the 101 response, or None to serve the
    /// request with [`InProcessChronik::handle_http`], which answers it with
    /// the same error a direct connection would get.
    pub fn ws_upgrade_headers(
        &self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
    ) -> Option<Vec<(String, String)>> {
        let path = target.split('?').next().unwrap_or_default();
        if path != "/ws" || method != "GET" {
            return None;
        }
        let header = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        let connection_upgrade = header("connection").is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
        let upgrade_ws = header("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        let version_13 = header("sec-websocket-version") == Some("13");
        if !connection_upgrade
            || !upgrade_ws
            || !version_13
            || header("sec-websocket-key").is_none()
        {
            return None;
        }
        let mut extra = Vec::new();
        if self.settings.enable_cors {
            extra.push((
                header::ACCESS_CONTROL_ALLOW_ORIGIN.to_string(),
                "*".to_string(),
            ));
            extra.push((header::VARY.to_string(), CORS_VARY.to_string()));
        }
        Some(extra)
    }

    /// Start a subscription session for a WebSocket the HTTP server accepted.
    /// Returns where to send the client's messages and the session future,
    /// which runs until either side closes.
    pub fn open_ws(
        &self,
        peer_ip: IpAddr,
        sink: Box<dyn InProcessWsSink>,
    ) -> (InProcessWsSender, impl Future<Output = ()> + Send + 'static) {
        let (sender, incoming) = mpsc::channel(IN_PROCESS_WS_QUEUE);
        let session = handle_subscribe_socket(
            WsTransport::InProcess(InProcessWs { incoming, sink }),
            self.indexer.clone(),
            self.settings.clone(),
            self.subscription_limiter.clone(),
            peer_ip,
        );
        (InProcessWsSender(sender), session)
    }
}
