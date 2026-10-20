// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Rust side of the bridge; these structs and functions are exposed to C++.

use std::{
    net::{AddrParseError, IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use abc_rust_error::Result;
use bitcoinsuite_core::{
    net::Net,
    tx::{Tx, TxId},
};
use chronik_bridge::ffi::init_error;
use chronik_db::{
    index_tx::TxNumCacheSettings, io::GroupHistorySettings, mem::MempoolTx,
};
use chronik_http::electrum::{
    ChronikElectrumProtocol, ChronikElectrumServer, ChronikElectrumServerParams,
};
use chronik_http::server::{
    ChronikServer, ChronikServerParams, ChronikSettings,
};
use chronik_http::subscription_limits::SubscriptionLimiter;
use chronik_indexer::{
    indexer::{ChronikIndexer, ChronikIndexerParams, Node},
    pause::Pause,
};
use chronik_plugin::{context::PluginContext, params::PluginParams};
use chronik_util::{log, log_chronik, mount_loggers, Loggers};
use thiserror::Error;
use tokio::{runtime::Runtime, sync::RwLock};

use crate::ffi::{self, StartChronikValidationInterface};
use crate::in_process::{InProcessServer, Served, ServedRef};
use chronik_http::ws::{MAX_WS_MESSAGE_SIZE, WS_PING_PAYLOAD};

/// Errors for [`Chronik`] and [`setup_chronik`].
#[derive(Debug, Eq, Error, PartialEq)]
pub enum ChronikError {
    /// Chronik host address failed to parse
    #[error("Invalid Chronik host address {0:?}: {1}")]
    InvalidChronikHost(String, AddrParseError),

    /// Chronik Electrum host address failed to parse
    #[error("Invalid Chronik Electrum host address {0:?}: {1}")]
    InvalidChronikElectrumHostAddr(String, AddrParseError),

    /// Chronik electrum host address failed to parse
    #[error("Invalid Chronik Electrum host address format {0:?}")]
    InvalidChronikElectrumHostFormat(String),

    /// Chronik electrum host address failed to parse
    #[error("Invalid Chronik Electrum host protocol {0:?}")]
    InvalidChronikElectrumHostProtocol(u8),

    /// Unknown net repr
    #[error("Unknown net repr {0}")]
    UnknownNetRepr(u8),

    /// V2Service failed to open
    #[error("V2Service open failed: {0}")]
    V2ServiceOpenFailed(String),
}

use self::ChronikError::*;

/// Setup the Chronik bridge. Returns a ChronikIndexer object.
pub fn setup_chronik(
    params: ffi::SetupParams,
    node: &ffi::NodeContext,
) -> bool {
    match try_setup_chronik(params, node) {
        Ok(()) => true,
        Err(report) => {
            log_chronik!("{report:?}\n");
            init_error(&report.to_string())
        }
    }
}

fn try_setup_chronik(
    params: ffi::SetupParams,
    node_context: &ffi::NodeContext,
) -> Result<()> {
    abc_rust_error::install();
    mount_loggers(Loggers {
        log: chronik_bridge::ffi::log_print,
        log_chronik: chronik_bridge::ffi::log_print_chronik,
    });
    let hosts = params
        .hosts
        .into_iter()
        .map(|host| parse_socket_addr(host, params.default_port))
        .collect::<Result<Vec<_>>>()?;
    let datadir: PathBuf = params.datadir.into();
    let net = match params.net {
        ffi::Net::Mainnet => Net::Mainnet,
        ffi::Net::Testnet => Net::Testnet,
        ffi::Net::Regtest => Net::Regtest,
        _ => return Err(UnknownNetRepr(params.net.repr).into()),
    };
    let plugin_ctx = PluginContext::setup(PluginParams {
        net,
        plugins_dir: datadir.join("plugins"),
        plugins_conf: datadir.join("plugins.toml"),
    })?;
    log!("Starting Chronik bound to {hosts:?}\n");
    let bridge = chronik_bridge::ffi::make_bridge(node_context);
    let node = Arc::new(Node { bridge });
    let (pause, pause_notify) = Pause::new_pair(params.is_pause_allowed);
    let datadir_net: PathBuf = params.datadir_net.into();
    let mut indexer = ChronikIndexer::setup(
        ChronikIndexerParams {
            datadir_net: datadir_net.clone(),
            wipe_db: params.wipe_db,
            enable_token_index: params.enable_token_index,
            enable_lokad_id_index: params.enable_lokad_id_index,
            enable_scripthash_index: params.enable_scripthash_index,
            enable_perf_stats: params.enable_perf_stats,
            tx_num_cache: TxNumCacheSettings {
                bucket_size: params.tx_num_cache.bucket_size,
                num_buckets: params.tx_num_cache.num_buckets,
            },
            plugin_ctx: Arc::new(plugin_ctx),
            script_history: GroupHistorySettings {
                is_member_hash_index_enabled: params.enable_scripthash_index,
            },
            decompress_script_fn: decompress_script,
        },
        node.clone(),
    )?;
    indexer.resync_indexer(node.as_ref())?;
    if node.bridge.shutdown_requested() {
        // Don't setup Chronik if the user requested shutdown during resync
        return Ok(());
    }
    let v2_path = datadir_net.join("indexes").join("chronik").join("v2_index");
    let v2_fresh = if params.wipe_db || !v2_path.join("mdbx.dat").is_file() {
        if v2_path.exists() {
            let _ = std::fs::remove_dir_all(&v2_path);
        }
        true
    } else {
        false
    };
    let v2_binding = crate::v2_ffi::get_v2_binding(&node.bridge);
    // Index bounds follow the consensus block-size limit, so that every
    // valid block is indexed.
    let v2_block_bytes = crate::v2_ffi::get_v2_max_block_bytes(&node.bridge);
    let v2_bounds = chronik_db::v2_branch::Bounds::new(v2_block_bytes.into())
        .map_err(|err| V2ServiceOpenFailed(err.to_string()))?;
    let v2_limits = crate::v2_ffi::ServiceLimits {
        block_bytes: v2_block_bytes,
        transactions: v2_bounds.transactions() as u32,
        changes: v2_bounds.changes() as u32,
        roots: 256,
        clauses: 16,
        page_size: 1000,
        posting_reads: 65536,
        work: 131072,
        response_bytes: 1024 * 1024,
    };
    // An index of another schema version is refused with a reindex
    // message; any other open failure rebuilds the index from scratch.
    let v2_service = match crate::v2::open_service_with_node(
        &v2_path.to_string_lossy(),
        v2_binding.clone(),
        v2_fresh,
        v2_limits.clone(),
        node.clone(),
    ) {
        Ok(svc) => svc,
        Err(err @ crate::v2::OpenError::Schema(_)) => {
            return Err(V2ServiceOpenFailed(err.to_string()).into());
        }
        Err(_) => {
            let _ = std::fs::remove_dir_all(&v2_path);
            crate::v2::open_service_with_node(
                &v2_path.to_string_lossy(),
                v2_binding,
                true,
                v2_limits,
                node.clone(),
            )
            .map_err(|err| V2ServiceOpenFailed(err.to_string()))?
        }
    };
    resync_v2_service(&v2_service, node.as_ref());
    let v2_state = Some(v2_service.http_state());
    let indexer = Arc::new(RwLock::new(indexer));
    let subscription_limiter =
        SubscriptionLimiter::new_ref(params.max_subs, params.max_subs_per_ip);
    log!(
        "Chronik subscription limits: max_subs={}, max_subs_per_ip={}, \
         subscription_max_script_size={}, subscription_max_plugin_size={}\n",
        params.max_subs,
        params.max_subs_per_ip,
        params.subscription_max_script_size,
        params.subscription_max_plugin_size,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let server = runtime.block_on({
        let indexer = Arc::clone(&indexer);
        let node = Arc::clone(&node);
        let subscription_limiter = Arc::clone(&subscription_limiter);
        async move {
            // try_bind requires a Runtime
            ChronikServer::setup(ChronikServerParams {
                hosts,
                indexer,
                node,
                pause_notify: Arc::new(pause_notify),
                settings: ChronikSettings {
                    ws_ping_interval: Duration::from_secs(
                        params.ws_ping_interval_secs,
                    ),
                    enable_cors: params.enable_cors,
                    subscription_max_script_size: params
                        .subscription_max_script_size,
                    subscription_max_plugin_size: params
                        .subscription_max_plugin_size,
                },
                subscription_limiter,
                v2_state,
            })
        }
    })?;
    // Serve /chronik on the node's HTTP server, with the client addresses
    // it sees (the HTTP server only uses it with -chronikpubliconrpcport).
    let in_process_chronik = server.in_process();
    let ws_ping_interval = in_process_chronik.settings().ws_ping_interval;
    let in_process: ServedRef = Arc::new(Mutex::new(Some(Served {
        runtime: runtime.handle().clone(),
        chronik: in_process_chronik,
    })));
    runtime.spawn({
        let node = Arc::clone(&node);
        async move {
            node.ok_or_abort("ChronikServer::serve", server.serve().await);
        }
    });

    if !params.electrum_hosts.is_empty() {
        let electrum_hosts = params
            .electrum_hosts
            .into_iter()
            .map(|host| {
                parse_socket_addr_protocol(
                    host,
                    params.electrum_default_port,
                    params.electrum_default_protocol,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        log!(
            "Starting Chronik Electrum interface bound to {electrum_hosts:?}\n",
        );
        let electrum_server =
            ChronikElectrumServer::setup(ChronikElectrumServerParams {
                hosts: electrum_hosts,
                url: params.electrum_url,
                indexer: indexer.clone(),
                node: node.clone(),
                tls_cert_path: params.electrum_cert_path,
                tls_privkey_path: params.electrum_privkey_path,
                max_history: params.electrum_max_history,
                donation_address: params.electrum_donation_address,
                peers_validation_interval: params
                    .electrum_peers_validation_interval,
                idle_timeout: params.electrum_idle_timeout,
                subscription_limiter,
            })?;
        runtime.spawn({
            let node = Arc::clone(&node);
            async move {
                node.ok_or_abort(
                    "ChronikElectrumServer::serve",
                    electrum_server.serve().await,
                );
            }
        });
    }

    let chronik = Box::new(Chronik {
        node: Arc::clone(&node),
        indexer,
        v2_service,
        pause,
        runtime: Mutex::new(Some(runtime)),
        in_process: Arc::clone(&in_process),
    });
    ffi::RegisterChronikInProcess(
        Box::new(InProcessServer::new(Arc::clone(&in_process))),
        ws_ping_interval.as_millis().try_into().unwrap_or(u64::MAX),
        WS_PING_PAYLOAD,
        MAX_WS_MESSAGE_SIZE,
    );
    StartChronikValidationInterface(node_context, chronik);
    Ok(())
}

fn resync_v2_service(v2_service: &crate::v2::V2Service, node: &Node) {
    let Ok(tip) = node.bridge.get_chain_tip() else {
        return;
    };
    let tip_info = chronik_bridge::ffi::get_block_info(tip);
    if tip_info.height < 0 {
        return;
    }
    while let Ok(Some(cp)) = v2_service.checkpoint() {
        if cp.height <= tip_info.height as u64 {
            if let Ok(bindex) =
                node.bridge.lookup_block_index_by_height(cp.height as i32)
            {
                let info = chronik_bridge::ffi::get_block_info(bindex);
                if info.hash == cp.block_id {
                    break;
                }
            }
        }
        if v2_service.disconnect_block(cp).is_err() {
            break;
        }
    }
    let start_height = match v2_service.checkpoint() {
        Ok(Some(cp)) => cp.height as i32 + 1,
        Ok(None) => 0,
        Err(_) => return,
    };
    for h in start_height..=tip_info.height {
        if node.bridge.shutdown_requested() {
            return;
        }
        let Ok(bindex) = node.bridge.lookup_block_index_by_height(h) else {
            break;
        };
        let Ok(cblock) = node.bridge.load_block(bindex) else {
            break;
        };
        let Ok(native_block) =
            crate::v2_ffi::bridge_v2_native_block(&cblock, bindex)
        else {
            break;
        };
        let res = if h == 0 {
            v2_service.initialize_genesis(native_block)
        } else {
            v2_service.connect_block(native_block)
        };
        if let Err(err) = res {
            log_chronik!("Chronik V2 resync skipped at height {h}: {err}\n");
            break;
        }
    }
    if let Ok(Some(cp)) = v2_service.checkpoint() {
        let _ = v2_service.publish_authority(cp);
    }
}

fn parse_socket_addr(host: String, default_port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let ip_addr = host
        .parse::<IpAddr>()
        .map_err(|err| InvalidChronikHost(host, err))?;
    Ok(SocketAddr::new(ip_addr, default_port))
}

fn parse_socket_addr_protocol(
    host: String,
    default_port: u16,
    default_protocol: u8,
) -> Result<(SocketAddr, ChronikElectrumProtocol)> {
    let split_host = host.split(':').collect::<Vec<_>>();
    let split_host_len = split_host.len();
    if split_host_len > 3 {
        return Err(InvalidChronikElectrumHostFormat(host).into());
    }

    let addr_port = split_host[..split_host_len.min(2)].join(":");

    let mut protocol_letter = default_protocol;
    if split_host_len > 2 {
        protocol_letter = split_host[2]
            .bytes()
            .next()
            .ok_or(InvalidChronikElectrumHostFormat(host.clone()))?;
    }

    let protocol = match protocol_letter {
        b't' => ChronikElectrumProtocol::Tcp,
        b's' => ChronikElectrumProtocol::Tls,
        b'w' => ChronikElectrumProtocol::Ws,
        b'y' => ChronikElectrumProtocol::Wss,
        _ => {
            return Err(
                InvalidChronikElectrumHostProtocol(protocol_letter).into()
            )
        }
    };

    if let Ok(addr) = addr_port.parse::<SocketAddr>() {
        return Ok((addr, protocol));
    }
    let ip_addr = host
        .parse::<IpAddr>()
        .map_err(|err| InvalidChronikElectrumHostAddr(host, err))?;
    Ok((SocketAddr::new(ip_addr, default_port), protocol))
}

fn decompress_script(script: &[u8]) -> Result<Vec<u8>> {
    Ok(chronik_bridge::ffi::decompress_script(script)?)
}

/// Contains all db, runtime, tpc, etc. handles needed by Chronik.
/// This makes it so when this struct is dropped, all handles are relased
/// cleanly.
pub struct Chronik {
    node: Arc<Node>,
    indexer: Arc<RwLock<ChronikIndexer>>,
    v2_service: Box<crate::v2::V2Service>,
    pause: Pause,
    /// Tokio runtime driving HTTP and Electrum. Wrapped so
    /// [`Chronik::interrupt`] can shut it down before the node is torn down
    /// and before RocksDB is closed, ensuring no async task touches either
    /// during teardown. The Option is needed to allow for the runtime to
    /// be consumed before the Chronik struct is dropped.
    runtime: Mutex<Option<Runtime>>,
    /// What /chronik on the node's HTTP server is served with; cleared by
    /// [`Chronik::interrupt`] before the runtime shuts down.
    in_process: ServedRef,
}

impl Chronik {
    /// Tx added to the bitcoind mempool
    pub fn handle_tx_added_to_mempool(
        &self,
        ptx: &ffi::CTransaction,
        spent_coins: &cxx::CxxVector<ffi::CCoin>,
        time_first_seen: i64,
    ) {
        self.block_if_paused();
        self.node.ok_or_abort(
            "handle_tx_added_to_mempool",
            self.add_tx_to_mempool(ptx, spent_coins, time_first_seen),
        );
    }

    /// Tx removed from the bitcoind mempool
    pub fn handle_tx_removed_from_mempool(&self, txid: [u8; 32]) {
        self.block_if_paused();
        let mut indexer = self.indexer.blocking_write();
        let txid = TxId::from(txid);
        self.node.ok_or_abort(
            "handle_tx_removed_from_mempool",
            indexer.handle_tx_removed_from_mempool(txid),
        );
        log_chronik!("Chronik: transaction {txid} removed from mempool\n");
    }

    /// Block connected to the longest chain
    pub fn handle_block_connected(
        &self,
        block: &ffi::CBlock,
        bindex: &ffi::CBlockIndex,
    ) {
        self.block_if_paused();
        self.node.ok_or_abort(
            "handle_block_connected",
            self.connect_block(block, bindex),
        );
    }

    /// Block disconnected from the longest chain
    pub fn handle_block_disconnected(
        &self,
        block: &ffi::CBlock,
        bindex: &ffi::CBlockIndex,
    ) {
        self.block_if_paused();
        self.node.ok_or_abort(
            "handle_block_disconnected",
            self.disconnect_block(block, bindex),
        );
    }

    /// Block finalized with Avalanche
    pub fn handle_block_finalized(&self, bindex: &ffi::CBlockIndex) {
        self.block_if_paused();
        self.node
            .ok_or_abort("handle_block_finalized", self.finalize_block(bindex));
    }

    /// Block invalidated with Avalanche
    pub fn handle_block_invalidated(
        &self,
        block: &ffi::CBlock,
        bindex: &ffi::CBlockIndex,
    ) {
        self.block_if_paused();
        self.node.ok_or_abort(
            "handle_block_invalidated",
            self.invalidate_block(block, bindex),
        );
    }

    /// Transaction finalized with Avalanche
    pub fn handle_tx_finalized(&self, txid: [u8; 32]) {
        self.block_if_paused();
        let txid = TxId::from(txid);
        self.node.ok_or_abort(
            "handle_tx_finalized",
            self.finalize_transaction(&txid),
        );
    }

    /// Transaction invalidated with Avalanche
    pub fn handle_tx_invalidated(
        &self,
        tx: &ffi::CTransaction,
        spent_coins: &cxx::CxxVector<ffi::CCoin>,
    ) {
        self.block_if_paused();
        self.node.ok_or_abort(
            "handle_tx_invalidated",
            self.invalidate_transaction(tx, spent_coins),
        );
    }

    /// Shut down the tokio runtime driving HTTP and Electrum, so no request
    /// handler (including detached `tokio::spawn` work) can access the node or
    /// RocksDB anymore. Chronik keeps indexing validation interface events
    /// after this returns; only [`Chronik::stop`] tears the indexer down.
    pub fn interrupt(&self) {
        // In-process requests arriving from now on get 503.
        self.in_process.lock().unwrap().take();
        let mut runtime_guard = self.runtime.lock().unwrap();
        if let Some(runtime) = runtime_guard.take() {
            runtime.shutdown_timeout(Duration::from_secs(60));
        }
    }

    /// Stop Chronik to prepare for shutdown.
    ///
    /// Shuts down the tokio runtime first (if [`Chronik::interrupt`] didn't
    /// already do so) so HTTP and Electrum tasks cannot access RocksDB, then
    /// flushes the DB. RocksDB background work cancellation happens when the DB
    /// is dropped.
    pub fn stop(&self) -> Result<()> {
        self.interrupt();
        let indexer = self.indexer.blocking_write();
        indexer.stop()?;
        Ok(())
    }

    fn add_tx_to_mempool(
        &self,
        ptx: &ffi::CTransaction,
        spent_coins: &cxx::CxxVector<ffi::CCoin>,
        time_first_seen: i64,
    ) -> Result<()> {
        let mut indexer = self.indexer.blocking_write();
        let tx = chronik_bridge::ffi::bridge_tx(ptx, spent_coins)?;
        let txid = TxId::from(tx.txid);
        indexer.handle_tx_added_to_mempool(MempoolTx {
            tx: Tx::from(tx),
            time_first_seen,
        })?;
        log_chronik!("Chronik: transaction {txid} added to mempool\n");
        Ok(())
    }

    fn connect_block(
        &self,
        cblock: &ffi::CBlock,
        bindex: &ffi::CBlockIndex,
    ) -> Result<()> {
        let block_undo = self.node.bridge.load_block_undo(bindex)?;
        let block =
            chronik_bridge::ffi::bridge_block(cblock, &block_undo, bindex)?;
        let mut indexer = self.indexer.blocking_write();
        let block = indexer.make_chronik_block(block);
        let block_hash = block.db_block.hash.clone();
        let num_txs = block.block_txs.txs.len();
        indexer.handle_block_connected(block)?;
        if let Ok(native_block) =
            crate::v2_ffi::bridge_v2_native_block(cblock, bindex)
        {
            let anchor = native_block.anchor.clone();
            let res = if anchor.height == 0 {
                self.v2_service.initialize_genesis(native_block)
            } else {
                self.v2_service.connect_block(native_block)
            };
            if res.is_ok() {
                let _ = self.v2_service.publish_authority(anchor);
            } else if let Err(err) = res {
                log_chronik!("Chronik V2 connect_block skipped: {err}\n");
            }
        }
        log_chronik!(
            "Chronik: block {block_hash} connected with {num_txs} txs\n"
        );
        Ok(())
    }

    fn disconnect_block(
        &self,
        cblock: &ffi::CBlock,
        bindex: &ffi::CBlockIndex,
    ) -> Result<()> {
        let block_undo = self.node.bridge.load_block_undo(bindex)?;
        let block =
            chronik_bridge::ffi::bridge_block(cblock, &block_undo, bindex)?;
        let mut indexer = self.indexer.blocking_write();
        let block = indexer.make_chronik_block(block);
        let block_hash = block.db_block.hash.clone();
        let num_txs = block.block_txs.txs.len();
        indexer.handle_block_disconnected(block)?;
        let info = chronik_bridge::ffi::get_block_info(bindex);
        if info.height >= 0 {
            let expected = crate::v2_ffi::Anchor {
                block_id: info.hash,
                height: info.height as u64,
            };
            if self.v2_service.disconnect_block(expected).is_ok() {
                if let Ok(Some(cp)) = self.v2_service.checkpoint() {
                    let _ = self.v2_service.publish_authority(cp);
                }
            }
        }
        log_chronik!(
            "Chronik: block {block_hash} disconnected with {num_txs} txs\n"
        );
        Ok(())
    }

    fn finalize_block(&self, bindex: &ffi::CBlockIndex) -> Result<()> {
        let mut indexer = self.indexer.blocking_write();
        let block = indexer.load_chronik_block(&self.node, bindex)?;
        let block_hash = block.db_block.hash.clone();
        let num_txs = block.block_txs.txs.len();
        indexer.handle_block_finalized(block)?;
        log_chronik!(
            "Chronik: block {block_hash} finalized with {num_txs} txs\n"
        );
        Ok(())
    }

    fn invalidate_block(
        &self,
        block: &ffi::CBlock,
        bindex: &ffi::CBlockIndex,
    ) -> Result<()> {
        // If there is no block undo for this block, skip the processing.
        // This behavior can only occur for blocks building on a parked chain,
        // and we don't have any interest for these blocks. This might as well
        // be another chain.
        let Ok(block_undo) = self.node.bridge.load_block_undo(bindex) else {
            return Ok(());
        };
        let block =
            chronik_bridge::ffi::bridge_block(block, &block_undo, bindex)?;
        let mut indexer = self.indexer.blocking_write();
        let block = indexer.make_chronik_block(block);
        let block_hash = block.db_block.hash.clone();
        let num_txs = block.block_txs.txs.len();
        indexer.handle_block_invalidated(block)?;
        log_chronik!(
            "Chronik: block {block_hash} invalidated with {num_txs} txs\n",
        );
        Ok(())
    }

    fn finalize_transaction(&self, txid: &TxId) -> Result<()> {
        let mut indexer = self.indexer.blocking_write();
        indexer.handle_transaction_finalized(txid)?;
        log_chronik!(
            "Chronik: transaction {txid} finalized by pre-consensus\n"
        );
        Ok(())
    }

    fn invalidate_transaction(
        &self,
        tx: &ffi::CTransaction,
        spent_coins: &cxx::CxxVector<ffi::CCoin>,
    ) -> Result<()> {
        let mut indexer = self.indexer.blocking_write();
        let tx = chronik_bridge::ffi::bridge_tx(tx, spent_coins)?;
        let txid: TxId = TxId::from(tx.txid);
        indexer.handle_transaction_invalidated(Tx::from(tx))?;
        log_chronik!(
            "Chronik: transaction {txid} invalidated by pre-consensus\n"
        );
        Ok(())
    }

    fn block_if_paused(&self) {
        let handle = {
            let guard = self.runtime.lock().unwrap();
            guard.as_ref().map(|runtime| runtime.handle().clone())
        };
        if let Some(handle) = handle {
            self.pause.block_if_paused(&handle);
        }
    }
}

impl std::fmt::Debug for Chronik {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Chronik {{ .. }}")
    }
}
