//! Independent bounded native V2 service bridge. Identities use native wire order.

pub use self::ffi_inner::*;
use crate::v2::{open_service, start_v2_server, V2Service};
use crate::v2_server::V2Server;

#[allow(unsafe_code)]
#[cxx::bridge(namespace = "chronik_v2")]
mod ffi_inner {
    /// Native V2 Binding transport.
    #[derive(Clone, Debug)]
    struct Binding {
        /// Native chain id.
        chain_id: [u8; 32],
        /// Native genesis.
        genesis: [u8; 32],
        /// Native profile.
        profile: [u8; 32],
    }
    /// Native V2 Anchor transport.
    #[derive(Clone, Debug)]
    struct Anchor {
        /// Native block id.
        block_id: [u8; 32],
        /// Native height.
        height: u64,
    }
    /// Native V2 ServiceLimits transport.
    #[derive(Clone, Debug)]
    struct ServiceLimits {
        /// Native block bytes.
        block_bytes: u32,
        /// Native transactions.
        transactions: u32,
        /// Native changes.
        changes: u32,
        /// Native roots.
        roots: u32,
        /// Native clauses.
        clauses: u32,
        /// Native page size.
        page_size: u32,
        /// Native posting reads.
        posting_reads: u32,
        /// Native work.
        work: u32,
        /// Native response bytes.
        response_bytes: u32,
    }
    /// Native V2 Input transport.
    #[derive(Clone, Debug)]
    struct Input {
        /// Native txid.
        txid: [u8; 32],
        /// Native out idx.
        out_idx: u32,
        /// Native input index.
        input_index: u32,
    }
    /// Native V2 NativeOutput transport.
    #[derive(Clone, Debug)]
    struct NativeOutput {
        /// Native wire.
        wire: Vec<u8>,
    }
    /// Byte range in the exact transaction frame.
    #[derive(Clone, Debug)]
    struct WireRange {
        offset: u64,
        length: u64,
    }
    /// Authenticated witness section locations.
    #[derive(Clone, Debug)]
    struct NativeWitness {
        script: WireRange,
        siblings_table: WireRange,
        siblings_count: u32,
        arguments_table: WireRange,
        arguments_count: u32,
    }
    /// Complete input descriptor, including non-spend selectors.
    #[derive(Clone, Debug)]
    struct NativeFullInput {
        prev_txid: [u8; 32],
        prev_index: u32,
        sequence: u32,
        flags: u8,
        path_index: u8,
        has_coinbase_data: bool,
        coinbase_data: WireRange,
        witnesses: Vec<NativeWitness>,
    }
    /// Native V2 NativeTx transport.
    #[derive(Clone, Debug)]
    struct NativeTx {
        /// Native txid.
        txid: [u8; 32],
        /// Native txhash.
        txhash: [u8; 32],
        /// Native index.
        index: u32,
        /// Native inputs.
        inputs: Vec<Input>,
        /// Native outputs.
        outputs: Vec<NativeOutput>,
        wire: Vec<u8>,
        lock: u64,
        full_inputs: Vec<NativeFullInput>,
    }
    /// Native V2 NativeBlock transport.
    #[derive(Clone, Debug)]
    struct NativeBlock {
        /// Native anchor.
        anchor: Anchor,
        /// Native parent.
        parent: Anchor,
        /// Native transactions.
        transactions: Vec<NativeTx>,
        header_wire: [u8; 134],
    }
    /// Native V2 Status transport.
    #[derive(Clone, Debug)]
    struct Status {
        /// Native initialized.
        initialized: bool,
        /// Native indexed.
        indexed: Anchor,
        /// Native node.
        node: Anchor,
        /// Native ready.
        ready: bool,
    }
    /// Native V2 Root transport.
    #[derive(Clone, Debug)]
    struct Root {
        /// Native bytes.
        bytes: [u8; 32],
    }
    /// Native V2 Position transport.
    #[derive(Clone, Debug)]
    struct Position {
        /// Native position.
        position: u8,
        /// Native roots.
        roots: Vec<Root>,
    }
    /// Native V2 Continuation transport.
    #[derive(Clone, Debug)]
    struct Continuation {
        /// Native present.
        present: bool,
        /// Native version.
        version: u8,
        /// Native chain id.
        chain_id: [u8; 32],
        /// Native profile.
        profile: [u8; 32],
        /// Native anchor.
        anchor: Anchor,
        /// Native filter digest.
        filter_digest: [u8; 32],
        /// Native has last.
        has_last: bool,
        /// Native last txid.
        last_txid: [u8; 32],
        /// Native last out idx.
        last_out_idx: u32,
    }
    /// Native V2 BranchRequest transport.
    #[derive(Clone, Debug)]
    struct BranchRequest {
        /// Native any branch.
        any_branch: Vec<Root>,
        /// Native positions.
        positions: Vec<Position>,
        /// Native utxos.
        utxos: bool,
        /// Native include burn.
        include_burn: bool,
        /// Native cursor.
        cursor: Continuation,
    }
    /// Native V2 Location transport.
    #[derive(Clone, Debug)]
    struct Location {
        /// Native anchor.
        anchor: Anchor,
        /// Native tx index.
        tx_index: u32,
        /// Native txid.
        txid: [u8; 32],
        /// Native txhash.
        txhash: [u8; 32],
    }
    /// Native V2 OutputMatch transport.
    #[derive(Clone, Debug)]
    struct OutputMatch {
        /// Native txid.
        txid: [u8; 32],
        /// Native out idx.
        out_idx: u32,
        /// Native wire.
        wire: Vec<u8>,
        /// Native creation.
        creation: Location,
        /// Native spent.
        spent: bool,
        /// Native spend.
        spend: Location,
        /// Native input index.
        input_index: u32,
        /// Native matching positions.
        matching_positions: Vec<u8>,
    }
    /// Native V2 BranchPage transport.
    #[derive(Clone, Debug)]
    struct BranchPage {
        /// Native anchor.
        anchor: Anchor,
        /// Native chain id.
        chain_id: [u8; 32],
        /// Native profile.
        profile: [u8; 32],
        /// Native matches.
        matches: Vec<OutputMatch>,
        /// Native cursor.
        cursor: Continuation,
        /// Native posting reads.
        posting_reads: u64,
        /// Native work.
        work: u64,
        /// Native encoded bytes.
        encoded_bytes: u64,
    }
    extern "Rust" {
        type V2Service;
        type V2Server;
        fn start_v2_server(
            service: &V2Service,
            bind: &str,
        ) -> Result<Box<V2Server>>;
        fn actual_address(self: &V2Server) -> String;
        fn stop(self: &V2Server) -> Result<()>;
        fn invalidate_authority(self: &V2Service) -> Result<u64>;
        fn suspend_authority(self: &V2Service) -> Result<u64>;
        fn publish_authority_context(
            self: &V2Service,
            anchor: Anchor,
            context_generation: u64,
            chain_revision: u64,
        ) -> Result<u64>;
        fn publish_authority(self: &V2Service, anchor: Anchor) -> Result<u64>;
        fn open_service(
            path: &str,
            binding: Binding,
            fresh: bool,
            limits: ServiceLimits,
        ) -> Result<Box<V2Service>>;
        fn initialize_genesis(
            self: &V2Service,
            block: NativeBlock,
        ) -> Result<()>;
        fn connect_block(self: &V2Service, block: NativeBlock) -> Result<()>;
        fn disconnect_block(self: &V2Service, anchor: Anchor) -> Result<()>;
        fn status(self: &V2Service, node: Anchor) -> Result<Status>;
        fn query_branches(
            self: &V2Service,
            request: BranchRequest,
        ) -> Result<BranchPage>;
    }

    unsafe extern "C++" {
        include!("blockindex.h");
        include!("chronik-cpp/chronik_bridge.h");
        include!("chronik-cpp/chronik_validationinterface.h");
        include!("primitives/block.h");

        #[namespace = ""]
        type CBlockIndex = chronik_bridge::ffi::CBlockIndex;
        #[namespace = ""]
        type CBlock = chronik_bridge::ffi::CBlock;
        #[namespace = "chronik_bridge"]
        type ChronikBridge = chronik_bridge::ffi::ChronikBridge;

        fn get_v2_binding(bridge: &ChronikBridge) -> Binding;
        fn bridge_v2_native_block(
            block: &CBlock,
            bindex: &CBlockIndex,
        ) -> Result<NativeBlock>;
    }
}
