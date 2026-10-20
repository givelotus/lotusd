// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! V2 output branch root (`key_branch`, `script_branch`, `data_branch`) and
//! `AssetId` (`token_id`) group implementations for Chronik's [`Group`]
//! indexing architecture.

use bitcoinsuite_core::{
    lotus_v2::{Hash32, Output as V2Output},
    script::Script,
};

use crate::{
    db::{
        CF_V2_ASSET_HISTORY, CF_V2_ASSET_HISTORY_NUM_TXS, CF_V2_ASSET_UTXO,
        CF_V2_BRANCH_HISTORY, CF_V2_BRANCH_HISTORY_NUM_TXS, CF_V2_BRANCH_UTXO,
    },
    group::{Group, GroupQuery, MemberItem, UtxoDataValue},
    io::{
        GroupHistoryConf, GroupHistoryReader, GroupHistoryWriter,
        GroupUtxoConf, GroupUtxoReader, GroupUtxoWriter,
    },
    mem::{MempoolGroupHistory, MempoolGroupUtxos},
};

/// Index the mempool tx history of V2 branch root hashes.
pub type MempoolV2BranchHistory = MempoolGroupHistory<V2BranchGroup>;
/// Index the mempool UTXOs of V2 branch root hashes.
pub type MempoolV2BranchUtxos = MempoolGroupUtxos<V2BranchGroup>;
/// Index the tx history of V2 branch root hashes in the DB.
pub type V2BranchHistoryWriter<'a> = GroupHistoryWriter<'a, V2BranchGroup>;
/// Read the tx history of V2 branch root hashes in the DB.
pub type V2BranchHistoryReader<'a> = GroupHistoryReader<'a, V2BranchGroup>;
/// Index the UTXOs of V2 branch root hashes in the DB.
pub type V2BranchUtxoWriter<'a> = GroupUtxoWriter<'a, V2BranchGroup>;
/// Read the UTXOs of V2 branch root hashes in the DB.
pub type V2BranchUtxoReader<'a> = GroupUtxoReader<'a, V2BranchGroup>;

/// Index the mempool tx history of V2 asset IDs.
pub type MempoolV2AssetHistory = MempoolGroupHistory<V2AssetGroup>;
/// Index the mempool UTXOs of V2 asset IDs.
pub type MempoolV2AssetUtxos = MempoolGroupUtxos<V2AssetGroup>;
/// Index the tx history of V2 asset IDs in the DB.
pub type V2AssetHistoryWriter<'a> = GroupHistoryWriter<'a, V2AssetGroup>;
/// Read the tx history of V2 asset IDs in the DB.
pub type V2AssetHistoryReader<'a> = GroupHistoryReader<'a, V2AssetGroup>;
/// Index the UTXOs of V2 asset IDs in the DB.
pub type V2AssetUtxoWriter<'a> = GroupUtxoWriter<'a, V2AssetGroup>;
/// Read the UTXOs of V2 asset IDs in the DB.
pub type V2AssetUtxoReader<'a> = GroupUtxoReader<'a, V2AssetGroup>;

/// Helper representing a Lotus V2 3-branch Taproot-style output
/// (`key_branch`, optional `script_branch`, optional `data_branch`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2ThreeBranchOutput {
    /// Primary key branch authorization root (`32` bytes).
    pub key_branch: Hash32,
    /// Optional script branch authorization root (`32` bytes).
    pub script_branch: Option<Hash32>,
    /// Optional data commitment branch root (`32` bytes).
    pub data_branch: Option<Hash32>,
    /// Optional V2 `AssetId` (`32` bytes).
    pub asset_id: Option<Hash32>,
    /// Native or token quantity.
    pub value: u64,
    /// Whether this output is a burn commitment.
    pub is_burn: bool,
}

impl V2ThreeBranchOutput {
    /// Convert this 3-branch output into a canonical [`V2Output`].
    pub fn to_v2_output(&self) -> V2Output {
        let mut branches = Vec::with_capacity(3);
        branches.push(self.key_branch);
        if let Some(script_branch) = self.script_branch {
            if !branches.contains(&script_branch) {
                branches.push(script_branch);
            }
        }
        if let Some(data_branch) = self.data_branch {
            if !branches.contains(&data_branch) {
                branches.push(data_branch);
            }
        }
        let mut flags = 0u8;
        let token_id = match self.asset_id {
            Some(id) if id != Hash32::default() => {
                flags |= 1;
                id
            }
            _ => Hash32::default(),
        };
        if self.is_burn {
            flags |= 2;
        }
        let paths = if self.is_burn {
            Vec::new()
        } else {
            (0..branches.len() as u8).map(|idx| vec![idx]).collect()
        };
        V2Output {
            legacy_script: None,
            flags,
            value: self.value,
            token_id,
            state_root: Hash32::default(),
            branches,
            paths,
        }
    }

    /// Encode this 3-branch output as a [`Script`] carrying the canonical V2
    /// output wire frame.
    pub fn to_script(&self) -> Option<Script> {
        let v2_out = self.to_v2_output();
        let bytes = v2_out.encode().ok()?;
        Some(Script::new(bytes.into()))
    }
}

/// Decode a [`Script`] as a canonical Lotus V2 [`V2Output`] if it matches the
/// V2 output wire grammar (or `0x6a || wire` from `CTxOut::FromV2Output` on
/// burn outputs).
pub fn decode_v2_output_script(script: &Script) -> Option<V2Output> {
    let bytes = script.bytecode().as_ref();
    if let Ok(out) = V2Output::decode(bytes) {
        return Some(out);
    }
    if bytes.first() == Some(&0x6a) && bytes.len() >= 44 {
        if let Ok(out) = V2Output::decode(&bytes[1..]) {
            return Some(out);
        }
    }
    None
}

/// Group transactions by Lotus V2 output branch root hashes (`Hash32`).
#[derive(Clone, Copy, Debug, Default)]
pub struct V2BranchGroup;

impl Group for V2BranchGroup {
    type Aux = ();
    type Iter<'a> = Vec<MemberItem<Hash32>>;
    type Member<'a> = Hash32;
    type MemberSer = [u8; 32];
    type UtxoData = UtxoDataValue;

    fn input_members<'a>(
        &self,
        query: GroupQuery<'a>,
        _aux: &(),
    ) -> Self::Iter<'a> {
        if query.is_coinbase {
            return Vec::new();
        }
        let mut items = Vec::new();
        for (idx, input) in query.tx.inputs.iter().enumerate() {
            let Some(coin) = &input.coin else {
                continue;
            };
            if coin.is_legacy {
                continue;
            }
            if let Some(v2_out) = decode_v2_output_script(&coin.output.script) {
                for branch in v2_out.branches {
                    items.push(MemberItem {
                        idx,
                        member: branch,
                    });
                }
            }
        }
        items
    }

    fn output_members<'a>(
        &self,
        query: GroupQuery<'a>,
        _aux: &(),
    ) -> Self::Iter<'a> {
        if query.tx.version != 7 {
            return Vec::new();
        }
        let mut items = Vec::new();
        for (idx, output) in query.tx.outputs.iter().enumerate() {
            if let Some(v2_out) = decode_v2_output_script(&output.script) {
                if v2_out.is_burn() {
                    continue;
                }
                for branch in v2_out.branches {
                    items.push(MemberItem {
                        idx,
                        member: branch,
                    });
                }
            }
        }
        items
    }

    fn ser_member(&self, member: &Self::Member<'_>) -> Self::MemberSer {
        member.0
    }

    fn is_hash_member_supported(&self) -> bool {
        false
    }

    fn ser_hash_member(&self, member: &Self::Member<'_>) -> [u8; 32] {
        member.0
    }

    fn tx_history_conf() -> GroupHistoryConf {
        GroupHistoryConf {
            cf_page_name: CF_V2_BRANCH_HISTORY,
            cf_num_txs_name: CF_V2_BRANCH_HISTORY_NUM_TXS,
            page_size: 1000,
            cf_member_hash_name: None,
        }
    }

    fn utxo_conf() -> GroupUtxoConf {
        GroupUtxoConf {
            cf_name: CF_V2_BRANCH_UTXO,
        }
    }
}

/// Group transactions by Lotus V2 32-byte `AssetId` (`token_id`).
#[derive(Clone, Copy, Debug, Default)]
pub struct V2AssetGroup;

impl Group for V2AssetGroup {
    type Aux = ();
    type Iter<'a> = Vec<MemberItem<Hash32>>;
    type Member<'a> = Hash32;
    type MemberSer = [u8; 32];
    type UtxoData = UtxoDataValue;

    fn input_members<'a>(
        &self,
        query: GroupQuery<'a>,
        _aux: &(),
    ) -> Self::Iter<'a> {
        if query.is_coinbase {
            return Vec::new();
        }
        let mut items = Vec::new();
        for (idx, input) in query.tx.inputs.iter().enumerate() {
            let Some(coin) = &input.coin else {
                continue;
            };
            if coin.is_legacy {
                continue;
            }
            if let Some(v2_out) = decode_v2_output_script(&coin.output.script) {
                if v2_out.has_token() {
                    items.push(MemberItem {
                        idx,
                        member: v2_out.token_id,
                    });
                }
            }
        }
        items
    }

    fn output_members<'a>(
        &self,
        query: GroupQuery<'a>,
        _aux: &(),
    ) -> Self::Iter<'a> {
        if query.tx.version != 7 {
            return Vec::new();
        }
        let mut items = Vec::new();
        for (idx, output) in query.tx.outputs.iter().enumerate() {
            if let Some(v2_out) = decode_v2_output_script(&output.script) {
                if v2_out.has_token() && !v2_out.is_burn() {
                    items.push(MemberItem {
                        idx,
                        member: v2_out.token_id,
                    });
                }
            }
        }
        items
    }

    fn ser_member(&self, member: &Self::Member<'_>) -> Self::MemberSer {
        member.0
    }

    fn is_hash_member_supported(&self) -> bool {
        false
    }

    fn ser_hash_member(&self, member: &Self::Member<'_>) -> [u8; 32] {
        member.0
    }

    fn tx_history_conf() -> GroupHistoryConf {
        GroupHistoryConf {
            cf_page_name: CF_V2_ASSET_HISTORY,
            cf_num_txs_name: CF_V2_ASSET_HISTORY_NUM_TXS,
            page_size: 1000,
            cf_member_hash_name: None,
        }
    }

    fn utxo_conf() -> GroupUtxoConf {
        GroupUtxoConf {
            cf_name: CF_V2_ASSET_UTXO,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoinsuite_core::{
        lotus_v2::Hash32,
        tx::{Coin, Tx, TxId, TxInput, TxMut, TxOutput},
    };

    use super::{V2AssetGroup, V2BranchGroup, V2ThreeBranchOutput};
    use crate::group::{tx_members_for_group, Group, GroupQuery, MemberItem};

    #[test]
    fn test_v2_three_branch_and_asset_groups() {
        let key_branch = Hash32([0x11; 32]);
        let script_branch = Hash32([0x22; 32]);
        let data_branch = Hash32([0x33; 32]);
        let asset_id = Hash32([0xaa; 32]);

        let in_script = V2ThreeBranchOutput {
            key_branch,
            script_branch: Some(script_branch),
            data_branch: None,
            asset_id: Some(asset_id),
            value: 500,
            is_burn: false,
        }
        .to_script()
        .unwrap();

        let out_spendable = V2ThreeBranchOutput {
            key_branch,
            script_branch: Some(script_branch),
            data_branch: Some(data_branch),
            asset_id: Some(asset_id),
            value: 300,
            is_burn: false,
        }
        .to_script()
        .unwrap();

        let out_burn = V2ThreeBranchOutput {
            key_branch: Hash32([0x99; 32]),
            script_branch: None,
            data_branch: None,
            asset_id: Some(asset_id),
            value: 200,
            is_burn: true,
        }
        .to_script()
        .unwrap();

        let tx = Tx::with_txid(
            TxId::from([1; 32]),
            TxMut {
                native_txid: None,
                version: 7,
                inputs: vec![TxInput {
                    coin: Some(Coin {
                        output: TxOutput {
                            sats: 500,
                            script: in_script,
                        },
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                outputs: vec![
                    TxOutput {
                        sats: 300,
                        script: out_spendable,
                    },
                    TxOutput {
                        sats: 200,
                        script: out_burn,
                    },
                ],
                locktime: 0,
            },
        );

        let query = GroupQuery {
            is_coinbase: false,
            tx: &tx,
        };

        let branch_group = V2BranchGroup;
        assert_eq!(
            branch_group.input_members(query, &()),
            vec![
                MemberItem {
                    idx: 0,
                    member: key_branch,
                },
                MemberItem {
                    idx: 0,
                    member: script_branch,
                },
            ],
        );
        assert_eq!(
            branch_group.output_members(query, &()),
            vec![
                MemberItem {
                    idx: 0,
                    member: key_branch,
                },
                MemberItem {
                    idx: 0,
                    member: script_branch,
                },
                MemberItem {
                    idx: 0,
                    member: data_branch,
                },
            ],
        );
        assert_eq!(
            tx_members_for_group(&branch_group, query, &()).collect::<Vec<_>>(),
            vec![
                key_branch,
                script_branch,
                key_branch,
                script_branch,
                data_branch,
            ],
        );

        let asset_group = V2AssetGroup;
        assert_eq!(
            asset_group.input_members(query, &()),
            vec![MemberItem {
                idx: 0,
                member: asset_id,
            }],
        );
        assert_eq!(
            asset_group.output_members(query, &()),
            vec![MemberItem {
                idx: 0,
                member: asset_id,
            }],
        );

        // Identical bytes in a legacy script do not create native roots.
        let mut legacy: TxMut = tx.clone().into();
        legacy.version = 2;
        legacy.native_txid = None;
        legacy.inputs[0].coin.as_mut().unwrap().is_legacy = true;
        let legacy = Tx::with_txid(TxId::from([2; 32]), legacy);
        let query = GroupQuery {
            is_coinbase: false,
            tx: &legacy,
        };
        assert!(branch_group.input_members(query, &()).is_empty());
        assert!(branch_group.output_members(query, &()).is_empty());
        assert!(asset_group.input_members(query, &()).is_empty());
        assert!(asset_group.output_members(query, &()).is_empty());
        let mut bridge: TxMut = legacy.into();
        bridge.version = 7;
        let bridge = Tx::with_txid(TxId::from([3; 32]), bridge);
        let query = GroupQuery {
            is_coinbase: false,
            tx: &bridge,
        };
        assert!(branch_group.input_members(query, &()).is_empty());
        assert!(asset_group.input_members(query, &()).is_empty());
        assert!(!branch_group.output_members(query, &()).is_empty());
    }
}
