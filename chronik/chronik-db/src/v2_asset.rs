//! Pure native asset accounting and read-only indexes. The transition owner
//! applies these plans in its existing receipt/undo batch; this module never writes.
use std::collections::{BTreeMap, BTreeSet};

use bitcoinsuite_core::lotus_v2::{Hash32, OutPoint, Output, TxId, TxLocation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    v2_branch::{Error, ReadSnapshot},
    v2_explorer::native_serde,
};

type Result<T> = std::result::Result<T, Error>;
const MAX_RECORD_BYTES: usize = 512;

/// Asset facts of a consumed coin: its flags, value and token, as recorded by
/// the index when the coin was created. The branches and paths of the output
/// are not needed for asset accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpentCoin {
    /// Consumed output identity.
    pub outpoint: OutPoint,
    /// Native output flags (`1` token, `2` burn).
    pub flags: u8,
    /// Native output value.
    pub value: u64,
    /// Token identity, zero when the output carries no token.
    pub token_id: Hash32,
}
impl SpentCoin {
    /// Asset facts of `output` at `outpoint`.
    pub fn from_output(outpoint: OutPoint, output: &Output) -> Self {
        SpentCoin {
            outpoint,
            flags: output.flags,
            value: output.value,
            token_id: output.token_id,
        }
    }
    /// Whether the output carries a token.
    pub fn has_token(&self) -> bool {
        self.flags & 1 != 0
    }
    /// Whether the output is a burn commitment.
    pub fn is_burn(&self) -> bool {
        self.flags & 2 != 0
    }
    fn valid(&self) -> bool {
        self.flags & !7 == 0
            && self.has_token() == (self.token_id != Hash32::default())
    }
}

/// Immutable facts resolved by the authoritative transition owner before spending.
#[derive(Clone, Copy, Debug)]
pub struct AssetTxView<'a> {
    /// Exact confirmed transaction position.
    pub location: TxLocation,
    /// All outputs, including native outputs, zero units, and burns.
    pub outputs: &'a [Output],
    /// Frozen prior creations; not the runtime's current UTXO view.
    pub resolved_spends: &'a [SpentCoin],
    /// One selector per mint input; duplicates must remain visible.
    pub mint_token_ids: &'a [Hash32],
}

/// Aggregate effects for one token in one canonical transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEvent {
    /// Native token identity.
    #[serde(with = "native_serde::hash")]
    pub token_id: Hash32,
    /// Exact event position, including both transaction identities.
    #[serde(with = "native_serde::location")]
    pub location: TxLocation,
    /// Total resolved input units.
    pub spent_units: u128,
    /// Total output units, including explicit burns.
    pub output_units: u128,
    /// Units in burn output commitments.
    pub explicit_burn_units: u128,
    /// Positive output minus input difference.
    pub minted_units: u128,
    /// Positive input minus output difference.
    pub implicit_burn_units: u128,
    /// Whether the native mint input selects this token.
    pub has_mint_input: bool,
}

/// Covered-history occurrence counts. Supply and external metadata are unknown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetSummary {
    /// Native token identity.
    #[serde(with = "native_serde::hash")]
    pub token_id: Hash32,
    /// First covered canonical occurrence, not an issuer or unique genesis.
    #[serde(with = "native_serde::location")]
    pub first_seen: TxLocation,
    /// Number of touched transactions.
    pub event_count: u64,
    /// Number of created token outputs, including burns and zero values.
    pub output_count: u64,
}

fn add(total: &mut u128, value: u64) -> Result<()> {
    *total = total
        .checked_add(u128::from(value))
        .ok_or(Error::Invalid("asset amount overflow"))?;
    Ok(())
}

/// Derive the full token union and enforce the native positive-delta/mint bijection.
/// The caller supplies authenticated complete facts; no consensus engine runs here.
pub fn derive_asset_events(view: AssetTxView<'_>) -> Result<Vec<AssetEvent>> {
    preflight_asset_tx(view)?;
    let mut totals = BTreeMap::<Hash32, (u128, u128, u128)>::new();
    let mut spent = BTreeSet::new();
    for coin in view.resolved_spends {
        if !spent.insert(coin.outpoint) || coin.is_burn() {
            return Err(Error::Invalid("duplicate or burned asset spend"));
        }
        if !coin.valid() {
            return Err(Error::Invalid("asset spend output"));
        }
        if coin.has_token() {
            add(&mut totals.entry(coin.token_id).or_default().0, coin.value)?;
        }
    }
    for output in view.outputs {
        output
            .validate()
            .map_err(|_| Error::Invalid("asset output"))?;
        if output.has_token() {
            let total = totals.entry(output.token_id).or_default();
            add(&mut total.1, output.value)?;
            if output.is_burn() {
                add(&mut total.2, output.value)?;
            }
        }
    }
    let mut mints = BTreeSet::new();
    for &token in view.mint_token_ids {
        if token == Hash32::default() || !mints.insert(token) {
            return Err(Error::Invalid("duplicate or zero asset mint selector"));
        }
        totals.entry(token).or_default();
    }
    totals
        .into_iter()
        .map(
            |(token_id, (spent_units, output_units, explicit_burn_units))| {
                let minted_units = output_units.saturating_sub(spent_units);
                let has_mint_input = mints.contains(&token_id);
                if (minted_units > 0) != has_mint_input {
                    return Err(Error::Invalid("asset mint/delta mismatch"));
                }
                Ok(AssetEvent {
                    token_id,
                    location: view.location,
                    spent_units,
                    output_units,
                    explicit_burn_units,
                    minted_units,
                    implicit_burn_units: spent_units.saturating_sub(output_units),
                    has_mint_input,
                })
            },
        )
        .collect()
}

/// Conservative reservation for this module's maps, events, summaries and writes.
/// The batch owner reserves more per element (old values, receipts, undo and
/// read keys) against the index bounds (`v2_branch::Bounds`).
pub fn preflight_asset_tx(view: AssetTxView<'_>) -> Result<usize> {
    let count = view
        .outputs
        .len()
        .checked_add(view.resolved_spends.len())
        .and_then(|n| n.checked_add(view.mint_token_ids.len()))
        .ok_or(Error::Invalid("asset capacity"))?;
    count
        .checked_mul(4096)
        .ok_or(Error::Invalid("asset capacity"))
}

/// Exact registry key, with native digest order.
pub fn asset_summary_key(token: Hash32) -> Vec<u8> {
    [b"eA".as_slice(), &token.0].concat()
}
/// Exact event key in canonical height/index order.
pub fn asset_event_key(token: Hash32, location: TxLocation) -> Vec<u8> {
    [
        b"eE".as_slice(),
        &token.0,
        &location.height.to_be_bytes(),
        &location.tx_index.to_be_bytes(),
    ]
    .concat()
}
/// Exact creation posting key, including the native output ordinal.
pub fn asset_output_key(token: Hash32, location: TxLocation, out_idx: u32) -> Vec<u8> {
    [
        b"eP".as_slice(),
        &token.0,
        &location.height.to_be_bytes(),
        &location.tx_index.to_be_bytes(),
        &out_idx.to_be_bytes(),
    ]
    .concat()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = postcard::to_allocvec(value).map_err(|_| Error::Corrupt)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid("asset record limit"));
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Corrupt);
    }
    postcard::from_bytes(bytes).map_err(|_| Error::Corrupt)
}

/// Encode a bounded summary for the parent's atomic batch.
pub fn encode_asset_summary(summary: &AssetSummary) -> Result<Vec<u8>> {
    encode(summary)
}
/// Decode a bounded summary from receipt/undo or staged state.
pub fn decode_asset_summary(bytes: &[u8]) -> Result<AssetSummary> {
    let summary: AssetSummary = decode(bytes)?;
    if summary.token_id == Hash32::default() || summary.event_count == 0 {
        return Err(Error::Corrupt);
    }
    Ok(summary)
}

/// Pure complete write plan. Old summaries must come from staged state first.
/// Recomputing with the undo's old summaries yields the exact owned keys/values.
pub fn plan_asset_tx(
    view: AssetTxView<'_>,
    old: &BTreeMap<Hash32, Option<AssetSummary>>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    preflight_asset_tx(view)?;
    let events = derive_asset_events(view)?;
    let mut writes = Vec::new();
    let mut counts = BTreeMap::<Hash32, u64>::new();
    for output in view.outputs.iter().filter(|o| o.has_token()) {
        let count = counts.entry(output.token_id).or_default();
        *count = count
            .checked_add(1)
            .ok_or(Error::Invalid("asset output count"))?;
    }
    for event in events {
        let count = counts.get(&event.token_id).copied().unwrap_or(0);
        let previous = old
            .get(&event.token_id)
            .ok_or(Error::Invalid("missing old asset summary"))?;
        let summary = match previous {
            Some(s) => {
                if s.token_id != event.token_id
                    || s.event_count == 0
                    // In a block in canonical (txid) order, an in-block
                    // parent applied first can sit at a later position.
                    || s.first_seen.height > view.location.height
                {
                    return Err(Error::Corrupt);
                }
                AssetSummary {
                    event_count: s
                        .event_count
                        .checked_add(1)
                        .ok_or(Error::Invalid("asset event count overflow"))?,
                    output_count: s
                        .output_count
                        .checked_add(count)
                        .ok_or(Error::Invalid("asset output count overflow"))?,
                    ..s.clone()
                }
            }
            None => AssetSummary {
                token_id: event.token_id,
                first_seen: view.location,
                event_count: 1,
                output_count: count,
            },
        };
        writes.push((asset_summary_key(event.token_id), encode(&summary)?));
        writes.push((
            asset_event_key(event.token_id, view.location),
            encode(&event)?,
        ));
    }
    for (index, output) in view
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| o.has_token())
    {
        let index = u32::try_from(index).map_err(|_| Error::Invalid("asset output ordinal"))?;
        let mut op = view.location.txid.0 .0.to_vec();
        op.extend(index.to_be_bytes());
        writes.push((asset_output_key(output.token_id, view.location, index), op));
    }
    Ok(writes)
}

/// Storage-read budget, shared by initial existence joins and page reads.
/// Every charge happens before the corresponding get/iterator advancement.
#[derive(Debug)]
pub struct AssetReadBudget {
    limit: usize,
    reads: usize,
}
impl AssetReadBudget {
    /// Trusted maximum number of reads for this operation.
    pub fn new(limit: usize) -> Self {
        Self { limit, reads: 0 }
    }
    /// Number of reads already charged, including exhausted iterator seeks.
    pub fn reads(&self) -> usize {
        self.reads
    }
    /// Remaining read capacity.
    pub fn remaining(&self) -> usize {
        self.limit - self.reads
    }
    /// Reserve one read before invoking storage, including joins outside this module.
    pub fn charge(&mut self) -> Result<()> {
        if self.reads == self.limit {
            return Err(Error::Invalid("asset read budget"));
        }
        self.reads += 1;
        Ok(())
    }
}

impl ReadSnapshot<'_> {
    fn asset_canonical_location(
        &self,
        location: TxLocation,
        budget: &mut AssetReadBudget,
    ) -> Result<()> {
        if self.transaction_counted(location.txid, budget)? != Some(location) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    /// Read one validated summary; bounded callers use the counted variant.
    pub fn asset_summary(&self, token: Hash32) -> Result<Option<AssetSummary>> {
        self.asset_summary_counted(token, &mut AssetReadBudget::new(usize::MAX))
    }
    /// Point read plus exact canonical-location join (at most three reads).
    pub fn asset_summary_counted(
        &self,
        token: Hash32,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<AssetSummary>> {
        budget.charge()?;
        self.inner
            .get(asset_summary_key(token))?
            .map(|b| {
                let s: AssetSummary = decode(&b)?;
                if token == Hash32::default()
                    || s.token_id != token
                    || s.event_count == 0
                    || s.first_seen.height > self.anchor.height
                {
                    return Err(Error::Corrupt);
                }
                self.asset_canonical_location(s.first_seen, budget)?;
                Ok(s)
            })
            .transpose()
    }
    fn next_asset_raw(
        &self,
        prefix: &[u8],
        key_len: usize,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if after.is_some_and(|k| k.len() != key_len || !k.starts_with(prefix)) {
            return Err(Error::Invalid("asset cursor key"));
        }
        let Some((key, value)) = self
            .inner
            .seek_next_regular(prefix, after, || budget.charge())?
        else {
            return Ok(None);
        };
        if key.len() != key_len || value.len() > MAX_RECORD_BYTES {
            return Err(Error::Corrupt);
        }
        Ok(Some((key, value)))
    }
    /// Exclusive registry iterator; bounded callers use the counted variant.
    pub fn next_asset_summary(
        &self,
        after: Option<&[u8]>,
    ) -> Result<Option<(Vec<u8>, AssetSummary)>> {
        self.next_asset_summary_counted(after, &mut AssetReadBudget::new(usize::MAX))
    }
    /// At most two iterator advancements plus two canonical-location reads.
    pub fn next_asset_summary_counted(
        &self,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, AssetSummary)>> {
        self.next_asset_raw(b"eA", 34, after, budget)?
            .map(|(key, bytes)| {
                let s: AssetSummary = decode(&bytes)?;
                if s.token_id == Hash32::default()
                    || s.token_id.0 != key[2..]
                    || s.event_count == 0
                    || s.first_seen.height > self.anchor.height
                {
                    return Err(Error::Corrupt);
                }
                self.asset_canonical_location(s.first_seen, budget)?;
                Ok((key, s))
            })
            .transpose()
    }
    /// Exclusive event iterator; bounded callers use the counted variant.
    pub fn next_asset_event(
        &self,
        token: Hash32,
        after: Option<&[u8]>,
    ) -> Result<Option<(Vec<u8>, AssetEvent)>> {
        self.next_asset_event_counted(token, after, &mut AssetReadBudget::new(usize::MAX))
    }
    /// At most two iterator advancements plus two canonical-location reads.
    pub fn next_asset_event_counted(
        &self,
        token: Hash32,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, AssetEvent)>> {
        let prefix = [b"eE".as_slice(), &token.0].concat();
        self.next_asset_raw(&prefix, 46, after, budget)?
            .map(|(key, bytes)| {
                let e: AssetEvent = decode(&bytes)?;
                if token == Hash32::default()
                    || e.token_id != token
                    || key != asset_event_key(token, e.location)
                    || e.location.height > self.anchor.height
                    || e.explicit_burn_units > e.output_units
                    || e.minted_units != e.output_units.saturating_sub(e.spent_units)
                    || e.implicit_burn_units != e.spent_units.saturating_sub(e.output_units)
                    || e.has_mint_input != (e.minted_units > 0)
                {
                    return Err(Error::Corrupt);
                }
                self.asset_canonical_location(e.location, budget)?;
                Ok((key, e))
            })
            .transpose()
    }
    /// Exclusive output iterator; creation/existence is joined by the query owner.
    pub fn next_asset_output(
        &self,
        token: Hash32,
        after: Option<&[u8]>,
    ) -> Result<Option<(Vec<u8>, OutPoint)>> {
        self.next_asset_output_counted(token, after, &mut AssetReadBudget::new(usize::MAX))
    }
    /// At most two iterator advancements. Output and canonical joins are additional.
    pub fn next_asset_output_counted(
        &self,
        token: Hash32,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, OutPoint)>> {
        let prefix = [b"eP".as_slice(), &token.0].concat();
        self.next_asset_raw(&prefix, 50, after, budget)?
            .map(|(key, bytes)| {
                if token == Hash32::default()
                    || bytes.len() != 36
                    || bytes[32..] != key[46..]
                    || u64::from_be_bytes(key[34..42].try_into().map_err(|_| Error::Corrupt)?)
                        > self.anchor.height
                {
                    return Err(Error::Corrupt);
                }
                let op = OutPoint {
                    txid: TxId(Hash32(bytes[..32].try_into().map_err(|_| Error::Corrupt)?)),
                    out_idx: u32::from_be_bytes(
                        bytes[32..].try_into().map_err(|_| Error::Corrupt)?,
                    ),
                };
                Ok((key, op))
            })
            .transpose()
    }
}

#[cfg(test)]
#[path = "v2_asset_test.rs"]
mod tests;
