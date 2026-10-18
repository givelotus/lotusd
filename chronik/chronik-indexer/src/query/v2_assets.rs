//! Bounded asset pages over the existing immutable confirmed snapshot.
//! Transport owns the common restart/authority fence and binds `after` to its
//! entire normalized route, token, view and snapshot before calling this module.
use bitcoinsuite_core::lotus_v2::{Hash32, OutPoint, OutputRecord};
use chronik_db::{
    v2_asset::{asset_output_key, AssetEvent, AssetReadBudget, AssetSummary},
    v2_branch::ReadSnapshot,
};

/// Trusted caps; work is charged before each source call.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum returned records (1..=100).
    pub page_size: usize,
    /// Maximum examined index entries (1..=1024).
    pub examined: usize,
    /// Maximum storage reads (1..=4096), including secondary joins.
    pub reads: usize,
    /// Maximum logical binary result bytes; transport separately caps JSON.
    pub result_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            page_size: 25,
            examined: 1024,
            reads: 4096,
            result_bytes: 128 * 1024,
        }
    }
}
/// Bounded query failure; corrupt/missing joined records never become empty pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid cap or key shape.
    InvalidLimits,
    /// Wrong family/token or malformed exclusive key.
    InvalidCursor,
    /// Bounded source failure or contradictory persisted facts.
    Source,
    /// Indivisible first result exceeds the page budget.
    RecordLimit,
}
/// Each implementation charges actual storage reads before performing them,
/// including iterator rereads and canonical joins, on this one pinned snapshot.
pub trait Source {
    /// Next summary with a checked canonical first occurrence.
    fn summary(
        &self,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, AssetSummary)>, Error>;
    /// Next event with a checked canonical transaction location.
    fn event(
        &self,
        token: Hash32,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, AssetEvent)>, Error>;
    /// Next output posting, before its output/canonical joins.
    fn posting(
        &self,
        token: Hash32,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, OutPoint)>, Error>;
    /// Complete output with checked canonical creation/spend locations, charging
    /// the output read plus canonical transaction/height joins for creation and
    /// optional spender (at most five reads).
    fn output(
        &self,
        op: OutPoint,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<OutputRecord>, Error>;
}
impl Source for ReadSnapshot<'_> {
    fn summary(
        &self,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, AssetSummary)>, Error> {
        self.next_asset_summary_counted(after, budget)
            .map_err(|_| Error::Source)
    }
    fn event(
        &self,
        token: Hash32,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, AssetEvent)>, Error> {
        self.next_asset_event_counted(token, after, budget)
            .map_err(|_| Error::Source)
    }
    fn posting(
        &self,
        token: Hash32,
        after: Option<&[u8]>,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, OutPoint)>, Error> {
        self.next_asset_output_counted(token, after, budget)
            .map_err(|_| Error::Source)
    }
    fn output(
        &self,
        op: OutPoint,
        budget: &mut AssetReadBudget,
    ) -> Result<Option<OutputRecord>, Error> {
        self.output_counted(op, budget).map_err(|_| Error::Source)
    }
}
/// Exclusive continuation must be wrapped in the common transport cursor.
#[derive(Clone, Debug)]
pub struct Page<T> {
    /// Complete records in prescribed key order.
    pub items: Vec<T>,
    /// Last fully examined key; None only at observed index exhaustion.
    pub next_key: Option<Vec<u8>>,
    /// Whether the requested family/filter is exhausted in this snapshot.
    pub exhausted: bool,
    /// Exact charged storage reads, including exhausted seeks and iterator rereads.
    pub reads: usize,
    /// Actual examined index entries, including filtered outputs.
    pub examined: usize,
}
fn validate(
    limits: Limits,
    prefix: &[u8],
    len: usize,
    after: Option<&[u8]>,
    calls: usize,
) -> Result<(), Error> {
    if limits.page_size == 0
        || limits.page_size > 100
        || limits.examined == 0
        || limits.examined > 1024
        || limits.reads < calls
        || limits.reads > 4096
        || limits.result_bytes == 0
    {
        return Err(Error::InvalidLimits);
    }
    if after.is_some_and(|key| key.len() != len || !key.starts_with(prefix)) {
        return Err(Error::InvalidCursor);
    }
    Ok(())
}
struct RecordCost {
    reads: usize,
    bytes: usize,
}
fn page<T>(
    source: &impl Source,
    prefix: &[u8],
    key_len: usize,
    after: Option<&[u8]>,
    limits: Limits,
    cost: RecordCost,
    mut next: impl FnMut(
        &dyn Source,
        Option<&[u8]>,
        &mut AssetReadBudget,
    ) -> Result<Option<(Vec<u8>, Option<T>)>, Error>,
) -> Result<Page<T>, Error> {
    let RecordCost {
        reads: calls,
        bytes: record_bytes,
    } = cost;
    validate(limits, prefix, key_len, after, calls)?;
    let mut page = Page {
        items: Vec::new(),
        next_key: after.map(Vec::from),
        exhausted: false,
        reads: 0,
        examined: 0,
    };
    let mut bytes = 0usize;
    let mut budget = AssetReadBudget::new(limits.reads);
    loop {
        if page.items.len() == limits.page_size
            || page.examined == limits.examined
            || budget.remaining() < calls
        {
            return Ok(page);
        }
        // Reserve the indivisible joined record before reading. If a prior page
        // item consumed capacity, resume after that item without consuming another.
        if limits.result_bytes - bytes < record_bytes {
            if page.items.is_empty() {
                return Err(Error::RecordLimit);
            }
            return Ok(page);
        }
        let item = next(source, page.next_key.as_deref(), &mut budget)?;
        page.reads = budget.reads();
        let Some((key, item)) = item else {
            page.next_key = None;
            page.exhausted = true;
            return Ok(page);
        };
        if key.len() != key_len
            || !key.starts_with(prefix)
            || page.next_key.as_ref().is_some_and(|old| key <= *old)
        {
            return Err(Error::Source);
        }
        page.examined += 1;
        page.next_key = Some(key);
        if let Some(item) = item {
            bytes += record_bytes;
            page.items.push(item);
        }
    }
}
/// Known assets in native-byte lexicographic order. Native currency is absent.
pub fn assets(
    source: &impl Source,
    after: Option<&[u8]>,
    limits: Limits,
) -> Result<Page<AssetSummary>, Error> {
    page(
        source,
        b"eA",
        34,
        after,
        limits,
        RecordCost {
            reads: 4,
            bytes: 512,
        },
        |s, a, budget| Ok(s.summary(a, budget)?.map(|(k, v)| (k, Some(v)))),
    )
}
/// One aggregate event per touched transaction in height/index order.
pub fn events(
    source: &impl Source,
    token: Hash32,
    after: Option<&[u8]>,
    limits: Limits,
) -> Result<Page<AssetEvent>, Error> {
    let prefix = [b"eE".as_slice(), &token.0].concat();
    page(
        source,
        &prefix,
        46,
        after,
        limits,
        RecordCost {
            reads: 4,
            bytes: 512,
        },
        |s, a, budget| {
            Ok(s.event(token, a, budget)?.map(|(k, v)| (k, Some(v))))
        },
    )
}
/// History includes burns; unspent excludes spent outputs and burns. Filtering
/// can yield an empty advancing page when the examined/work budget is consumed.
pub fn outputs(
    source: &impl Source,
    token: Hash32,
    unspent: bool,
    after: Option<&[u8]>,
    limits: Limits,
) -> Result<Page<OutputRecord>, Error> {
    let prefix = [b"eP".as_slice(), &token.0].concat();
    page(
        source,
        &prefix,
        50,
        after,
        limits,
        RecordCost {
            reads: 7,
            bytes: 2048,
        },
        |s, a, budget| {
            let Some((key, op)) = s.posting(token, a, budget)? else {
                return Ok(None);
            };
            let record = s.output(op, budget)?.ok_or(Error::Source)?;
            if record.outpoint != op
                || !record.output.has_token()
                || record.output.token_id != token
                || key != asset_output_key(token, record.creation, op.out_idx)
                || record.creation.txid != op.txid
            {
                return Err(Error::Source);
            }
            let include = !unspent
                || (record.spend.is_none() && !record.output.is_burn());
            Ok(Some((key, include.then_some(record))))
        },
    )
}

#[cfg(test)]
#[path = "v2_assets_test.rs"]
mod tests;
