//! Bounded confirmed V2 branch discovery over a pinned posting snapshot.
//! Roots use native wire byte order. Matching does not imply ownership.
use bitcoinsuite_core::{
    hash::{Hashed, Sha256},
    lotus_v2::{Hash32, OutPoint, Output, OutputRecord},
};

#[derive(Clone, Debug, Eq, PartialEq)]
/// Roots accepted at one public branch position.
pub struct PositionClause {
    /// Zero-based public branch vector position, in 0..16.
    pub position: u8,
    /// Root alternatives in native wire byte order.
    pub roots: Vec<Hash32>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// OR within selectors and AND across position clauses, on the same output.
pub struct BranchFilter {
    /// Root alternatives accepted at any public branch position.
    pub any_branch: Vec<Hash32>,
    /// Position clauses, all of which must match the same output.
    pub positions: Vec<PositionClause>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Confirmed output selection and burn policy.
pub enum QueryKind {
    /// Output creation/spend records, deduplicated by outpoint. This is not a
    /// transaction history projection; multiple outputs may share a TxID.
    History {
        /// Whether creation history includes burn commitments.
        include_burn: bool,
    },
    /// Unspent outputs; burns are always excluded.
    Utxos,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Immutable indexed chain and profile identity anchoring query reads.
pub struct Snapshot {
    /// Native chain identifier.
    pub chain_id: Hash32,
    /// Deployment profile identity.
    pub profile_id: Hash32,
    /// Indexed tip block identity.
    pub tip: Hash32,
    /// Indexed tip height.
    pub height: u64,
}
/// Fixed-size, typed continuation. Transport encoding is a separate concern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cursor {
    /// Cursor schema version, currently 1.
    pub version: u8,
    /// Immutable indexed identity anchoring this cursor or response.
    pub snapshot: Snapshot,
    /// Canonical filter and query-kind SHA256 commitment.
    pub filter_digest: Hash32,
    /// Last fully processed outpoint, excluded from subsequent seeks.
    pub last_key: Option<OutPoint>,
}
#[derive(Clone, Copy, Debug)]
/// Trusted per-request allocation and per-page read/result caps.
pub struct Limits {
    /// Maximum input roots across all selectors, before deduplication.
    pub roots: usize,
    /// Maximum positional clauses, also limited by the 16 native positions.
    pub clauses: usize,
    /// Maximum matching output records returned per page.
    pub page_size: usize,
    /// Number of posting seeks allowed or consumed by the page.
    pub posting_reads: usize,
    /// Source read calls (posting seeks plus output lookups), not CPU time or
    /// resident memory. Predicate/encoding work is bounded by request root caps
    /// and the native 16-branch, 812-byte output grammar.
    pub work: usize,
    /// Logical binary record bytes; transport encoding needs its own cap.
    pub result_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            roots: 256,
            clauses: 16,
            page_size: 100,
            posting_reads: 4096,
            work: 8192,
            result_bytes: 128 * 1024,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Filter, capacity, snapshot or source failure.
pub enum QueryError {
    /// Empty, duplicate-position, out-of-range or oversized filter.
    InvalidFilter,
    /// Limits cannot process at least one complete candidate.
    InvalidLimits,
    /// Cursor version, snapshot or filter differs from this query.
    StaleCursor,
    /// Posting/source inconsistency or bounded read failure.
    Source(&'static str),
    /// One matching output exceeds the complete page byte budget.
    RecordTooLarge,
}
/// Each call must be bounded: seek to the first strictly greater key in this
/// root/optional-position posting, with no scan over unrelated output records.
/// All methods operate on the same immutable snapshot, including spend state.
pub trait PostingSource {
    /// Identity shared by every read from this source.
    fn snapshot(&self) -> Snapshot;
    /// Seek the smallest matching outpoint strictly after `after`.
    fn next_posting(
        &self,
        root: Hash32,
        position: Option<u8>,
        after: Option<OutPoint>,
    ) -> Result<Option<OutPoint>, QueryError>;
    /// Return at most one native record. Enforce a fixed serialized record cap
    /// before deserialization/allocation (2048 bytes suffices for this model),
    /// and MAX_OUTPUT_BYTES before decoding the native output frame. Reject
    /// malformed counts before allocating branch/path vectors. Never return
    /// unchecked arbitrarily sized vectors: kernel validation occurs after the
    /// source has already allocated its result. Database corruption is an error.
    fn output(&self, key: OutPoint)
        -> Result<Option<OutputRecord>, QueryError>;
}
#[derive(Clone, Debug)]
/// One matching output and the public positions satisfying selectors.
pub struct Match {
    /// Complete public output, creation location and optional spend.
    pub record: OutputRecord,
    /// Ascending public positions satisfying at least one selector.
    pub matching_positions: Vec<u8>,
}
#[derive(Clone, Debug)]
/// A page of complete output records, with each outpoint included at most once.
/// `work` counts source read calls; response transport size is a separate bound.
pub struct Page {
    /// Immutable indexed identity anchoring this cursor or response.
    pub snapshot: Snapshot,
    /// Matching complete output records in ascending outpoint order.
    pub matches: Vec<Match>,
    /// Resume token when capacity ended this page; absent at posting end.
    pub continuation: Option<Cursor>,
    /// Number of posting seeks allowed or consumed by the page.
    pub posting_reads: usize,
    /// Consumed posting-seek and output-lookup calls, excluding CPU time.
    pub work: usize,
    /// Logical binary record bytes; transport encoding needs its own cap.
    pub result_bytes: usize,
}
impl BranchFilter {
    /// Bounds are checked before sorting/copying root arrays. Duplicate roots
    /// are set members; duplicate positions and empty clauses are invalid.
    pub fn canonicalize(&self, limits: Limits) -> Result<Self, QueryError> {
        if self.positions.len() > limits.clauses || self.positions.len() > 16 {
            return Err(QueryError::InvalidFilter);
        }
        let count = self
            .positions
            .iter()
            .try_fold(self.any_branch.len(), |n, c| {
                n.checked_add(c.roots.len())
            })
            .ok_or(QueryError::InvalidFilter)?;
        if count == 0 || count > limits.roots {
            return Err(QueryError::InvalidFilter);
        }
        let mut seen = [false; 16];
        for c in &self.positions {
            if c.position >= 16
                || c.roots.is_empty()
                || seen[c.position as usize]
            {
                return Err(QueryError::InvalidFilter);
            }
            seen[c.position as usize] = true;
        }
        let mut f = self.clone();
        f.any_branch.sort_unstable();
        f.any_branch.dedup();
        for c in &mut f.positions {
            c.roots.sort_unstable();
            c.roots.dedup();
        }
        f.positions.sort_unstable_by_key(|c| c.position);
        Ok(f)
    }
    /// Evaluate selectors on one output; call canonicalize to validate a request.
    pub fn matches(&self, output: &Output) -> bool {
        (self.any_branch.is_empty()
            || output.branches.iter().any(|r| self.any_branch.contains(r)))
            && self.positions.iter().all(|c| {
                output
                    .branches
                    .get(c.position as usize)
                    .is_some_and(|r| c.roots.contains(r))
            })
    }
    /// Canonicalization is internal so callers cannot hash noncanonical sets.
    pub fn digest(
        &self,
        kind: QueryKind,
        limits: Limits,
    ) -> Result<Hash32, QueryError> {
        let f = self.canonicalize(limits)?;
        let mut bytes = b"LotusV2BranchQuery\0v1".to_vec();
        bytes.push(match kind {
            QueryKind::Utxos => 0,
            QueryKind::History {
                include_burn: false,
            } => 1,
            QueryKind::History { include_burn: true } => 2,
        });
        bytes.extend((f.any_branch.len() as u64).to_le_bytes());
        for r in f.any_branch {
            bytes.extend(r.0);
        }
        bytes.push(f.positions.len() as u8);
        for c in f.positions {
            bytes.push(c.position);
            bytes.extend((c.roots.len() as u64).to_le_bytes());
            for r in c.roots {
                bytes.extend(r.0);
            }
        }
        Ok(Hash32(Sha256::digest(bytes).0))
    }
}
/// Fetch one bounded page. Exhausted work returns the last fully processed key;
/// an unreturned matching candidate is retried on the next page, never skipped.
pub fn query<S: PostingSource>(
    source: &S,
    filter: &BranchFilter,
    kind: QueryKind,
    limits: Limits,
    cursor: Option<Cursor>,
) -> Result<Page, QueryError> {
    let filter = filter.canonicalize(limits)?;
    let digest = filter.digest(kind, limits)?;
    let snapshot = source.snapshot();
    if let Some(c) = cursor {
        if c.version != 1 || c.snapshot != snapshot || c.filter_digest != digest
        {
            return Err(QueryError::StaleCursor);
        }
    }
    let (roots, position) = if !filter.any_branch.is_empty() {
        (&filter.any_branch, None)
    } else {
        (
            &filter.positions[0].roots,
            Some(filter.positions[0].position),
        )
    };
    if limits.page_size == 0
        || limits.posting_reads < roots.len()
        || limits.work < roots.len() + 1
        || limits.result_bytes == 0
    {
        return Err(QueryError::InvalidLimits);
    }
    let mut last = cursor.and_then(|c| c.last_key);
    let mut page = Page {
        snapshot,
        matches: vec![],
        continuation: None,
        posting_reads: 0,
        work: 0,
        result_bytes: 0,
    };
    loop {
        if page.matches.len() == limits.page_size
            || limits.posting_reads - page.posting_reads < roots.len()
            || limits.work - page.work < roots.len() + 1
        {
            break;
        }
        let mut candidate = None;
        for &root in roots {
            let key = source.next_posting(root, position, last)?;
            page.posting_reads += 1;
            page.work += 1;
            if let Some(k) = key {
                if last.is_some_and(|l| k <= l) {
                    return Err(QueryError::Source("unordered posting"));
                }
                candidate =
                    Some(candidate.map_or(k, |old: OutPoint| old.min(k)));
            }
        }
        let Some(key) = candidate else {
            return Ok(page);
        };
        let record = source
            .output(key)?
            .ok_or(QueryError::Source("missing posting record"))?;
        page.work += 1;
        if record.outpoint != key || record.output.validate().is_err() {
            return Err(QueryError::Source("invalid posting record"));
        }
        let eligible = match kind {
            QueryKind::Utxos => {
                !record.output.is_burn() && record.spend.is_none()
            }
            QueryKind::History { include_burn } => {
                include_burn || !record.output.is_burn()
            }
        };
        if eligible && filter.matches(&record.output) {
            let matching_positions: Vec<u8> = record
                .output
                .branches
                .iter()
                .enumerate()
                .filter(|(i, r)| {
                    filter.any_branch.contains(r)
                        || filter.positions.iter().any(|c| {
                            c.position as usize == *i && c.roots.contains(r)
                        })
                })
                .map(|(i, _)| i as u8)
                .collect();
            // Stable logical binary result budget: outpoint + framed output +
            // creation/spend locations + matching-position framing.
            let size = 36
                + record
                    .output
                    .encode()
                    .map_err(|_| QueryError::Source("invalid output"))?
                    .len()
                + 108
                + 1
                + if record.spend.is_some() { 112 } else { 0 }
                + 1
                + matching_positions.len();
            if size > limits.result_bytes {
                return Err(QueryError::RecordTooLarge);
            }
            if size > limits.result_bytes - page.result_bytes {
                break;
            }
            page.result_bytes += size;
            page.matches.push(Match {
                record,
                matching_positions,
            });
        }
        last = Some(key);
    }
    page.continuation = Some(Cursor {
        version: 1,
        snapshot,
        filter_digest: digest,
        last_key: last,
    });
    Ok(page)
}
#[cfg(test)]
#[path = "v2_branches_test/tests.rs"]
mod tests;
