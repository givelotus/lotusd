//! Lossless public Lotus V2 indexing records, separate from legacy transactions.
//!
//! Wire order is the native byte order: hashes are never reversed. The output
//! codec follows `src/lotus_v2/output.{h,cpp}` at `5aa296b7c` (C05/C09).
//! Transaction fields follow `transaction.h` (C10/C11); no transaction codec,
//! identity computation, contextual validation or ownership inference is implied.

use crate::ser::BitcoinSer;

/// A 32-byte commitment in V2 wire order, without display-endian conversion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hash32(pub [u8; 32]);

/// V2 transaction identifier; distinct from the full-serialization hash.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TxId(pub Hash32);

/// V2 full transaction hash, preserving the accepted witness variant identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TxHash(pub Hash32);

/// An output reference uses TxID, never TxHash.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OutPoint {
    /// Creating transaction ID.
    pub txid: TxId,
    /// Output ordinal within the transaction.
    pub out_idx: u32,
}

/// Native public output fields. Branch positions are vector indices (0..16),
/// not hidden leaf positions. Root matches establish neither ownership nor
/// spendability; burns also carry public roots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Output {
    /// Exact legacy script; legacy coins have no V2 authorization roots.
    pub legacy_script: Option<Vec<u8>>,
    /// Native flags: bit 0 token, bit 1 burn, bit 2 state. Legacy records
    /// use 0x80, with bit 1 additionally marking an unspendable script.
    pub flags: u8,
    /// Unsigned native/token quantity, including the full u64 range.
    pub value: u64,
    /// Nonzero exactly when the token flag is set; otherwise all zero.
    pub token_id: Hash32,
    /// Nonzero exactly when the state flag is set; otherwise all zero. A
    /// contract-defined commitment authorized by the creating transaction's
    /// scripts (ENFORCEOUTPUT); never set on burns.
    pub state_root: Hash32,
    /// Complete ordered, distinct public authorization roots.
    pub branches: Vec<Hash32>,
    /// Lexicographically ordered paths of strictly increasing branch indices.
    pub paths: Vec<Vec<u8>>,
}

/// Hard native framing bound, independent of stricter deployment profiles.
pub const MAX_OUTPUT_BYTES: usize = 844;
/// Legacy state coin framing permits the consensus legacy script bound.
pub const MAX_COIN_OUTPUT_BYTES: usize = 10020;
/// Maximum branches and paths in the native output grammar.
pub const MAX_OUTPUT_BRANCHES: usize = 16;

/// A stable native output framing/structural error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid Lotus V2 output: {0}")]
pub struct OutputError(pub &'static str);

type Result<T> = std::result::Result<T, OutputError>;

impl Output {
    /// Whether the token flag is present.
    pub fn has_token(&self) -> bool {
        self.flags & 1 != 0
    }
    /// Whether this is a burn commitment (excluded from UTXOs).
    pub fn is_burn(&self) -> bool {
        self.flags & 2 != 0
    }
    /// Whether the output carries a 32-byte state root.
    pub fn has_state(&self) -> bool {
        self.flags & 4 != 0
    }

    /// Check native output structure only, without coin or script validation.
    pub fn validate(&self) -> Result<()> {
        let fail = |category| Err(OutputError(category));
        if let Some(script) = &self.legacy_script {
            if self.flags
                != (0x80
                    | if script.first() == Some(&0x6a) || script.len() > 10000 {
                        2
                    } else {
                        0
                    })
                || script.len() > u32::MAX as usize - 12
                || !self.branches.is_empty()
                || !self.paths.is_empty()
                || self.token_id != Hash32::default()
                || self.state_root != Hash32::default()
            {
                return fail("legacy coin");
            }
            return Ok(());
        }
        if self.flags & 0xf8 != 0 {
            return fail("flags");
        }
        if self.has_state() {
            if self.is_burn() {
                return fail("burn state");
            }
            if self.state_root == Hash32::default() {
                return fail("zero state root");
            }
        } else if self.state_root != Hash32::default() {
            return fail("stateless root field");
        }
        if self.has_token() {
            if self.token_id == Hash32::default() {
                return fail("zero token");
            }
        } else if self.token_id != Hash32::default() {
            return fail("native token field");
        }
        if self.branches.is_empty() || self.branches.len() > 16 {
            return fail("branch count");
        }
        for (i, root) in self.branches.iter().enumerate() {
            if self.branches[..i].contains(root) {
                return fail("duplicate branch");
            }
        }
        if self.is_burn() {
            if !self.paths.is_empty() {
                return fail("burn paths");
            }
        } else if self.paths.is_empty() || self.paths.len() > 16 {
            return fail("path count");
        }
        for (p, path) in self.paths.iter().enumerate() {
            if path.is_empty() || path.len() > self.branches.len() {
                return fail("path length");
            }
            if path.iter().any(|&i| usize::from(i) >= self.branches.len())
                || path.windows(2).any(|w| w[0] >= w[1])
            {
                return fail("path index");
            }
            if p > 0 && self.paths[p - 1] >= *path {
                return fail("path order");
            }
        }
        Ok(())
    }

    /// Encode a canonical native output frame after structural checks.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        if let Some(script) = &self.legacy_script {
            let mut bytes = vec![0x80];
            bytes.extend(self.value.to_le_bytes());
            bytes.extend(script.ser());
            return Ok(bytes);
        }
        let mut bytes = Vec::with_capacity(MAX_OUTPUT_BYTES);
        bytes.push(self.flags);
        bytes.extend(self.value.to_le_bytes());
        if self.has_token() {
            bytes.extend(self.token_id.0);
        }
        if self.has_state() {
            bytes.extend(self.state_root.0);
        }
        // All CompactSize fields are bounded below 253, hence one byte.
        bytes.push(self.branches.len() as u8);
        for root in &self.branches {
            bytes.extend(root.0);
        }
        bytes.push(self.paths.len() as u8);
        for path in &self.paths {
            bytes.push(path.len() as u8);
            bytes.extend(path);
        }
        if bytes.len() > MAX_OUTPUT_BYTES {
            return Err(OutputError("output bytes"));
        }
        Ok(bytes)
    }

    /// Decode exactly one native frame, rejecting trailing bytes and allocating
    /// only after count bounds and available bytes have been checked.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.first() == Some(&0x80) {
            if bytes.len() > u32::MAX as usize || bytes.len() < 10 {
                return Err(OutputError("legacy coin"));
            }
            let value = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
            let first = bytes[9];
            let width = match first {
                253 => 2,
                254 => 4,
                255 => 8,
                _ => 0,
            };
            if bytes.len() < 10 + width {
                return Err(OutputError("legacy coin"));
            }
            let mut length = u64::from(first);
            if width != 0 {
                let mut encoded = [0u8; 8];
                encoded[..width].copy_from_slice(&bytes[10..10 + width]);
                length = u64::from_le_bytes(encoded);
                if length < 253
                    || (width > 2 && length <= 0xffff)
                    || (width > 4 && length <= 0xffff_ffff)
                {
                    return Err(OutputError("legacy coin"));
                }
            }
            if length > u64::from(u32::MAX) - 12
                || bytes.len() - 10 - width != length as usize
            {
                return Err(OutputError("legacy coin"));
            }
            let script = bytes[10 + width..].to_vec();
            return Ok(Self {
                flags: 0x80
                    | if script.first() == Some(&0x6a) || script.len() > 10000 {
                        2
                    } else {
                        0
                    },
                value,
                legacy_script: Some(script),
                ..Self::default()
            });
        }
        if bytes.len() > MAX_OUTPUT_BYTES {
            return Err(OutputError("output bytes"));
        }
        let mut r = Reader(bytes);
        let flags = r.byte("truncated flags")?;
        if flags & 0xf8 != 0 {
            return Err(OutputError("flags"));
        }
        let value = u64::from_le_bytes(
            r.take(8, "truncated value")?.try_into().unwrap(),
        );
        let token_id = if flags & 1 != 0 {
            r.hash("truncated token")?
        } else {
            Hash32::default()
        };
        let state_root = if flags & 4 != 0 {
            r.hash("truncated state root")?
        } else {
            Hash32::default()
        };
        let n = r.count(16, "branch count")?;
        if n > r.0.len() / 32 {
            return Err(OutputError("truncated branches"));
        }
        let mut branches = Vec::with_capacity(n);
        for _ in 0..n {
            branches.push(r.hash("truncated branches")?);
        }
        let n = r.count(16, "path count")?;
        if n > r.0.len() {
            return Err(OutputError("truncated paths"));
        }
        let mut paths = Vec::with_capacity(n);
        for _ in 0..n {
            let length = r.count(16, "path length")?;
            if length > r.0.len() {
                return Err(OutputError("truncated path"));
            }
            let mut path = Vec::with_capacity(length);
            for _ in 0..length {
                path.push(r.count(15, "path index")? as u8);
            }
            paths.push(path);
        }
        if !r.0.is_empty() {
            return Err(OutputError("trailing bytes"));
        }
        let output = Self {
            legacy_script: None,
            flags,
            value,
            token_id,
            state_root,
            branches,
            paths,
        };
        output.validate()?;
        Ok(output)
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, error: &'static str) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(OutputError(error));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn byte(&mut self, error: &'static str) -> Result<u8> {
        Ok(self.take(1, error)?[0])
    }
    fn hash(&mut self, error: &'static str) -> Result<Hash32> {
        Ok(Hash32(self.take(32, error)?.try_into().unwrap()))
    }
    fn count(&mut self, cap: u8, error: &'static str) -> Result<usize> {
        // Multi-byte CompactSize cannot encode any permitted count minimally.
        let n = self.byte(error)?;
        if n > cap {
            return Err(OutputError(error));
        }
        Ok(usize::from(n))
    }
}

/// A revealed branch witness. Siblings prove unordered membership, not a hidden
/// leaf position, tree size or uniqueness.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BranchWitness {
    /// Revealed script bytes.
    pub script: Vec<u8>,
    /// Membership siblings in their supplied order.
    pub siblings: Vec<Hash32>,
    /// Ordered script arguments.
    pub arguments: Vec<Vec<u8>>,
}

/// Native transaction input, retaining framing distinctions losslessly.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Input {
    /// Previous transaction ID and output index.
    pub prev_out: OutPoint,
    /// Native sequence word.
    pub sequence: u32,
    /// Native discriminator: 1 spend, 2 coinbase, 3 mint.
    pub flags: u8,
    /// Selected public output path (meaningful only for spends).
    pub path_index: u8,
    /// Ordered branch disclosures.
    pub witnesses: Vec<BranchWitness>,
    /// Presence is distinct from a present empty coinbase payload.
    pub coinbase_data: Option<Vec<u8>>,
}

/// Native transaction fields; callers must perform profile/context checks.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Transaction {
    /// Full unsigned 64-bit native lock field.
    pub lock: u64,
    /// Ordered native inputs.
    pub inputs: Vec<Input>,
    /// Ordered public outputs.
    pub outputs: Vec<Output>,
}

/// Authoritative confirmed transaction location, bound to a block identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxLocation {
    /// Native block ID in wire order.
    pub block_id: Hash32,
    /// Native unsigned block height.
    pub height: u64,
    /// Transaction ordinal in the block.
    pub tx_index: u32,
    /// Merkleized transaction ID.
    pub txid: TxId,
    /// Full transaction hash of the accepted variant.
    pub txhash: TxHash,
}

/// A recorded consumption of an indexed output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendLocation {
    /// Confirmed consuming transaction.
    pub transaction: TxLocation,
    /// Consuming input ordinal.
    pub input_index: u32,
}

/// Complete confirmed output record for future indexing; no pending state is
/// inferred. Burns belong in creation history, never the UTXO set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputRecord {
    /// Output identity.
    pub outpoint: OutPoint,
    /// Complete public output policy and quantity.
    pub output: Output,
    /// Authoritative creation location.
    pub creation: TxLocation,
    /// Authoritative spend, if one exists.
    pub spend: Option<SpendLocation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> std::collections::BTreeMap<String, String> {
        serde_json::from_str(include_str!(
            "lotus_v2/fixtures/native_outputs.json"
        ))
        .unwrap()
    }

    #[test]
    fn native_reference_roundtrips() {
        for (name, wire) in fixtures() {
            let bytes = hex::decode(wire).unwrap();
            let output = Output::decode(&bytes).unwrap();
            assert_eq!(output.encode().unwrap(), bytes, "{name}");
            assert_eq!(output.is_burn(), name.contains("burn"));
            assert_eq!(output.has_token(), name.contains("token"));
            assert!(!output.has_state());
            if name == "token" {
                assert_eq!(output.value, u64::MAX);
            }
            for end in 0..bytes.len() {
                assert!(Output::decode(&bytes[..end]).is_err());
            }
            let mut extra = bytes;
            extra.push(0);
            assert_eq!(
                Output::decode(&extra),
                Err(OutputError("trailing bytes"))
            );
        }
    }

    #[test]
    fn legacy_coin_frames_have_no_native_roots() {
        for script in [
            vec![],
            vec![0x51],
            vec![0x6a, 1, 0x42],
            vec![0x51; 10000],
            vec![0x51; 10001],
        ] {
            let output = Output {
                flags: 0x80
                    | if script.first() == Some(&0x6a) || script.len() > 10000 {
                        2
                    } else {
                        0
                    },
                value: 123,
                legacy_script: Some(script),
                ..Output::default()
            };
            let wire = output.encode().unwrap();
            assert_eq!(wire[0], 0x80);
            let decoded = Output::decode(&wire).unwrap();
            assert_eq!(decoded, output);
            assert!(decoded.branches.is_empty());
            assert!(!decoded.has_token());
            for end in
                (0..wire.len().min(32)).chain(std::iter::once(wire.len() - 1))
            {
                assert!(Output::decode(&wire[..end]).is_err());
            }
            let mut extra = wire;
            extra.push(0);
            assert!(Output::decode(&extra).is_err());
        }
        let mut nonminimal = vec![0x80];
        nonminimal.extend(123u64.to_le_bytes());
        nonminimal.extend([253, 1, 0, 0x51]);
        assert!(Output::decode(&nonminimal).is_err());
    }

    #[test]
    fn structural_bounds_and_order() {
        let mut output = Output {
            flags: 1,
            value: u64::MAX,
            token_id: Hash32([1; 32]),
            branches: (0..16).map(|i| Hash32([i; 32])).collect(),
            paths: (0..16).map(|i| vec![i]).collect(),
            ..Output::default()
        };
        assert_eq!(Output::decode(&output.encode().unwrap()).unwrap(), output);
        output.paths = vec![(0..16).collect()];
        assert!(output.encode().is_ok());
        output.paths = vec![vec![1, 0]];
        assert_eq!(output.validate(), Err(OutputError("path index")));
        output.paths = vec![vec![1], vec![0]];
        assert_eq!(output.validate(), Err(OutputError("path order")));
        output.paths = vec![vec![16]];
        assert_eq!(output.validate(), Err(OutputError("path index")));
        output.paths = vec![vec![0]];
        output.branches[1] = output.branches[0];
        assert_eq!(output.validate(), Err(OutputError("duplicate branch")));
        assert_eq!(
            Output::decode(&vec![0; 845]),
            Err(OutputError("output bytes"))
        );
    }

    #[test]
    fn validation_rejects_non_native_models() {
        let base = Output::decode(&hex::decode(&fixtures()["native"]).unwrap())
            .unwrap();
        for (flags, token_id, expected) in [
            (8, Hash32::default(), "flags"),
            (4, Hash32::default(), "zero state root"),
            (1, Hash32::default(), "zero token"),
            (0, Hash32([1; 32]), "native token field"),
            (2, Hash32::default(), "burn paths"),
        ] {
            let bad = Output {
                flags,
                token_id,
                ..base.clone()
            };
            assert_eq!(bad.validate(), Err(OutputError(expected)));
        }
        for (branches, expected) in [
            (vec![], "branch count"),
            ((0..17).map(|i| Hash32([i; 32])).collect(), "branch count"),
        ] {
            assert_eq!(
                Output {
                    branches,
                    ..base.clone()
                }
                .validate(),
                Err(OutputError(expected))
            );
        }
        for paths in [vec![], vec![vec![0]; 17]] {
            assert_eq!(
                Output {
                    paths,
                    ..base.clone()
                }
                .validate(),
                Err(OutputError("path count"))
            );
        }
        assert_eq!(
            Transaction {
                lock: u64::MAX,
                ..Transaction::default()
            }
            .lock,
            u64::MAX
        );
    }

    #[test]
    fn malformed_native_frames() {
        let bytes = hex::decode(&fixtures()["native"]).unwrap();
        for (offset, value, error) in [
            (0, 8, "flags"),
            (9, 17, "branch count"),
            (9, 0, "path count"),
            (44, 1, "path index"),
            (43, 0, "trailing bytes"),
        ] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert_eq!(Output::decode(&bad), Err(OutputError(error)));
        }
        let mut bad = bytes.clone();
        bad.splice(9..10, [253, 1, 0]);
        assert_eq!(Output::decode(&bad), Err(OutputError("branch count")));
        let mut burn = bytes;
        burn[0] = 2;
        assert_eq!(Output::decode(&burn), Err(OutputError("burn paths")));
    }

    #[test]
    fn state_root_outputs() {
        // Matches the C++ wire order: flags, value, token, state, branches.
        let base = Output::decode(&hex::decode(&fixtures()["native"]).unwrap())
            .unwrap();
        let stateful = Output {
            flags: 4,
            state_root: Hash32([9; 32]),
            ..base.clone()
        };
        let bytes = stateful.encode().unwrap();
        assert_eq!(bytes.len(), base.encode().unwrap().len() + 32);
        assert_eq!(&bytes[9..41], &[9; 32]);
        assert_eq!(Output::decode(&bytes).unwrap(), stateful);
        for end in 0..bytes.len() {
            assert!(Output::decode(&bytes[..end]).is_err());
        }
        let token = Output {
            flags: 5,
            token_id: Hash32([1; 32]),
            ..stateful.clone()
        };
        let bytes = token.encode().unwrap();
        assert_eq!(&bytes[9..41], &[1; 32]);
        assert_eq!(&bytes[41..73], &[9; 32]);
        assert_eq!(Output::decode(&bytes).unwrap(), token);
        assert_eq!(
            Output {
                flags: 0,
                ..stateful.clone()
            }
            .validate(),
            Err(OutputError("stateless root field"))
        );
        assert_eq!(
            Output {
                flags: 6,
                paths: vec![],
                ..stateful
            }
            .validate(),
            Err(OutputError("burn state"))
        );
    }
}
