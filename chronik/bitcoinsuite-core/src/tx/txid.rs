// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{
    bytes::read_array,
    error::DataError,
    hash::{Hashed, Sha256d},
    ser::{BitcoinSer, BitcoinSerializer},
    tx::{TxInput, TxMut, TxOutput},
};

fn lotus_merkle_root_and_height(mut leaves: Vec<Sha256d>) -> (Sha256d, u8) {
    if leaves.is_empty() {
        return (Sha256d::default(), 0);
    }
    let mut height = 1;
    while leaves.len() > 1 {
        height += 1;
        if leaves.len() % 2 == 1 {
            // Pad odd layers with 0000...0000 on Lotus
            leaves.push(Sha256d::default());
        }
        let mut next_layer = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(pair[0].as_le_bytes());
            bytes[32..].copy_from_slice(pair[1].as_le_bytes());
            next_layer.push(Sha256d::digest(bytes));
        }
        leaves = next_layer;
    }
    (leaves[0], height)
}

fn lotus_tx_inputs_merkle_root(inputs: &[TxInput]) -> (Sha256d, u8) {
    let leaves = inputs
        .iter()
        .map(|input| {
            let mut data = bytes::BytesMut::with_capacity(36 + 4);
            input.prev_out.ser_to(&mut data);
            input.sequence.ser_to(&mut data);
            Sha256d::digest(data.freeze())
        })
        .collect::<Vec<_>>();
    lotus_merkle_root_and_height(leaves)
}

fn lotus_tx_outputs_merkle_root(outputs: &[TxOutput]) -> (Sha256d, u8) {
    let leaves = outputs
        .iter()
        .map(|output| Sha256d::digest(output.ser()))
        .collect::<Vec<_>>();
    lotus_merkle_root_and_height(leaves)
}

/// Wraps a tx ID's [`Sha256d`], to avoid mixing different kinds of hashes.
/// Txids are always represented with a big-endian hex string, but stored
/// in little-endian byteorder.
#[derive(
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct TxId(Sha256d);

impl std::fmt::Debug for TxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TxId({})", self.0.hex_be())
    }
}

impl std::fmt::Display for TxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.hex_be().fmt(f)
    }
}

impl TxId {
    /// Create a [`TxId`] with the given txid in little endian.
    /// Can be used in a const context.
    /// ```
    /// # use bitcoinsuite_core::tx::TxId;
    /// const txid: TxId = TxId::new([5; 32]);
    /// ```
    pub const fn new(txid: [u8; 32]) -> Self {
        TxId(Sha256d(txid))
    }

    /// Return the Lotus Merkleized [`TxId`] for the given [`TxMut`] (or `Tx`).
    ///
    /// ```
    /// # use bitcoinsuite_core::tx::{Tx, TxId, TxMut};
    /// let zero_tx_hash =
    ///     "0aa86a445457f6eab159b7961df079bfd2107240b590d7c037bef3f26eafd291"
    ///         .parse::<TxId>()
    ///         .unwrap();
    /// assert_eq!(TxId::from_tx(&TxMut::default()), zero_tx_hash);
    /// assert_eq!(TxId::from_tx(&Tx::default()), zero_tx_hash);
    /// let v2_tx_hash =
    ///     "9ced0819179f3362e7306ad7e5eaa7d2fddeb8eb74cd75a4f3997f43a6d33f90"
    ///         .parse::<TxId>()
    ///         .unwrap();
    /// assert_eq!(
    ///     TxId::from_tx(&TxMut { version: 2, ..Default::default() }),
    ///     v2_tx_hash,
    /// );
    /// ```
    pub fn from_tx(tx: &TxMut) -> Self {
        let mut data = bytes::BytesMut::with_capacity(4 + 32 + 1 + 32 + 1 + 4);
        tx.version.ser_to(&mut data);
        let (inputs_hash, inputs_height) =
            lotus_tx_inputs_merkle_root(&tx.inputs);
        inputs_hash.as_le_bytes().ser_to(&mut data);
        inputs_height.ser_to(&mut data);
        let (outputs_hash, outputs_height) =
            lotus_tx_outputs_merkle_root(&tx.outputs);
        outputs_hash.as_le_bytes().ser_to(&mut data);
        outputs_height.ser_to(&mut data);
        tx.locktime.ser_to(&mut data);
        TxId(Sha256d::digest(data.freeze()))
    }

    /// Returns the txid bytes in little-endian byte order.
    ///
    /// ```
    /// # use bitcoinsuite_core::{tx::TxId, hash::{Sha256d, Hashed}};
    /// # use hex_literal::hex;
    /// let hash = hex!(
    ///     "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    /// );
    /// let txid = TxId::from(Sha256d(hash));
    /// assert_eq!(txid.to_bytes(), hash);
    /// ```
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_le_bytes()
    }

    /// Returns a reference to the txid bytes in little-endian byte order.
    ///
    /// ```
    /// # use bitcoinsuite_core::{tx::TxId, hash::{Sha256d, Hashed}};
    /// # use hex_literal::hex;
    /// let hash = hex!(
    ///     "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    /// );
    /// let txid = TxId::from(Sha256d(hash));
    /// assert_eq!(txid.as_bytes(), &hash);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_le_bytes()
    }

    /// Returns the txid as [`Vec<u8>`] in little-endian byte order.
    ///
    /// ```
    /// # use bitcoinsuite_core::{tx::TxId, hash::{Sha256d, Hashed}};
    /// # use hex_literal::hex;
    /// let hash = hex!(
    ///     "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    /// );
    /// let txid = TxId::from(Sha256d(hash));
    /// assert_eq!(txid.to_vec(), hash.to_vec());
    /// ```
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Return the hash behind the [`TxId`].
    pub fn hash(&self) -> Sha256d {
        self.0
    }
}

impl std::str::FromStr for TxId {
    type Err = DataError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(TxId(Sha256d::from_be_hex(s)?))
    }
}

impl TryFrom<&'_ [u8]> for TxId {
    type Error = DataError;

    fn try_from(value: &'_ [u8]) -> Result<Self, Self::Error> {
        Ok(TxId(Sha256d::from_le_slice(value)?))
    }
}

impl TryFrom<&'_ serde_json::Value> for TxId {
    type Error = &'static str;

    fn try_from(value: &'_ serde_json::Value) -> Result<Self, Self::Error> {
        match value.as_str() {
            Some(txid_hex) => {
                TxId::from_str(txid_hex).or(Err("Invalid tx hash"))
            }
            None => Err("Invalid tx hash"),
        }
    }
}

impl From<[u8; 32]> for TxId {
    fn from(array: [u8; 32]) -> Self {
        TxId(Sha256d(array))
    }
}

impl From<Sha256d> for TxId {
    fn from(hash: Sha256d) -> Self {
        TxId(hash)
    }
}

impl AsRef<[u8]> for TxId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl BitcoinSer for TxId {
    fn ser_to<S: BitcoinSerializer>(&self, bytes: &mut S) {
        bytes.put(self.as_bytes())
    }

    fn deser(data: &mut bytes::Bytes) -> Result<Self, DataError> {
        Ok(TxId(Sha256d(read_array(data)?)))
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{
        error::DataError,
        hash::{Hashed, Sha256d},
        tx::TxId,
    };

    const HASH_HEX: &str =
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

    fn txid_hash() -> Sha256d {
        let txid_hash = hex!(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        Sha256d::from_be_bytes(txid_hash)
    }

    #[test]
    fn test_parse() -> Result<(), DataError> {
        let txid = HASH_HEX.parse::<TxId>()?;
        assert_eq!(txid, TxId::from(txid_hash()));
        Ok(())
    }

    #[test]
    fn test_parse_fail() {
        assert_eq!(
            "abcd".parse::<TxId>(),
            Err(DataError::InvalidLength {
                expected: 32,
                actual: 2,
            }),
        );
    }

    #[test]
    fn test_try_from_slice() {
        let hash = txid_hash();
        let slice = hash.as_le_bytes().as_ref();
        let txid: TxId = slice.try_into().unwrap();
        assert_eq!(txid, TxId::from(hash));
        assert_eq!(
            TxId::try_from(b"ab".as_ref()),
            Err(DataError::InvalidLength {
                expected: 32,
                actual: 2,
            }),
        );
    }

    #[test]
    fn test_debug() {
        assert_eq!(
            format!("{:?}", TxId::from(txid_hash())),
            format!("TxId({})", HASH_HEX),
        );
    }

    #[test]
    fn test_display() -> Result<(), DataError> {
        assert_eq!(TxId::from(txid_hash()).to_string(), HASH_HEX);
        Ok(())
    }
}
