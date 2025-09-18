use std::convert::TryInto;

use serde::Deserialize;

pub struct Block {
    pub header: [u8; 160],
    pub body: Vec<u8>,
    pub target: [u8; 32],
}

#[derive(Deserialize, Debug, Clone)]
pub struct GetRawUnsolvedBlockResponse {
    pub result: Option<RawUnsolvedBlockAndTarget>,
    pub error: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RawUnsolvedBlockAndTarget {
    pub blockhex: String,
    pub target: String,
}

pub fn create_block(unsolved_block_and_target: &RawUnsolvedBlockAndTarget) -> Block {
    let block = hex::decode(&unsolved_block_and_target.blockhex).unwrap();
    // nBits (4 bytes)
    let mut target: [u8; 32] = hex::decode(&unsolved_block_and_target.target)
        .unwrap()
        .try_into()
        .unwrap();
    target.reverse();
    Block {
        header: block[0..160].try_into().unwrap(),
        body: block[160..].try_into().unwrap(),
        target,
    }
}

impl Block {
    pub fn prev_hash(&self) -> &[u8] {
        &self.header[..32]
    }
    
    pub fn empty() -> Self {
        Block {
            header: [0; 160],
            body: Vec::new(),
            target: [0; 32],
        }
    }
    
    pub fn body_size(&self) -> usize {
        self.body.len()
    }
    
    pub fn get_body(&self) -> &[u8] {
        &self.body
    }
}
