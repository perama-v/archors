//! Compares two cached transferrable block proofs and quantifies the degree
//! of data overlap (contracts, nodes). This represents data that a node
//! would not have to duplicate on disk.

use std::{collections::HashSet, fmt::Display};

use thiserror::Error;

use crate::cache::{get_required_state_from_cache, CacheError};

#[derive(Debug, Error)]
pub enum OverlapError {
    #[error("CacheError {0}")]
    CacheError(#[from] CacheError),
}

/// Overlap between two transferrable proofs, measured in bytes.
pub struct DataSaved {
    /// This excludes proof account and storage values.
    nodes_and_contracts_to_store: usize,
    contracts: usize,
    accounts: usize,
    storage: usize,
}

impl Display for DataSaved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Overlap: Contracts {}KB, Account nodes {}KB, Storage nodes {}KB. Savings {}%",
            self.contracts / 1000,
            self.accounts / 1000,
            self.storage / 1000,
            self.percentage_savings(),
        )
    }
}

impl DataSaved {
    /// Percentage of code and nodes data that does not need to be stored twice
    /// due to overlap between blocks.
    pub fn percentage_savings(&self) -> usize {
        let savings = self.contracts + self.accounts + self.storage;
        let naive_sum = self.nodes_and_contracts_to_store + savings;
        100 * savings / naive_sum
    }
    /// Bytes saved byt not duplicating repeated code and account/storage nodes
    /// between different blocks.
    pub fn total_savings(&self) -> usize {
        self.contracts + self.accounts + self.storage
    }
}

pub fn measure_proof_overlap(blocks: Vec<u64>) -> Result<DataSaved, OverlapError> {
    let mut contract_saved_bytes = 0usize;
    let mut accounts_saved_bytes = 0usize;
    let mut storage_saved_bytes = 0usize;
    let mut to_store = 0usize;

    let mut contract_set: HashSet<Vec<u8>> = HashSet::new();
    let mut accounts_set: HashSet<Vec<u8>> = HashSet::new();
    let mut storage_set: HashSet<Vec<u8>> = HashSet::new();

    for block in blocks {
        let proof = get_required_state_from_cache(block)?;
        for contract in proof.contracts.iter() {
            check_bytes(
                &mut contract_saved_bytes,
                &mut contract_set,
                contract.to_vec(),
                &mut to_store,
            );
        }
        todo!("Overlap stats not updated after implementing node bag")
        /*
        // TODO Note: The node bag contains account and storage nodes all together.
        for node in proof.account_nodes.iter() {
            check_bytes(
                &mut accounts_saved_bytes,
                &mut accounts_set,
                node.to_vec(),
                &mut to_store,
            );
        }
        for node in proof.storage_nodes.iter() {
            check_bytes(
                &mut storage_saved_bytes,
                &mut storage_set,
                node.to_vec(),
                &mut to_store,
            )
        }
         */
    }

    Ok(DataSaved {
        contracts: contract_saved_bytes,
        accounts: accounts_saved_bytes,
        storage: storage_saved_bytes,
        nodes_and_contracts_to_store: to_store,
    })
}

/// Either records data, or if already present registers saved bytes.
fn check_bytes(
    saved_bytes: &mut usize,
    set: &mut HashSet<Vec<u8>>,
    data: Vec<u8>,
    to_store: &mut usize,
) {
    if set.contains(&data) {
        *saved_bytes += data.len();
    } else {
        *to_store += data.len();
        set.insert(data);
    }
}
