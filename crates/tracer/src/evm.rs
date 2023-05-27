//! For creation and use of an EVM for a single block.

use std::io::stdout;

use ethers::types::{Block, Transaction};
use revm::{
    db::{CacheDB, EmptyDB},
    inspectors::TracerEip3155,
    primitives::{EVMError, ExecutionResult, TransactTo, U256},
    EVM,
};
use thiserror::Error;

use crate::utils::{
    access_list_e_to_r, eu256_to_ru256, eu256_to_u64, eu64_to_ru256, ru256_to_u64, UtilsError,
};

/// An error with tracing a block
#[derive(Debug, Error, PartialEq)]
pub enum EvmError {
    #[error("Attempted to set block environment twice")]
    BlockEnvAlreadySet,
    #[error("Expected a block author (coinbase) to set up the EVM, found none")]
    NoBlockAuthor,
    #[error("Expected a block number to set up the EVM, found none")]
    NoBlockNumber,
    #[error("Attempted to execute transaction before setting environment")]
    TxNotSet,
    #[error("Attempted to set transaction environment twice")]
    TxAlreadySet,
    #[error("UtilsError {0}")]
    UtilsError(#[from] UtilsError),
    #[error("revm Error {0}")]
    RevmError(String),
}

// A wrapper to implement handy methods for working with the revm EVM.
#[derive(Clone)]
pub struct BlockEvm {
    pub evm: EVM<CacheDB<EmptyDB>>,
    tx_env_status: TxStatus,
    block_env_status: BlockStatus,
}

impl BlockEvm {
    /// Create the EVM and insert a populated database of state values.
    ///
    /// The DB should contain the states required to execute the intended transactions.
    pub fn init_from_db(db: CacheDB<EmptyDB>) -> Self {
        let mut evm = EVM::new();
        evm.database(db);
        Self {
            evm,
            tx_env_status: TxStatus::NotLoaded,
            block_env_status: BlockStatus::NotSet,
        }
    }
    /// Set the chain ID (mainnet = 1).
    pub fn add_chain_id(&mut self, id: U256) -> &mut Self {
        self.evm.env.cfg.chain_id = U256::from(id);
        self
    }
    /// Set initial block values (BaseFee, GasLimit, ..., Etc.).
    pub fn add_block_environment(
        &mut self,
        block: &Block<Transaction>,
    ) -> Result<&mut Self, EvmError> {
        if self.block_env_status == BlockStatus::Set {
            return Err(EvmError::BlockEnvAlreadySet);
        }
        let env = &mut self.evm.env.block;

        env.number = eu64_to_ru256(block.number.ok_or(EvmError::NoBlockNumber)?);
        env.coinbase = block.author.ok_or(EvmError::NoBlockAuthor)?.into();
        env.timestamp = block.timestamp.into();
        env.gas_limit = block.gas_limit.into();
        env.basefee = block.base_fee_per_gas.unwrap_or_default().into();
        env.difficulty = block.difficulty.into();
        env.prevrandao = Some(block.difficulty.into());
        self.block_env_status = BlockStatus::Set;
        Ok(self)
    }
    /// Set the spec id (hard fork definition).
    pub fn add_spec_id(&mut self, _block: &Block<Transaction>) -> Result<&mut Self, EvmError> {
        // TODO. E.g.,
        // if block x < block.number < y,
        // self.env.cfg.spec_id = SpecId::Constantinople
        Ok(self)
    }
    /// Add a single transaction environment (index, sender, recipient, etc.).
    pub fn add_transaction_environment(&mut self, tx: Transaction) -> Result<&mut Self, EvmError> {
        self.tx_env_status.ready_to_set()?;
        let env = &mut self.evm.env.tx;

        env.caller = tx.from.into();
        env.gas_limit = eu256_to_u64(tx.gas);
        env.gas_price = match tx.gas_price {
            Some(price) => eu256_to_ru256(price)?,
            None => todo!("handle Type II transaction gas price"),
        };
        env.gas_priority_fee = match tx.max_priority_fee_per_gas {
            Some(fee) => Some(eu256_to_ru256(fee)?),
            None => None,
        };
        env.transact_to = match tx.to {
            Some(to) => TransactTo::Call(to.into()),
            None => todo!("handle tx create scheme"), // TransactTo::Create(),
        };
        env.value = tx.value.into();
        env.data = tx.input.0;
        env.chain_id = Some(ru256_to_u64(self.evm.env.cfg.chain_id));
        env.nonce = Some(eu256_to_u64(tx.nonce));
        env.access_list = match tx.access_list {
            Some(list_in) => access_list_e_to_r(list_in),
            None => vec![],
        };

        self.tx_env_status.set()?;
        Ok(self)
    }
    /// Execute a loaded transaction with an inspector to produce an EIP-3155 style trace.
    ///
    /// This applies the transaction, monitors the output and leaves the EVM ready for the
    /// next transaction to be added.
    pub fn execute_with_inspector_eip3155(&mut self) -> Result<ExecutionResult, EvmError> {
        self.tx_env_status.ready_to_execute()?;
        // Initialize the inspector
        let inspector = TracerEip3155::new(Box::new(stdout()), true, true);

        // see: https://github.com/bluealloy/revm/blob/main/bins/revme/src/statetest/runner.rs#L259
        let outcome = self.evm.inspect_commit(inspector).map_err(EvmError::from)?;
        self.tx_env_status.executed()?;
        Ok(outcome)
    }
    /// Execute a loaded transaction without an inspector.
    ///
    /// This applies the transaction and leaves the EVM ready for the
    /// next transaction to be added.
    pub fn execute_without_inspector(&mut self) -> Result<ExecutionResult, EvmError> {
        self.tx_env_status.ready_to_execute()?;
        let outcome = self.evm.transact_commit().map_err(EvmError::from)?;
        self.tx_env_status.executed()?;
        Ok(outcome)
    }
}

/// Transactions are executed individually, this status prevents accidental
/// double-loading.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TxStatus {
    Loaded,
    NotLoaded,
}

/// This status prevents accidental double-loading of block between transactions.
#[derive(Clone, Debug, Eq, PartialEq)]
enum BlockStatus {
    Set,
    NotSet,
}

/// Readable state manager for whether a transaction is set or not.
impl TxStatus {
    fn ready_to_execute(&self) -> Result<(), EvmError> {
        match self {
            TxStatus::Loaded => Ok(()),
            TxStatus::NotLoaded => Err(EvmError::TxNotSet),
        }
    }
    fn ready_to_set(&self) -> Result<(), EvmError> {
        match self {
            TxStatus::Loaded => Err(EvmError::TxAlreadySet),
            TxStatus::NotLoaded => Ok(()),
        }
    }
    fn executed(&mut self) -> Result<(), EvmError> {
        self.ready_to_execute()?;
        *self = TxStatus::NotLoaded;
        Ok(())
    }
    fn set(&mut self) -> Result<(), EvmError> {
        self.ready_to_set()?;
        *self = TxStatus::Loaded;
        Ok(())
    }
}

/// Convert revm Error type (no Display impl) to local error type.
impl<DBError> From<EVMError<DBError>> for EvmError {
    fn from(value: EVMError<DBError>) -> Self {
        let e = match value {
            EVMError::Transaction(t) => {
                match serde_json::to_string(&t).map_err(|e| e.to_string()) {
                    Ok(tx_err) => tx_err,
                    Err(serde_err) => serde_err,
                }
            }
            // _d is Infallible - ignore.
            EVMError::Database(_d) => "database error".to_string(),
            EVMError::PrevrandaoNotSet => String::from("prevrandao error"),
        };
        EvmError::RevmError(e)
    }
}
