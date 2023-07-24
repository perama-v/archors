//! For single EVM instruction/opcode representations from a transaction trace.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Eip3155Line {
    Step(EvmStep),
    Output(EvmOutput),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvmStep {
    pub(crate) pc: u64,
    pub(crate) op: u64,
    pub(crate) gas: String,
    pub(crate) gas_cost: String,
    pub(crate) mem_size: u64,
    pub(crate) stack: Vec<String>,
    pub(crate) depth: u64,
    pub(crate) op_name: String,
    pub(crate) memory: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvmOutput {
    pub(crate) output: String,
    pub(crate) gas_used: String,
}
