//! For single EVM instruction/opcode representations from a transaction trace.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum TraceLine {
    StepDebug(EvmStepDebug),
    StepEip3155(EvmStepEip3155),
    Output(EvmOutput),
}
impl TraceLine {
    pub(crate) fn depth(&self) -> u64 {
        match self {
            TraceLine::StepDebug(s) => *s.depth(),
            TraceLine::StepEip3155(s) => *s.depth(),
            TraceLine::Output(_) => 0,
        }
    }

    pub(crate) fn same_depth(&self, other: &TraceLine) -> bool {
        self.depth() == other.depth()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvmStepEip3155 {
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvmStepDebug {
    pub(crate) pc: u64,
    pub(crate) op: String,
    pub(crate) gas: u64,
    pub(crate) gas_cost: u64,
    pub(crate) depth: u64,
    pub(crate) stack: Vec<String>,
    pub(crate) memory: Option<Vec<String>>,
}

pub trait EvmStep {
    fn op_name(&self) -> &str;

    fn stack(&self) -> &[String];

    fn depth(&self) -> &u64;
}

impl EvmStep for EvmStepDebug {
    fn op_name(&self) -> &str {
        &self.op
    }

    fn stack(&self) -> &[String] {
        &self.stack
    }

    fn depth(&self) -> &u64 {
        &self.depth
    }
}

impl EvmStep for EvmStepEip3155 {
    fn op_name(&self) -> &str {
        &self.op_name
    }

    fn stack(&self) -> &[String] {
        &self.stack
    }

    fn depth(&self) -> &u64 {
        &self.depth
    }
}
