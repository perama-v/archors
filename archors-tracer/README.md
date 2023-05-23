# archors-tracer

For replaying Ethereum blocks using state from EIP-1186 proofs.

Sort of like a tiny trustless archive node that can only do one block.

## Why

When an ethereum block is retrieved with transaction details via `eth_getBlockByNumber` it doesn't have everything in it.


There are things that the EVM did that you cannot ascertain without tracing the block.
An archive node can trace the block because it can work out the state at any block.

However, if you have a proof for every state that you need in the block, you can trustlessly
trace the block.

If there is a data source of these proofs, then you could trace individual blocks.

## How

First verify the proof data (see archors-verify) against the block state root.
Then, start executing the first transaction.

Each time the EVM needs access to state (E.g., storage load via `SLOAD` for some key),
look up the key in the proof data and get the value there.

If the transaction modifies state data (E.g., storage store via `SSTORE` for some key),
make a note of what the new value is (in case it is used later in the block).

Output the transaction traces in a way that conforms to `eth_debugTraceTransaction`.

