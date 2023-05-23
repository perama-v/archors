# archors-inventory

For discovering which state was accessed for an Ethereum block.

## Why

When a block is executed, it may access any state. However, once included blocks
only access a tiny subset of all state.

That information is useful because one can get a proof for each of these state
values using `eth_getProof`. As a finite list, this inventory of accessed state
can be used to create a collection of state proofs.

With the state proofs, anyone could trustlessly replay the block because every
state is anchored the state root in the block header.

## How

For every transaction in a block, call `debug_traceTransaction` and specify the `prestateTracer`.
This returns the state prior to each transaction execution.

Detect if a transaction state access was already accessed in a prior transaction and ignore these
values.

For each state call `eth_getProof`, verify the proofs, then store them.