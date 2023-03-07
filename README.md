# archival-scissors
A tool for single Ethereum archival block state proofs.

## Why

To send a single historical block to a peer and have
them be able to trustlessly trace the transactions in that block.

Background: https://perama-v.github.io/ethereum/protocol/archive

## Modes

### Generate

Start with a block trace, generate a Merkle proof of any state accessed by that block.

### Consume

Start with a block state proof, generate a trace of that block.

## Use case

Run `debug_traceTransaction` or `trace_Transaction` with minimal data. A CDN could provide
proofs for all historical blocks. Acquisition of one is sufficient to trustlessly replay
that block and trace a single transaction.

## Requirements

Requires knowledge of canonicality of block headers, such as through a cryptographic accumulator.
