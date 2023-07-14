## RequiredBlockState specification

Details for a data format that contains state required to
trace a single Ethereum block.

> Note: This is a draft to test a format for distributed archival nodes.

This data structure may be suitable as a sub-protocol in the Portal Network,
see the accompanying sub-protocol spec [./spec/required_block_state_subprotocol.md](./required_block_state_subprotocol.md)
## Abstract

A specification for peer-to-peer distributable data that can enables trustless
tracing of an Ethereum block.

## Motivation

State is rooted in the header. A multiproof for all state required for all
transactions in one block enables is sufficient to trace any historical block.

In addition to the proof, BLOCKHASH opcode reads are also included.

Together, anyone with an ability to verify that a historical block header is canonical
can trustlessly trace a block without posession of an archive node.

The format of the data is deterministic, so that two peers creating the same
data will produce identical structures.

## Table of Contents


## Overview

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in RFC 2119 and RFC 8174.

### General Structure


### Notation
Code snippets appearing in `this style` are to be interpreted as Python 3 psuedocode. The
style of the document is intended to be readable by those familiar with the
Ethereum [consensus](#ethereum-consensus-specification) and
[ssz](#ssz-spec) specifications. Part of this
rationale is that SSZ serialization is used in this index to benefit from ecosystem tooling.
No doctesting is applied and functions are not likely to be executable.

Where a list/vector is said to be sorted, it indicates that the elements are ordered
lexicographically when in hexadecimal representation (e.g., `[0x12, 0x3e, 0xe3]`) prior
to conversion to ssz format. For elements that are containers, the ordering is determined by
the first element in the container.

### Endianness

Big endian form is used as most data relates to the Execution context.

## Constants

### Design parameters

| Name | Value | Description |
| - | - | - |
|-|-|-|

### Fixed-size type parameters


| Name | Value | Description |
| - | - | - |
|-|-|-|

### Variable-size type parameters

Helper values for SSZ operations. SSZ variable-size elements require a maximum length field.

Most values are chosen to be the approximately the smallest possible value.

| Name | Value | Description |
| - | - | - |
| MAX_ACCOUNT_NODES_PER_BLOCK | uint16(32768) | - |
| MAX_BLOCKHASH_READS_PER_BLOCK | uint16(256) | A BLOCKHASH opcode may read up to 256 recent blocks |
| MAX_BYTES_PER_NODE | uint16(32768) | - |
| MAX_BYTES_PER_CONTRACT | uint16(32768) | - |
| MAX_CONTRACTS_PER_BLOCK | uint16(2048) | - |
| MAX_NODES_PER_PROOF | uint16(64) | - |
| MAX_STORAGE_NODES_PER_BLOCK | uint16(32768) | - |
| MAX_ACCOUNT_PROOFS_PER_BLOCK | uint16(8192) | - |
| MAX_STORAGE_PROOFS_PER_ACCOUNT | uint16(8192) | - |

### Derived

Constants derived from [design parameters](#design-parameters).

| Name | Value | Description |
| - | - | - |
|-|-|-|

## Definitions

### RequiredBlockState

The entire `RequiredBlockState` data format is represented by the following.

As proofs sometimes have common internal nodes, the nodes are kept separate.
A proof consists of a list of indices, indicating which node is used.

```python
class RequiredBlockState(Container):
    # sorted
    compact_eip1186_proofs: List[CompactEip1186Proof, MAX_ACCOUNT_PROOFS_PER_BLOCK]
    # sorted
    contracts: List[Contract, MAX_CONTRACTS_PER_BLOCK]
    # sorted
    account_nodes: List[TrieNode, MAX_ACCOUNT_NODES_PER_BLOCK]
    # sorted
    storage_nodes: List[TrieNode, MAX_STORAGE_NODES_PER_BLOCK]
    # sorted
    block_hashes: List[RecentBlockHash, MAX_BLOCKHASH_READS_PER_BLOCK]
```

> Note that merkle patricia proofs may be replaced by verkle proofs after some hard fork

### CompactEip1186Proof

```python
class CompactEip1186Proof(Container):
    address: Vector[uint8, 20]
    balance: List[uint8, 32]
    code_hash: Vector[uint8, 32]
    nonce: List[uint8, 8]
    storage_hash: Vector[uint8, 32]
    # sorted: node nearest to root first
    account_proof: List[uint16, MAX_NODES_PER_PROOF]
    # sorted
    storage_proofs: List[CompactStorageProof, MAX_STORAGE_PROOFS_PER_ACCOUNT]
```

### Contract

An alias for contract bytecode.
```python
Contract = List[uint8,  MAX_BYTES_PER_CONTRACT]
```

### TrieNode

An alias for a node in a merkle patricia proof.

Merkle Patricia Trie (MPT) proofs consist of a list of witness nodes that correspond to each trie node that consists of various data elements depending on the type of node (e.g. blank, branch, extension, leaf).  When serialized, each witness node is represented as an RLP serialized list of the component elements.

```python
TrieNode = List[uint8,  MAX_BYTES_PER_NODE]
```

### RecentBlockHash

```python
class RecentBlockHash(Container):
    block_number: List[uint8, 8]
    block_hash: Vector[uint8, 32]
```

### CompactStorageProof

The proof consists of a list of indices, one per node. The indices refer
to the nodes in `TrieNode`.
```python
class CompactStorageProof(Container):
    key: Vector[uint8, 32]
    value: List[uint8, 8]
    # sorted: node nearest to root first
    proof: List[uint16, MAX_NODES_PER_PROOF]
```

## Helper functions

High level algorithms relevant to the production/use of RequiredBlockState

### Get state accesses

Trace the block with the prestate tracer, record key/value pairs where
they are first encountered in the block.

### Get proofs

Call eth_getProof for each state key required. Do this for the block prior
to the block of interest (state is stored as post-block state).

### Verify data

Check block hashes are canonical against an accumulator of canonical
block hashes. Check merkle proofs in the requied block state.

### Trace block locally

Obtain a block (eth_getBlockByNumber) with transactions. Use an EVM
and load it with the `RequiredBlockState` and the block. Execute
the block and observe the trace.