## RequiredBlockState specification

Details for a data format that contains state required to
trace a single Ethereum block.

> Note: This is a draft to test a format for distributed archival nodes.

## Abstract

A specification for peer-to-peer distributable data that can enables trustless
tracing of an Ethereum block.

## Motivation

State is rooted in the header. A multiproof for all state required for all
transactions in one block enables is sufficient to trace any historical block.

In addition to the proof, BLOCKHASH opcode reads are also included.

Together, anyone with an ability to verify that a historical block header is canonical
can trustlessly trace a block without posession of an archive node.

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

The entire RequiredBlockState data format is represented by the following.

As proofs sometimes have common internal nodes, the nodes are kept separate.
A proof consists of a list of indices, indicating which node is used.

```python
class RequiredBlockState(Container):
    compact_eip1186_proofs: List[CompactEip1186Proof, MAX_ACCOUNT_PROOFS_PER_BLOCK]
    contracts: List[Contract, MAX_CONTRACTS_PER_BLOCK]
    account_nodes: List[TrieNode, MAX_ACCOUNT_NODES_PER_BLOCK]
    storage_nodes: List[TrieNode, MAX_STORAGE_NODES_PER_BLOCK]
    block_hashes: List[RecentBlockHash, MAX_BLOCKHASH_READS_PER_BLOCK]
```

### CompactEip1186Proof

```python
class CompactEip1186Proof(Container):
    address: Vector[uint8, 20]
    balance: List[uint8, 32]
    code_hash: Vector[uint8, 32]
    nonce: List[uint8, 8]
    storage_hash: Vector[uint8, 32]
    account_proof: List[uint16, MAX_NODES_PER_PROOF]
    storage_proofs: List[CompactStorageProof, MAX_STORAGE_PROOFS_PER_ACCOUNT]
```

### Contract

An alias for contract bytecode.
```python
Contract = List[uint8,  MAX_BYTES_PER_CONTRACT]
```

### TrieNode

An alias for a node in a merkle proof.
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

The proof consists of a list of indices, one per node.
```python
class CompactStorageProof(Container):
    key: Vector[uint8, 32]
    value: List[uint8, 8]
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
and load it with the RequiredBlockState and the block. Execute
the block and observe the trace.