# archors

**arch**ival sciss**ors**: A tool for single Ethereum archival block state proofs.

Research question: Can you build a static data format for a sharded archive node?

## Why

To send a single historical block (as an historical state proof) to a peer and have
them be able to trustlessly trace the transactions in that block.

Background: https://perama-v.github.io/ethereum/protocol/archive

Who would want that? If there was a network distributing such proofs then users could
collectively shard an archive node. This could be an extension to an existing network
such as the Portal Network, which already has a block header cryptographic accumulator.

How are these >17 million proofs being generated? With this tool! One needs an archive node
that serves `eth_getProof`. Then the actual historical state at each block can be exported and stored. These proofs only include state that was accessed during that block, not the entire chain state.

A proof plus a block body allows isolated single block trace. That is, every EVM operation
can be replayed and inspected - without needing the rest of the chain. Nodes can store
subsets of the data and remain functional and trustless.

## Status

> 🚧 Toy/experimental

In order to construct proofs for the entire history of the chain an Ethereum execution
node must provide both:
- debug_traceTransaction
- eth_getProof

## Modes

|example number|crate used|function|
|-|-|-|
|1, 2, 3|inventory|obtain and cache block data from a node|
|4, 5|inventory|create merkle proof for block state|
|6|verify|verify merkle proof for block|
|7|tracer|locally produce `debug_traceTransaction` / `debug_traceBlock` using proof data|

## Use case

Run `debug_traceTransaction` or `trace_Transaction` with minimal data. A CDN could provide
proofs for all historical blocks. Acquisition of one is sufficient to trustlessly replay
that block and trace a single transaction.

## Requirements

- Requires knowledge of canonicality of block headers, such as through a cryptographic accumulator.
- Full node connection for blocks up to 128 blocks old, or archive node connection for older blocks.

## State proof viz

We are working with radix trees. The radix trees have depth 2, which makes them
a Practical Algorithm to Retrieve Information Coded in Alphanumeric (PATRICIA) trees.

The trees are nested, with one state tree (tree 1) holding the roots of many storage trees (tree 2).


```mermaid
flowchart TD
    SR[state root for tree 1]
    AA[leaf node: account address]
    ARLP[leaf data: account RLP data]
    storage_root[storage root for tree 2]
    codehash[code hash]
    siblings[... nodes have up to 16 siblings]
    SK[leaf node: storage key]
    siblings2[... nodes have up to 16 siblings]
    SV[leaf data: storage value]

    SR --o AA & siblings
    AA ---> ARLP
    ARLP -.- nonce & balance & storage_root & codehash
    storage_root --o SK & siblings2
    SK -.- SV
```
### State tree value structure
The leaf data of the state root (first) tree is Recursive Length Prefix (RLP) encoded.
So to provide someone with a specific storage value (e.g., some storage slot that will be
accessed during a block) in the storage (second) tree, the RLP data must be reconstructed, hashed and proved in the first
tree. This requires that the code hash, nonce and balance for every account accessed must be
part of the proof data.

### Combining all accessed state

A retrospective look at one block can reveal all the leaf data that is needed to execute that block.
Aggregation of all those values into one big tree (tree 1 containing many values including
tree 2 roots) is the proof.

Imagine that a block only accessed one storage value from one contract (AKA account).
Here is the data that would be in the proof:
- Storage key
- Storage value
- Account storage root (of storage tree, using key/value)
- Account code hash
- Account nonce
- Account balance

A call to `debug_traceTransaction` with the `prestateTracer` may return
balance, code, nonce and storage, and some fields may absent.

If only the balance of an address is accessed (there is code etc that is not
accessed), the other fields are still required. Once obtained, the other fields are RLP encoded
to get the account leaf, then the hash of that encoded data is the account node.

Thus the prestateTracer is necessary (to know which storage keys are accessed) but
insufficient (does not get account storage root or other unaccessed account state fields).

The next step is therefore to call `eth_getProof` for every account. This will
provide the account node (account state root), the account value (RLP encoded data)
and the storage proof against the storage root in that encoded data.

```mermaid
sequenceDiagram
    Actor Archors
    participant BBH as eth_getBlockByHash
    participant DTT as debug_traceTransaction with prestateTracer
    participant GP as eth_getProof for account slots
    Actor Peer

    Archors ->> BBH: Block please
    activate BBH
    BBH -->> Archors: block with transaction hashes
    deactivate BBH

    loop For each transaction
        Archors ->> DTT: What state was accessed?
        activate DTT
        DTT -->> Archors: Code, storage key-value pairs, balance nonce
        deactivate DTT
    end
    Note right of Archors: Aggregate all slots for all accounts

    loop For each account
        Archors ->> GP: Proof for slots please
        activate GP
        GP -->> Archors: Account proof and storage proof
        deactivate GP
    end

    Note right of Archors: Create block state proof for all account nodes
    Archors ->> Peer: Use this to trustlessly run trace_block, trace_transaction or debug_traceTransaction. You will need a block header accumulator.
```
The proof sent to a peer is a proof of all accessed accounts, and for each account
a proof for each accessed storage slot is included.

## State and proof data properties

A sample (`./data/blocks/17190873`) is prepared using the examples, which
calls a node and caches the results. The data directory holds a lot of intermediate
data for testing.

The transferrable proof file (`./data/blocks/17190873/prior_block_transferrable_state_proofs.ssz_snappy`)
is the most important. It is an SSZ + snappy encoded representation of all the data required
to trace a block trustlessly. This includes contract code, account state values, storage state values and their respective merkle proofs.

Components required to trace the block:
- Block header confidence (header accumulator)
- `eth_getBlockByNumber` with flag transactions=`true`
- transferrable ssz snappy proof file.

Transferrable refers to this being a payload that could be transferred to a peer.

### Size
How big is this transferrable

|Block|MGas|Txs|Internal Txs|Total P2P payload|
|-|-|-|-|-|
|17190873|29|200|217|3.3 MB|
|17193183|17|100|42|1.6 MB|
|17193270|23|395|97|3.8 MB|

This is too small a sample to extrapolate from, but I will do exactly that
and use the average (2.9MB).
```
17 million blocks * 2.9 MB per block ~= 50 TB.
```
This for example could equate to a network with:
- replication of data 2x for redundancy
- 1000 nodes
- 100GB nodes

|Nodes|Node size (replication = 1)| Node size (replication = 2)| Node size (replication = 10)|
|-|-|-|-|
|1|50TB|100TB|500TB|
|100|500GB|1TB|5TB|
|1000|50GB|**-> 100GB <-**|500GB|
|10000|5GB|10GB|50GB|

Which is to say  archive node that is ~1/10th the size of a

### Additional compression

It is noted that contract data and merkle tree nodes are common amongst different blocks.
This represents compressible data for a single node. The prevalence of these occurrences
and therefore the amount of additional compression available is unknown.

## Trace data

What does tracing get you? Every step in the EVM.

```command
cargo run --release --example 07_use_proof |  grep '"REVERT"' | jq
```
This example is set to trace transaction index 14 in block 17190873. The
result is filtered to only include steps that involved a `REVERT` opcode.

Here we can see the `REVERT`s in action at stack depths 3, 2 and then 1 at
program counters 2080, 8672, 17898. One could create a parser that:

- The contract that was reverted from
- The function that was being called
- The values passed to that contract

```json
{
  "pc": 2080,
  "op": 253,
  "gas": "0x50044",
  "gasCost": "0x0",
  "memSize": 256,
  "stack": [
    "0xa9059cbb",
    "0x2f2",
    "0x53ae61d9e66d03d90a13bbb16b69187037c90f0d",
    "0x17d08f5af48b00",
    "0x0",
    "0x981",
    "0x9aaab62d0a33caacab26f213d1f41ec103c82407",
    "0x53ae61d9e66d03d90a13bbb16b69187037c90f0d",
    "0x17d08f5af48b00",
    "0x0",
    "0x64",
    "0x80"
  ],
  "depth": 3,
  "opName": "REVERT"
}
{
  "pc": 8672,
  "op": 253,
  "gas": "0x871d8",
  "gasCost": "0x0",
  "memSize": 576,
  "stack": [
    "0x22c0d9f",
    "0x257",
    "0x0",
    "0x17d08f5af48b00",
    "0x53ae61d9e66d03d90a13bbb16b69187037c90f0d",
    "0xa4",
    "0x0",
    "0x29f2360d4550f0ab",
    "0x10878fe6d250800",
    "0x0",
    "0x0",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "0xfc720f8d776e87e9dfb0f59732de8b259875fa32",
    "0x8e1",
    "0xfc720f8d776e87e9dfb0f59732de8b259875fa32",
    "0x53ae61d9e66d03d90a13bbb16b69187037c90f0d",
    "0x17d08f5af48b00",
    "0x0",
    "0x124",
    "0x64",
    "0x1c4"
  ],
  "depth": 2,
  "opName": "REVERT"
}
{
  "pc": 17898,
  "op": 253,
  "gas": "0x895b0",
  "gasCost": "0x0",
  "memSize": 1184,
  "stack": [
    "0x7ff36ab5",
    "0x340",
    "0x71afd498d0000",
    "0xa4",
    "0x2",
    "0x53ae61d9e66d03d90a13bbb16b69187037c90f0d",
    "0x1787586c4fa8a01c71c7",
    "0xe0",
    "0x1787586c4fa8a01c71c7",
    "0x250b",
    "0xe0",
    "0x2ba",
    "0x53ae61d9e66d03d90a13bbb16b69187037c90f0d",
    "0x0",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "0xfc720f8d776e87e9dfb0f59732de8b259875fa32",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "0x17d08f5af48b00",
    "0x0",
    "0x17d08f5af48b00",
    "0x53ae61d9e66d03d90a13bbb16b69187037c90f0d",
    "0x9aaab62d0a33caacab26f213d1f41ec103c82407",
    "0x22c0d9f",
    "0x49b",
    "0x1",
    "0x64",
    "0x0"
  ],
  "depth": 1,
  "opName": "REVERT"
}
```