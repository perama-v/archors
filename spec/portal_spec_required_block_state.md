# Execution State Network

This document is the specification for the sub-protocol that supports on-demand availability of state data from the execution chain.

> 🚧 The spec is for design space exploration and is independent from the Portal Network

## Overview

The execution state network is a [Kademlia](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf) DHT that uses the [Portal Wire Protocol](./portal-wire-protocol.md) to establish an overlay network on top of the [Discovery v5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md) protocol.

State data from the execution chain consists of all account data from the main storage trie, all contract storage data from all of the individual contract storage tries, and the individul bytecodes for all contracts.

The EVM accesses the state when executing transactions through opcodes that read (e.g., SLOAD) or write (SSTORE) values that persist across blocks. After a block is finalized, the
state that was accessed is known. To re-execute an old block (also called 'tracing', as in `eth_debugTraceBlockByNumber`), only that state is required. This data can be called `RequiredBlockState`. As state data is stored in merkle tree, a proof can accompany every value
so that no trust is required.

The EVM also has access to recent blockhash values via the BLOCKHASH opcode. This data can also
be included in `RequiredBlockState` such that it is sufficient re-execute a block using two data structures: the block, and the `RequiredBlockState`.

### Data

#### Types

The network stores the full record of accessed state for the execution layer. This
includes merkle proofs for the values that were accessed:

- `RequiredBlockState` (state required to re-execute a block)
    - Account proofs
        - Contract bytecode
    - Contract storage proofs

#### Retrieval

- `RequiredBlockState` by block hash

Note that the history sub-protocol can be used to obtain the block (header and body/transactions).
Together, this is sufficient to re-execute that block.

## Specification

<!-- This section is where the actual technical specification is written -->

### Distance Function

The state network uses the following "ring geometry" distance function.

```python
MODULO = 2**256
MID = 2**255

def distance(node_id: uint256, content_id: uint256) -> uint256:
    """
    A distance function for determining proximity between a node and content.

    Treats the keyspace as if it wraps around on both ends and
    returns the minimum distance needed to traverse between two
    different keys.

    Examples:

    >>> assert distance(10, 10) == 0
    >>> assert distance(5, 2**256 - 1) == 6
    >>> assert distance(2**256 - 1, 6) == 7
    >>> assert distance(5, 1) == 4
    >>> assert distance(1, 5) == 4
    >>> assert distance(0, 2**255) == 2**255
    >>> assert distance(0, 2**255 + 1) == 2**255 - 1
    """
    if node_id > content_id:
        diff = node_id - content_id
    else:
        diff = content_id - node_id

    if diff > MID:
        return MODULO - diff
    else:
        return diff

```

This distance function distributes data evenly and deterministically across nodes. Nodes
with similar IDs will store similar data.

### Content ID Derivation Function

The derivation function for Content ID values is defined separately for each data type.

### Wire Protocol

#### Protocol Identifier

As specified in the [Protocol identifiers](./portal-wire-protocol.md#protocol-identifiers) section of the Portal wire protocol, the `protocol` field in the `TALKREQ` message **MUST** contain the value of:

`0x5050` (placeholder only)

#### Supported Message Types

The execution state network supports the following protocol messages:

- `Ping` - `Pong`
- `Find Nodes` - `Nodes`
- `Find Content` - `Found Content`
- `Offer` - `Accept`

#### `Ping.custom_data` & `Pong.custom_data`

In the execution state network the `custom_payload` field of the `Ping` and `Pong` messages is the serialization of an SSZ Container specified as `custom_data`:

```
custom_data = Container(data_radius: uint256)
custom_payload = SSZ.serialize(custom_data)
```

### Routing Table

The execution state network uses the standard routing table structure from the Portal Wire Protocol.

### Node State

#### Data Radius

The execution state network includes one additional piece of node state that should be tracked.  Nodes must track the `data_radius` from the Ping and Pong messages for other nodes in the network.  This value is a 256 bit integer and represents the data that a node is "interested" in.  We define the following function to determine whether node in the network should be interested in a piece of content.

```
interested(node, content) = distance(node.id, content.id) <= node.radius
```

A node is expected to maintain `radius` information for each node in its local node table. A node's `radius` value may fluctuate as the contents of its local key-value store change.

A node should track their own radius value and provide this value in all Ping or Pong messages it sends to other nodes.

### Data Types

#### Required block state

See [./spec/required_block_state.md](./portal_spec_required_block_state.md) for
the specification of the `RequiredBlockState` data type.

The content is addressed in the portal network using the blockhash, similar to the block header
in the history sub-protocol.

```
content                    := # See RequiredBlockState in the spec ./spec/required_block_state.md
required_block_state_key   := Container(block_hash: Bytes32)
selector                   := 0x00
content_key                := selector + SSZ.serialize(required_block_state_key)
content_id                 := keccak(content_key)
```

## Gossip

### Overview

A bridge node composes proofs for blocks when available. The network aims to have `RequiredBlockState` for every block older than 256 blocks.

There are two modes in which a bridge mode may operate:
- Contemporary: to populate data for recent (<=256) blocks. A bridge can be a full node.
- Historic: to populate data for old (>256) blocks. An bridge must be an archive node.

The bridge node must have access to a node that has the following methods:
- eth_debugTraceBlockByNumber
    - prestateTracer.
    - default, with memory disabled.
- eth_getProof
- eth_getBlockByNumber

The bridge node gossips each proof to some (bounded-size) subset of its peers who are closest to the data based on the distance metric.

### Terminology

Historical bridge mode requires archive node, contemporary mode only requires
full node.
```
Entire blockchain
<0>-------------...----------<256>-------------------head

Bridge modes
|-------------Historic-------|-----Contemporary------|
```
### eth_getProof complexity

Some node architectures (flat architecture) make `eth_getProof` for old blocks difficult. See https://github.com/ledgerwatch/erigon/issues/7748. Recent blocks are not problematic.

The network promises to have data for blocks older than 256 blocks. So, this lead-time allows
bridge nodes in contemporary mode to populate the network before they fall outside this 'easy'
window.

The network is most optimally populated as follows:
- Create historic data once using an archive node with architecture that supports
`eth_getProof` to arbitrary depths.
- Keep up with the chain tip with non-archive nodes. Full nodes have
have eth_getProof and eth_debugTraceBlock capacity to a depth of about 256

### Denial of service

The `RequiredBlockState` data is approximately 2.5MB on average (~167 kb/Mgas) by estimation. A bridge nodes could gossip data that has many valid parts, but some invalid data. While
a recipient portal node can independently identify and reject this, it constitutes a denial of service vector. One specific vector is including valid state proof for state that is not required
by the block. Hence, the node could trace the block locally to determine this, expending work without gain.

One mitigation for this is to compare offers from peers and use a heuristic to reject spam. As `RequiredBlockState` is deterministic, if two separate bridges produce the same data, that is evidence for correctness.

Another mitigation might be to have nodes signal if they have re-executed a given block using the `RequiredBlockState`. As node ids determine which data to hold and re-execute, a single node would not be required to re-execute long sequential collections of new data. A third mitigation is to create an accumulator for the hashes of all `RequiredBlockState` data that.

Critically, the recipient is not vulnerable to incorrect state data as proofs are included and are quick to verify. `RequiredBlockState` is a self contained package that does not need
additional network requests to verify.
