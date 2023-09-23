# archors-multiproof

Combine multple EIP-1186 proofs rooted in the same block.

This allows the state root to be updated using state changes that occur
due to transactions in that block.


> 🚧 Blocker: For some key deletions, there is insufficient data to construct
the new root.

## Why

If one has a collection of proofs that cover all state for a block, then updating
this collection to get post-transaction state roots requires aggregating this collection
into a multiproof.

After applying every transaction in a block, the state root will be equal to the
state root in the header for that block.

This verifies that execution of transactions resulted in the correct state changes
for the block.

One cannot use a proof library that takes leaves as inputs because we do not know
all the leaves in the tree - we only have values along the path for key being proven.

## How

1. Get proofs (see archors-inventory)
2. Verify the proof data (see archors-verify) against the block state root of the previous header.
3. Start executing transactions (see archors-tracer) and observe state changes after each transaction.
4. Combine storage proofs / account proofs that belong to the same tries, then make changes to leaves (this crate).

Trie proofs visually look like pruned trees. Overlapping multiple pruned versions of the same tree
results in some common path/nodes. Now when one leaf is modified it will change nodes present
in the path for a different key. These changed nodes makes the proof for that key valid with
respect to the new updated root.

The input is a list of proofs (either multiple accounts or multiple storage slots for one account).
The output is a struct that has overlapped the proofs into one structure (multiproof).

Then calling update will compute the new hashes from leaf -> root and produce a new root hash.

## Architecture

### Combining proofs
An EIP-1186 proof consists of a vector of nodes, starting with the root end:


```mermaid
flowchart TD
    A[root end] --> B[intermediate node] --> C[intermediate node] --> D[leaf end]
```
Where each node consists of items:
- Branch node (16 node hashes, +/- 1 value)
- Extension node (extension, next node hash)
- Leaf node (path, value)

Suppose we have two accounts, with proofs: [A, B, C] and [A, B, X]
```mermaid
flowchart TD
    A --> B --> C
    B --> X
```
Node B, which is commone to both proofs is a branch node. As the proofs
diverge here, the path followed for the different accounts diverges here,
and different items in this node are followed:

```mermaid
flowchart TD
    A --> B
    I1 --> C
    I15 --> X

    subgraph B
    I0[Item 0]
    I1[Item 1]
    Ix[Item ...]
    I15[Item 15]
    I16[Item 16]
    I[Value ]
    end
```
Here to get to node X, item index 15 was followed.

To combine these proofs, we see that node B is unchanged, we refer to different items within it.
However, if there are nodes at the level below, we can see that we may now need to store multiple nodes at a given level/depth in the tree.



```mermaid
flowchart TD
    A --> B
    I1 --> C
    C0 --> D
    C15 --> E
    I15 --> X
    X1 --> Y
    X16--> Z

    subgraph B
    I0[Item 0]
    I1[Item 1]
    Ix[Item ...]
    I15[Item 15]
    I16[Item 16]
    Iv[Value ]
    end

    subgraph C
    C0[Item 0]
    C1[Item 1]
    Cx[Item ...]
    C15[Item 15]
    C16[Item 16]
    Cv[Value ]
    end


    subgraph X
    X0[Item 0]
    X1[Item 1]
    Xx[Item ...]
    X15[Item 15]
    X16[Item 16]
    Xv[Value ]
    end
```
With branches, extension nodes and exclusion proofs the shape of the trie can vary a lot.

### Retrieval

An element in the proof will be looked up by key, which defines the path (nibbles along `keccak(key)`) to follow from root to hash.

Suppose one wants to look up E, but there has been an update where D was changed and now A, B and C are all different.

1. Get the path (keccak(E))
2. Start at the root of the tree and follow the first nibble/path part
3. Item 1 is reached, which is a hash.
4. Look up the hash in a hashmap, C is returned.
5. Continue nibble/path part. Get the hash, look it up to get E.

What was the process for updating D?

1. Retrieve D (see above), but retain the parts along the way.
2. Modify D, then hash it
3. Recall the prior node. Now modify item 0 to be keccak(D).
4. Continue to the prior node, replace the item with the hash of the modified child.

Hence we have a hashmap that we are modifying the values of.

### Summary
For a set of proofs with a known root, pile the proof nodes all into a HashMap keccak(node), node. Then pile all the keys into a vector.

The proof is capped in size (it's for one block) and will fit in memory, so
no optimisations seem important here (proof sparsity, HashMap replacements, Etc.,).

Make a modification (see above). Then when recalculate the hashes all the way to the root. This is the new root of the trie. This must be stored so one can retrieve the root for following paths for
any key.


## Editing proofs

A change the the proof structure may be required to get the post-block state root.
For example: If a key is not in the trie, and is added during the block, then it
may start as an exclusion proof, and will then be an inclusion proof.

Exclusion proof for path ...abcdef

```mermaid
flowchart TD
    A[some traversal ...] --> B[extension 'abc12345'] --> C[branch B]
    B -.- E[Exclusion proof for key `...abcdef`]
```

Converting to inclusion proof, the extension node is shortened to 'abc' and a new branch
node is added:

```mermaid
flowchart TD
    A[some traversal ...] --> B[extension 'abc'] --> F[branch A]
    F --item 1--> C[extension '2345'] --> D[branch B]
    F --item d--> E[path 'ef', inclusion proof for leaf '...abcdef']
```

## Proof edits with tree depth reduction

If there is an inclusion proof that is converted to an exclusion proof, this
may result in a removal of some internal nodes.

In some cases, this requires knowledge of nodes where only the hash(node) is present.
These cases have the property:
- The leaf has only one sibling node
- The sibling node is an extension or a leaf

In a trio (grandparent-parent-sibling):
- **E & **L: Additional sibling node RLP required to make updates.
    - EBE -> E
    - EBL -> L
    - BBE -> BE
    - BBL -> BL
- **B: Additional sibling node type and hash required to make updates.
    - EBB -> EB
    - BBB -> BEB

In all scenarios, the goal is to update the grandparent so that trie changes can be made all the
way to the root. The grandparent hash is the missing component. This could be achieved either
by
- Updating trie structure according to the above principles (see below for expanded forms).
This requires sibling RLP knowledge, which is not readily available information using eth_getProof.
- Getting the grandparent node. The post-state eth_getProof for the key can be treated as an oracle
for the grandparent.

See relevant code at: [./src/proof.rs](./src/oracle.rs)

### Algorithm - grandparent oracle

The grandparent that needs to be updated when a parent is deleted can be fetched from an oracle.
The grandparent is hashed and added to the multiproof, cascading changes to the hashes all the
way to the root. Final verification of the state root will show that the oracle data is valid.

### Algorithm - revisiting an oracle-based node

> Note: this is not implemented and so archors will not detect an EVM bug affecting these storage
> keys. The number of affected keys is likely very small, but has not been measured.

When an update to a different key involves traversing that oracle-based grandparent, the
traversal will naturally follow the updated grandparent. How can one check that the state updates
for the key are correct?

One can add a flag to oracle-based nodes. When encountered, the old node should be traversed and
a temporary subtree created for the changes. When the root of the subtree matches the hash in the
oracle-based node, the output of the EVM is confirmed to be correct.

## Patterns

The following section illustrates the structure of some scenarios that require oracle-based
information.

### Pattern: Extension-Branch-Extension to Extension

Suppose the deletion of key ...abcdef

```mermaid
flowchart TD
    A[some traversal ...] --> B[extension 'abc'] --> F[branch A]
    F --item 1--> C[extension '2345'] --> D[branch B]
    F --item d--> E[path 'ef', inclusion proof for leaf '...abcdef']
```
In this case, branch A is removed and the surrounding two extensions are be combined.


```mermaid
flowchart TD
    A[some traversal ...] --> B[extension 'abc12345'] --> F[branch B]
```

Pattern: EBE -> E+

This creates a problem because we do not have the extension node '2345' in this multiproof,
only the hash of that node inside branch B. The extension node is not available, and
so it is not known what path to combine with the 'abc1' path.


```mermaid
flowchart TD
    A[some traversal in block n - 1...] --> B[extension 'abc'] --> F[branch A]
    F -.item 1.-> C[hash of extension '2345']
    F --item d--> E[path 'ef', inclusion proof for leaf '...abcdef']
```
Resolution: This scenario can be anticipated and the node can be made part of the
data required for block `n`. Here the absence of the key in the next block is
identified and an exclusion proof obtained via `eth_getProof`.

```mermaid
flowchart TD
    A[some traversal in block n...] --> B[extension 'abc12345']
    B -.-> E[exclusion proof for path '...abcdef']
```

### Pattern: Branch-Branch-Extension to Branch-Extension

This is a different trie structure that results in the same situation.
```mermaid
flowchart TD
    A[some traversal ...] --> B[branch node A] --item c--> F[branch node B]
    A --> N[Some node]
    F --item 1--> C[extension '2345'] --> D[branch node C]
    F --item d--> E[path 'ef', inclusion proof for leaf '...abcdef']
```


In this case, branch node B will only have one item and must be removed.
The extension now absorbs the extra '1' part of the path. As above, this
requires oracle based information.

```mermaid
flowchart TD
    C[extension '12345']
    A[some traversal ...] --> B[branch node A] --item c--> C
    A --> N[Some node]
    C --> D[branch node C]
```

Pattern: BBE -> BE+


### Pattern: Extension-Branch-Branch to Extension-Branch

This is a a trie structure where the sibling is a branch.
The sibling is ultimately not updated, but knowledge that it is a branch requires oracle-based
information.

```mermaid
flowchart TD
    A[some traversal ...] --> B[extension node 'abc'] --> F[branch node B]
    A --> N[Some node]
    F --item 1--> D[branch node C]
    D --item 2--> X[leaf 345]
    D --item 5 --> Y[leaf 555]
    F --item d--> E[path 'ef', inclusion proof for leaf '...abcdef']
```

The Branch node B is removed, so the extension gains the '1'

```mermaid
flowchart TD
    A[some traversal ...] --> B[extension node 'abc1'] --> D
    A --> N[Some node]
    D[branch node C]
    D --item 2--> X[leaf 345]
    D --item 5 --> Y[leaf 555]
```

Pattern EBB -> E+B


### Pattern: Branch-Branch-Branch


This is a trie structure where the sibling is a branch and so is the grandparent.
The sibling is ultimately not updated, but knowledge that it is a branch requires oracle-based
information.

```mermaid
flowchart TD
    T[some traversal ...] --item a--> A
    A[branch node] --item b--> B[branch node] --item c--> F[branch node B]
    A --> N[Some node]
    B --> G[Some node]
    F --item 1--> D[branch node C]
    D --item 2--> X[leaf 345]
    D --item 5 --> Y[leaf 555]
    F --item d--> E[path 'ef', inclusion proof for leaf '...abcdef']
```

The Branch node B is removed, and itself has a siblings, so it is turned into a single
nibble extension '1'.

```mermaid
flowchart TD
    T[some traversal ...] --item a--> A
    A[branch node] --item b--> B[branch node] --item c--> F[extension '1']
    A --> N[Some node]
    B --> G[Some node]
    F --> D[branch node C]
    D --item 2--> X[leaf 345]
    D --item 5 --> Y[leaf 555]
```


Pattern BBB -> BEB
