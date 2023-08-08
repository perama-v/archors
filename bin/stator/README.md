## Stator

Uses an Ethereum node to generate test cases for the `eth_getRequiredBlockState` JSON-RPC method.

### Flags
See flags here:
```command
cargo run --release -p archors_stator -- --help
```

### Format

The data returned in response to the `eth_getRequiredBlockState` method is the
`RequiredBlockState`. It is ssz-encoded and snappy-compressed, and is delivered over JSON-RPC
as a hex encoded string "0xabcde...".

The .ssz_snappy binary data is approximately ~176kB/Mgas, which is about ~2.5MB per block.
The test generator outputs a hex string by default, and so is about ~5MB per block. The
binary data can also be generated.

### Use

The `RequiredBlockState` is used as follows:

1. Acquire a block with transactions (via `eth_getBlockByNumber`)
2. Acquire block prestate (via `eth_getRequiredBlockState`)
3. Load block and state into an EVM (e.g., revm)
4. Execute the block (and any tracing/parsing as needed)

In this way, one can generate a full trace of every opcode, and including EVM stack and memory.
From the starting data (~5MB), the derived trace can be up to 10s of GB.

A full working example of using a proof to run revm can be seen in:
- [../../examples](../../examples/09_use_proof.rs) library examples showing generation of a raw trace
- [../interpret](../interpret/README.md) binary for parsed trace
- [../operator](../operator/README.md) binary for a visual representation of a parsed trace

### Example
To create hex-string file containing the RequiredBlockState for block 17190873.
```command
RUST_LOG=info cargo run --release -p archors_stator -- -b 17190873
```
A file is created, containing the following (truncated) text. This is ssz-snappy encoded
data that can be used to re-execute that block.
```
0xff060000734e6150705900b07d007316...f5f2490ff2ae79390000000001064fd8
```
### Running time
The application calls `eth_getProof` a number of times (one per account accessed in that block).
This can amount to hundreds of calls. Logging (`RUST_LOG=info cargo run  ...`) will
show the stages of completion, including how many `eth_getProof` calls are being made.