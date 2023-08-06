## Operator

Takes lines from stdin and makes them trickle down the terminal.

EVM tracing can be sent to stdin, so this can be piped for an aesthetic representation
of real data.


### `debug_traceBlockByNumber` and `debug_traceBlockByNumber`

1. Call the node
2. Convert to NDJSON, compact form (one trace per line)
3. Send to archors_interpret
4. Send to archors_operator

```command
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc": "2.0", "method": "debug_traceTransaction", "params": ["0x8f5dd8107e2efce82759c9bbf34ac7bab49a2992b2f2ee6fc9d510f5e2490680", {"disableMemory": true}], "id":1}' http://127.0.0.1:8545 \
    | jq '.["result"]["structLogs"][]' -c \
    | cargo run --release -p archors_interpret \
    | cargo run --release -p archors_operator
```

### EIP-3155 trace
In the example below, revm executes a block producing an EIP3155 trace, which is then
filtered and interpreted. That is then passed to operator to display.

```command
cargo run --release --example 09_use_proof | cargo run --release -p archors_interpret 3155 | cargo run --release -p archors_operator
```
Or for the raw trace:
```command
cargo run --release --example 09_use_proof | cargo run --release -p archors_operator
```
