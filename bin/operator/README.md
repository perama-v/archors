## Operator

Takes lines from stdin and makes them trickle down the terminal.


### EVM data
EVM tracing can be sent to stdin, so this can be piped for an aesthetic representation
of real data.

This works if your node is on a different computer too. In this case,
open a separate terminal and run the following. This will redirect any JSON-RPC
calls on the current computer to the node.
```command
ssh -N -L 8545:127.0.0.1:8545 <node ip / alias>
```
Leave that terminal and open a separate terminal, the operator can be run there.


### Flags
See flags here:
```command
cargo run -qr -p archors_operator -- --help
```

### `debug_traceBlockByNumber` and `debug_traceBlockByNumber`

1. Call the node
    - Be careful to use `{"disableMemory": true}` or `{"enableMemory": false}` depending on the client.
    - Use curl with `--silent`/`-s`
    - Use cargo with `--quiet`/`-q`
2. Convert to NDJSON, compact form (one trace per line)
3. Send to archors_interpret
4. Send to archors_operator

Trace a particular transaction
```command
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc": "2.0", "method": "debug_traceTransaction", "params": ["0x8f5dd8107e2efce82759c9bbf34ac7bab49a2992b2f2ee6fc9d510f5e2490680", {"disableMemory": true}], "id":1}' http://127.0.0.1:8545 \
    | jq '.["result"]["structLogs"][]' -c \
    | cargo run -qr -p archors_interpret \
    | cargo run -qr -p archors_operator
```

Trace a whole block
```command
curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc": "2.0", "method": "debug_traceBlockByNumber", "params": ["finalized", {"disableMemory": true}], "id":1}' http://127.0.0.1:8545 \
    | jq '.["result"][]["result"]["structLogs"][]' -c \
    | cargo run -qr -p archors_interpret \
    | cargo run -qr -p archors_operator
```
### Looping

This calls the next latest block once the current one is finished. Note that there is some blank
screen while the next block is fetched. As displaying at a relaxed speed takes longer than 14
seconds, this will skip blocks.

When a block has finished displaying, get the latest block and start again.
```command
while true; do curl -s -X POST -H "Content-Type: application/json" --data \
    '{"jsonrpc": "2.0", "method": "debug_traceBlockByNumber", "params": ["latest", {"disableMemory": true}], "id":1}' \
    http://127.0.0.1:8545 \
    | jq '.["result"][]["result"]["structLogs"][]' -c \
    | cargo run -qr -p archors_interpret \
    | cargo run -qr -p archors_operator; done
```

### EIP-3155 trace
In the example below, revm executes a block producing an EIP3155 trace, which is then
filtered and interpreted. That is then passed to operator to display.

```command
cargo run -qr --example 09_use_proof | cargo run -qr -p archors_interpret 3155 | cargo run -qr -p archors_operator
```
Or for the raw trace:
```command
cargo run -qr --example 09_use_proof | cargo run -qr -p archors_operator
```
