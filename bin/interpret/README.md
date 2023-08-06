## Archors interpret

Takes a stream of a transaction trace from stdin and produces
a stream to stdout.

The output is readable so one can see what the transaction did.

The function is pure in that only the transaction trace is used

## Flags

The interpreter may be passed different trace styles, as long as they are NDJSON.

### EIP-3155

This will be NDJSON by default. No flag is required for this style

### `debug_traceTransaction` and `debug_traceBlockByNumber`

This will be a JSON object and may be converted to NDJSON as follows:
```
<trace> | jq '.["result"]["structLogs"][]' -c
```
The `--debug` flag must be used for this kind of trace.
For example:
```
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc": "2.0", "method": "debug_traceTransaction", "params": ["0x8f5dd8107e2efce82759c9bbf34ac7bab49a2992b2f2ee6fc9d510f5e2490680", {"disableMemory": true}], "id":1}' http://127.0.0.1:8545 \
    | jq '.["result"]["structLogs"][]' -c \
    | cargo run --release -p archors_interpret --debug
```
## Examples

### Multiple contract creations

Transaction (index 185) in block 17190873.

Unreadable trace (via REVM EIP3155 inspector):
```
{"pc":0,"op":96,"gas":"0xe636b","gasCost":"0x3","memSize":0,"stack":[],"depth":1,"opName":"PUSH1"}
{"pc":2,"op":96,"gas":"0xe6368","gasCost":"0x3","memSize":0,"stack":["0x80"],"depth":1,"opName":"PUSH1"}
{"pc":4,"op":82,"gas":"0xe6365","gasCost":"0xc","memSize":0,"stack":["0x80","0x40"],"depth":1,"opName":"MSTORE"}
...
~7000 lines omitted
...
{"pc":133,"op":86,"gas":"0x4ec9a","gasCost":"0x8","memSize":384,"stack":["0x8467be0d","0x43"],"depth":1,"opName":"JUMP"}
{"pc":67,"op":91,"gas":"0x4ec92","gasCost":"0x1","memSize":384,"stack":["0x8467be0d"],"depth":1,"opName":"JUMPDEST"}
{"pc":68,"op":0,"gas":"0x4ec91","gasCost":"0x0","memSize":384,"stack":["0x8467be0d"],"depth":1,"opName":"STOP"}
{"output":"0x","gasUsed":"0x4ec91"}
```

Interpretation:
```
Function 0x8467be0d
        Deploy contract (CREATE)
                Contract (CALL) using code and storage at created contract (index 0), message.sender is tx.from
                        Function 0x84bc8c48
                        Function 0x84bc8c48
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Stopped
                Contract (STATICCALL) using code and storage at created contract (index 0), message.sender is tx.from
                        Function 0x70a08231
                        Function 0x70a08231
                        Function 0x70a08231
                        Returned
                Contract (CALL) using code and storage at created contract (index 0), message.sender is tx.from
                        Function 0xa9059cbb
                        Function 0xa9059cbb
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Returned
                Returned. Created contract (index 0) has address 0xba47611fb35365ffea81803c7163aa9a49b01110
        Deploy contract (CREATE)
                Contract (CALL) using code and storage at created contract (index 1), message.sender is tx.from
                        Function 0x84bc8c48
                        Function 0x84bc8c48
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Stopped
                Contract (STATICCALL) using code and storage at created contract (index 1), message.sender is tx.from
                        Function 0x70a08231
                        Function 0x70a08231
                        Function 0x70a08231
                        Returned
                Contract (CALL) using code and storage at created contract (index 1), message.sender is tx.from
                        Function 0xa9059cbb
                        Function 0xa9059cbb
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Returned
                Returned. Created contract (index 1) has address 0x9e1c11e99f9a51171defc026134a6c08f95da292
        Deploy contract (CREATE)
                Contract (CALL) using code and storage at created contract (index 2), message.sender is tx.from
                        Function 0x84bc8c48
                        Function 0x84bc8c48
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Stopped
                Contract (STATICCALL) using code and storage at created contract (index 2), message.sender is tx.from
                        Function 0x70a08231
                        Function 0x70a08231
                        Function 0x70a08231
                        Returned
                Contract (CALL) using code and storage at created contract (index 2), message.sender is tx.from
                        Function 0xa9059cbb
                        Function 0xa9059cbb
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Returned
                Returned. Created contract (index 2) has address 0x7766e2545ca92a0b7918a67f3ef2a05aa9198664
        Deploy contract (CREATE)
                Contract (CALL) using code and storage at created contract (index 3), message.sender is tx.from
                        Function 0x84bc8c48
                        Function 0x84bc8c48
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Stopped
                Contract (STATICCALL) using code and storage at created contract (index 3), message.sender is tx.from
                        Function 0x70a08231
                        Function 0x70a08231
                        Function 0x70a08231
                        Returned
                Contract (CALL) using code and storage at created contract (index 3), message.sender is tx.from
                        Function 0xa9059cbb
                        Function 0xa9059cbb
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Returned
                Returned. Created contract (index 3) has address 0xcca843a73558b87ea92c288cbbcdaf0323a49033
        Deploy contract (CREATE)
                Contract (CALL) using code and storage at created contract (index 4), message.sender is tx.from
                        Function 0x84bc8c48
                        Function 0x84bc8c48
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Stopped
                Contract (STATICCALL) using code and storage at created contract (index 4), message.sender is tx.from
                        Function 0x70a08231
                        Function 0x70a08231
                        Function 0x70a08231
                        Returned
                Contract (CALL) using code and storage at created contract (index 4), message.sender is tx.from
                        Function 0xa9059cbb
                        Function 0xa9059cbb
                        Log3 created (0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef)
                        Returned
                Returned. Created contract (index 4) has address 0xe135896367ca4140789ce18145e24e945f682466
        Transaction finished (STOP)
Transaction 0 complete. Transaction summary, gas used: 0x4ec91, output: 0x
```

### Example: Multiple ether sends via CALL
Transaction (index 95) in block 17190873.

Trace not shown (see above for example).

Interpretation
```
Function 0x1a1da075
Function 0x1a1da075
Function 0x1a1da075
0.003 ether paid to 0xfb48076ec5726fe0865e7c91ef0e4077a5040c7a (CALL to codeless account) from tx.from
0.006 ether paid to 0x2d9258a8eae7753b1990846de39b740bc04f25a1 (CALL to codeless account) from tx.from
0.013 ether paid to 0xa5730f3b442024d66c2ca7f6cc37e696edba9663 (CALL to codeless account) from tx.from
0.013 ether paid to 0xb47ece059072c144d3ac84d041d390be02f57478 (CALL to codeless account) from tx.from
0.018 ether paid to 0xaf94dd6de9b0d68e6dbf7eb43060885db218d9f4 (CALL to codeless account) from tx.from
0.023 ether paid to 0xde4fd23d4c0bb543799fc1aebf02044166be1e45 (CALL to codeless account) from tx.from
0.026 ether paid to 0xbd5678481143b4f757d240deef122a954f480a05 (CALL to codeless account) from tx.from
0.031 ether paid to 0x5be8bdc96c423f265fc589ff8611e4c72ee94dca (CALL to codeless account) from tx.from
0.032 ether paid to 0x13839ef097d42dab0a15164f13af6774748b7682 (CALL to codeless account) from tx.from
0.053 ether paid to 0xc96e4ea42a5ccacc75a2f10a6bacdf4d93401486 (CALL to codeless account) from tx.from
0.099 ether paid to 0xf9471a1af8836373208ebb96cdb2f14091b61c57 (CALL to codeless account) from tx.from
0.12 ether paid to 0x86e5781d43334b5dc892ca1c35ad15b82dc2df3b (CALL to codeless account) from tx.from
0.12 ether paid to 0x83988265eb9dfac380575fb2c37f72422aac3df6 (CALL to codeless account) from tx.from
0.15 ether paid to 0x5d516888c067e6176d148357bf5adffef263e262 (CALL to codeless account) from tx.from
0.25 ether paid to 0x4103532d8f262218db143fc2747e836c6044fa22 (CALL to codeless account) from tx.from
0.43 ether paid to 0xa36f06fc5a28768ebe9715c787122995d80dec0 (CALL to codeless account) from tx.from
0.58 ether paid to 0xd9e1d0ff2a71891f22b638015921d61ef0fcce41 (CALL to codeless account) from tx.from
0.59 ether paid to 0x13a161e0742f601a16b765abb510149e4b5a3d77 (CALL to codeless account) from tx.from
0.65 ether paid to 0xcc54441169904c7330660bf07770c6e66bbaff4f (CALL to codeless account) from tx.from
0.83 ether paid to 0xa158b6bed1c4bc657568b2e5136328a3638a71dd (CALL to codeless account) from tx.from
1.2 ether paid to 0x30a4639850b3ddeaaca4f06280aa751682f11382 (CALL to codeless account) from tx.from
1.5 ether paid to 0x68388d48b5baf99755ea9c685f15b0528edf90b6 (CALL to codeless account) from tx.from
Transaction finished (STOP)
Transaction 0 complete. Transaction summary, gas used: 0x1aa70e, output: 0x
```

## Trace naming differences
One must be aware of the difference between the fields in different tracing kinds:

`debug_traceBlockByNumber`
```
{"pc":25,"op":"JUMPI","gas":630770,"gasCost":10,"depth":2,"stack":["0x0","0x454"]}
```
EIP-3155 trace:
```
{"pc":133,"op":86,"gas":"0x4ec9a","gasCost":"0x8","memSize":384,"stack":["0x8467be0d","0x43"],"depth":1,"opName":"JUMP"}
```
