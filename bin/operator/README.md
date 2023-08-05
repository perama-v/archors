## Operator

Takes lines from stdin and makes them trickle down the terminal.

EVM tracing can be sent to stdin, so this can be piped for an aesthetic representation
of real data.

In the example below, revm executes a block producing an EIP3155 trace, which is then
filtered and interpreted. That is then passed to operator to display.

```command
cargo run --release --example 09_use_proof \
    | cargo run --release --example 11_interpret_trace \
    | cargo run --release operator
```
