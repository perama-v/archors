# archors-verify

For verification of EIP-1186 proofs.

## Why

When a proof is received, one must verify it. This crate does that.

When a proof fails verification, pointing to the cause is useful. It does that
too. That way, if you are verifying a pile of proofs, it will point to the
accoount, storage, proof element and reason for the failure.

## Architecture

Designed to be readable in order to communicate how these proofs work.
Special care is made for the error variants, which hopefully explain what
behaviour is normal in the proving process.

Seeks to explain:
- What proofs does an EIP-1186 proof contain?
- What does a single proof contain?
- What is a path and how is it followed?
- What are branches, extension and leaves?
- What are exclusion and inclusion proofs?
