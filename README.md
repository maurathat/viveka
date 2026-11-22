# viveka

A signed memory of what a system tried and what happened, and of the rule
changes a person approved because of it.

At scale a person cannot review every transaction. Viveka moves their
attention from cases to rules: the system records each attempt and its
outcome as a signed, content-addressed record, proposes rule changes from
that history, and a person approves or rejects them. Failed attempts stay
in the record, and anyone can check the history without trusting whoever
stored it.

Viveka (Sanskrit: discernment) is the faculty that tells what to keep from
what to let go.

- [`SPEC.md`](SPEC.md): the record format, the single source of truth.
- Records are addressed with [`uor-addr`](https://github.com/UOR-Foundation/uor-addr)
  (canonical JSON, then BLAKE3), so Rust and Python produce the same
  address for the same record.

Status: draft. Built for Kappa Exchange and for NANDA-based simulations;
usable by any system that learns from its own outcomes.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
