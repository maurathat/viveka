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

## Use

```sh
cargo install --path .

viveka keygen my.key                 # prints the public key
viveka init    -s store -c my-market -k my.key -b genesis.json
viveka add     -s store -c my-market -k my.key -t problem  -b problem.json
viveka add     -s store -c my-market -k my.key -t proposal -b proposal.json
viveka pending -s store -c my-market
viveka add     -s store -c my-market -k my.key -t decision -b decision.json
viveka rules   -s store -c my-market --at 12   # approved values in force at round 12
viveka verify  -s store -c my-market
```

Each body file holds the kind's fields from `SPEC.md` section 4; `-b -`
reads it from standard input, so a program in any language can write
records by calling the tool. `add` prints the new record's address and
refuses, changing nothing, any record that breaks a rule. Rust programs can
use the crate directly (`viveka::Chain`).

A key file holds a secret. Keep it out of version control.

[`VERIFICATION.md`](VERIFICATION.md) lists the tests and the defects planted
to show each can fail.

Status: draft. Built for Kappa Exchange and for NANDA-based simulations;
usable by any system that learns from its own outcomes.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
