# Verification

Every rule in `SPEC.md` has a test in `tests/chain.rs` that offers a record
breaking it and checks the refusal names the rule. A test is evidence only
if it can fail, so each rule was also broken in the code on purpose
(a planted defect), the tests run, and the code restored.

Run them with `cargo test`.

| Planted defect | Test that failed |
| --- | --- |
| Input: duplicate member names accepted | `input_rules_of_section_2` |
| Input: fractions accepted | `input_rules_of_section_2` |
| Input: non-NFC text accepted | `input_rules_of_section_2` |
| V2: stored bytes not compared with their address | `v2_bytes_under_the_wrong_address_are_refused` |
| V3: signature not verified | `v3_a_changed_record_or_signature_is_refused` |
| V4: parent link not checked | `v4_a_record_out_of_place_is_refused` |
| V5: anyone may decide | `v5_only_writers_write_and_only_approvers_decide` |
| V6: evidence need not be in the chain | `v6_a_body_names_only_earlier_records_of_the_right_kind` |
| V7: scope not enforced | `v7_a_proposal_stays_inside_the_scope` |
| V8: an unapproved decision may be run | `v8_an_attempt_runs_only_an_approved_change` |
| V8: the same approver counts twice | `v8_an_attempt_runs_only_an_approved_change` |
| V8: a rejection does not end a proposal | `v8_an_attempt_runs_only_an_approved_change` |
| V9: a missing measure is accepted | `v9_an_outcome_reports_every_measure_of_its_problem` |

The first run of the V4 defect was missed: the test only removed a record,
which the position check caught on its own. The test now also offers a
record at the right position with the wrong parent.

Not yet checked: a second implementation. `the_address_is_uor_addrs` pins
one address vector that `uor-addr`'s Python binding documents, but no
Python writer of viveka records exists yet to compare whole records with.
