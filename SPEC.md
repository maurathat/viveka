# Viveka record format, version 1 (draft)

Viveka is a signed memory of what a system tried and what happened, and of
the rule changes a person approved because of it. This document is the
format's single source of truth. Any implementation, in any language, that
produces the same bytes and addresses for the same records conforms; the
Rust crate in this repository is one implementation.

Status: draft. Nothing here is frozen until version 1 is tagged.

## 1. Words used here

- **Chain**: one system's memory, such as one market or one simulation. A
  chain is an ordered list of records; each record names the one before it.
- **Record**: one JSON object of one of the kinds in section 4.
- **Address**: a record's `blake3:<64 lowercase hex>` label, computed by
  `uor-addr`'s JSON realization (RFC 8785 canonical JSON, then BLAKE3) over
  the record's bytes. The same record has the same address in every
  language `uor-addr` supports.
- **Writer**: a key allowed to add records to a chain.
- **Approver**: a key allowed to approve or reject proposals on a chain.

## 2. Encoding

A record is a JSON object. Before it is addressed it must pass these input
rules, which follow the admission rules of the `uor-jcs-nfc` profile so that
a later move to that profile does not change what any record means:

1. Numbers are whole numbers only, from -(2^53 - 1) to 2^53 - 1. A share or
   rate is written in parts per thousand (`permille`) or per million.
2. Every string, member names included, is in Unicode NFC form.
3. No two members of one object have the same name, before or after NFC.
4. No `null` except where a field below says it may be `null`.

A record that breaks any rule is refused, never repaired.

## 3. The envelope

Every record has these members:

| Member | Type | Meaning |
| --- | --- | --- |
| `viveka` | integer | Format version: `1` |
| `kind` | string | One of the kinds in section 4 |
| `chain` | string | The chain's name, from 1 to 64 characters of `a-z`, `0-9` and `-` |
| `seq` | integer | Position in the chain: 0 for the genesis record, then each record one more than its parent |
| `parent` | string or null | The parent record's address; `null` only for the genesis record |
| `author` | string | The writer's Ed25519 public key, `ed25519:<64 lowercase hex>` |
| `time` | integer | Seconds since the Unix epoch, as the author's clock read it |
| `nonce` | string | 32 lowercase hex characters (128 random bits), fresh for every record |
| `body` | object | The kind's own fields (section 4) |

The nonce makes every address unguessable from the record's contents alone,
so publishing an address reveals nothing about what the record says.

A **signed record** is stored and sent as:

```json
{ "record": { ... }, "sig": "<128 lowercase hex>" }
```

`sig` is the Ed25519 signature, by the key named in `author`, over the 71
ASCII bytes of the record's address. The address is computed over the
`record` object alone, never over `sig`.

## 4. Kinds

### 4.1 `genesis` (seq 0)

Starts a chain and says who may write to it and who may approve.

| Body member | Type | Meaning |
| --- | --- | --- |
| `writers` | array of keys | Keys that may add records; must include `author` |
| `approvers` | array of keys | Keys whose decisions count |
| `quorum` | integer | How many approvers must approve a proposal, at least 1 |
| `scope` | array of strings | Names of the parameters proposals on this chain may change; anything not listed is off limits |
| `purpose` | string | One line on what the chain remembers |

### 4.2 `problem`

A recurring problem worth learning about, for example "new stalls far under
market price".

| Body member | Type | Meaning |
| --- | --- | --- |
| `title` | string | The problem in a few words |
| `measures` | array of strings | The names of the measures an outcome reports for it, for example `caught`, `escaped`, `false_alarms`, `human_decisions`, `profit` |

### 4.3 `proposal`

A rule change suggested from the memory. A proposal changes nothing by
itself.

| Body member | Type | Meaning |
| --- | --- | --- |
| `problem` | address | The problem it answers |
| `evidence` | array of addresses | Records that motivated it; each must be in this chain |
| `change` | object | Parameter names (each in the genesis `scope`) to their proposed integer values |
| `predicted` | object | For each measure, the predicted value after the change |
| `why` | string | One or two sentences |

### 4.4 `decision`

An approver's answer to a proposal.

| Body member | Type | Meaning |
| --- | --- | --- |
| `proposal` | address | The proposal decided |
| `verdict` | string | `approve` or `reject` |
| `effective` | integer or null | For an approval, the round or epoch from which the change applies; never earlier than the next round or epoch after the decision |
| `why` | string | One sentence |

The `author` of a decision must be one of the genesis `approvers`.

### 4.5 `attempt`

A run under some rules, recorded before it starts so the prediction cannot
be written after the fact.

| Body member | Type | Meaning |
| --- | --- | --- |
| `problem` | address | The problem it bears on |
| `decision` | address or null | The approval whose change it runs under, or `null` for the rules as they stood |
| `rules` | object | Every parameter in the genesis `scope` and its value for this run |
| `runner` | object | What produced the behaviour (section 5) |
| `predicted` | object | For each measure, the predicted value |

### 4.6 `outcome`

What happened in an attempt.

| Body member | Type | Meaning |
| --- | --- | --- |
| `attempt` | address | The attempt observed |
| `observed` | object | For each measure named by the problem, its observed integer value |
| `runs` | integer | How many runs the values cover, at least 1 |
| `spread` | object | For each measure, the range across runs as `[low, high]`; `{}` when `runs` is 1 |
| `artifacts` | array of addresses | Optional: addresses of logs, exports or results the outcome was read from |

Failed attempts and their outcomes stay in the chain. They are never
removed.

## 5. Who produced the behaviour: `runner`

An outcome means something only together with what produced it. When a
live model takes part, its behaviour can change without any rule changing:
the provider updates the model, sampling varies, a prompt is edited. So
every attempt names its runner, and comparisons are made only between
attempts with the same runner unless the runner is the thing being tested.

| Runner member | Type | Meaning |
| --- | --- | --- |
| `kind` | string | `scripted`, `model` or `human` |
| `name` | string | The program, model or role, for example `dharma-monitor`, `claude-opus-5-5` |
| `version` | string | The program's commit, or the model's dated identifier as the provider names it |
| `weights` | address or null | For a model whose weights are held locally: the address of the weights file by `uor-addr`'s model-file realization (GGUF or ONNX); `null` for a hosted model |
| `params` | object | Sampling settings that bear on behaviour, for example `temperature_permille`, `seed` |
| `prompt` | address or null | The address of the prompt template, if any |

A hosted model's dated identifier says what was asked for, not what ran: a
provider can serve a model under the same identifier after changing it. A
local model pinned by `weights` says which file was loaded, not that it was
the file that answered. Neither is proof of execution; a signed inference
receipt would be, and is outside this version.

## 6. Verifying a chain

An implementation verifying a chain checks, for every record in order, and
refuses the chain at the first failure, naming the record and the rule:

- **V1** The record passes the input rules of section 2 and the envelope of
  section 3.
- **V2** Its address, recomputed, equals the address it is stored under.
- **V3** `sig` is a valid Ed25519 signature by `author` over the address.
- **V4** Record 0 is a `genesis` with `parent` `null`; every other record
  has `seq` one more than its parent's and `parent` the parent's address.
- **V5** `author` is one of the genesis `writers`; for a `decision`, one of
  the `approvers`.
- **V6** Every address a body names is an earlier record of this chain, of
  the kind its field requires.
- **V7** A proposal changes only parameters in the genesis `scope`.
- **V8** An attempt that names a decision names an approval whose proposal
  has reached `quorum` approvals, and runs the proposal's `change`.
- **V9** An outcome names an attempt and reports every measure its problem
  names.

A proposal is **approved** once `quorum` distinct approvers have approved it
and no approver has rejected it before that.

## 7. Storing a chain

Any store that returns the exact bytes for an address will do, because
verification never trusts the store. Version 1 defines one layout, a
folder:

```text
<root>/<chain>/records/<64 hex>.json   one signed record, named by its address
<root>/<chain>/HEAD                    the address of the newest record
```

Files are written whole to a temporary name and renamed into place, so a
reader never sees half a record. Other stores (an object store, a cloud
bucket) keep the same bytes under the same addresses.

## 8. Privacy

- A chain's records can stay wholly private. To prove later that the
  history was not rewritten, a system may publish only the address of the
  newest record (for example inside a signed epoch root); the nonce makes
  that address reveal nothing.
- A record copied to a store its owner does not control should be
  encrypted first, and stored under the address of the encrypted bytes,
  never the plain address.
- The format adds no encryption of its own in version 1.
