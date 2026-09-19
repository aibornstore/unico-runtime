# U30 execution-contract reconciliation — 2026-09-20

**Scope:** evidence/contract integrity only.  
**Runtime behavior changed:** no.  
**Historical evidence mutated:** no.  
**Audit base:** `master` at merge commit `eb9a09d095f81b9a8f5e5e52fa3078c4cc53d147`.

## 1. Fail-closed finding

The current U30 release evidence is internally inconsistent and MUST NOT be used as release-grade proof until it is re-bound to a single canonical execution contract and source identity.

This finding does **not** assert that the runtime implementation is broken. It asserts that the evidence currently overstates what is independently bound and reviewable.

## 2. Observed contradictions

### 2.1 Contract status conflicts with release status

`SPEC_U30_EXECUTION_CONTRACT.md` currently declares:

- gate: `U30-EXECUTION-CONTRACT-0001`
- top-level status: `IN_PROGRESS`
- document status: `IN REVIEW`

At the same time, `U30_RELEASE_0001.json` declares the execution-contract gate `100%` / `PASS`.

Until a single accepted contract revision is frozen, the release record cannot treat that gate as final.

### 2.2 Runtime evidence is bound to a documentation commit

`U30_RUNTIME_0001.json` declares:

- `implementation_commit: e6a0cc8`
- `status: PASS`

But commit `e6a0cc85897cb86e1ea4fe6089f6f1bdc143492d` is the documentation commit that adds `SPEC_U30_EXECUTION_CONTRACT.md`. It is not a uniquely identifying runtime implementation commit.

Therefore the runtime PASS receipt is not cryptographically/source-bound to the runtime it claims to validate.

### 2.3 Release evidence is bound to another evidence/documentation commit

`U30_RELEASE_0001.json` declares:

- `implementation_commit: b1d76d4`

Commit `b1d76d4000a3840fb12cd2526fb34a75c75e12e0` adds `U30_APP_PERF_PORTABILITY_0001.json`; it is not a canonical source-code implementation identity.

A release receipt must bind the exact source tree/commit that was executed, not a later evidence-only commit.

### 2.4 Referenced parent evidence is absent from current master root

`U30_RELEASE_0001.json` references:

- `U30_BASELINE_0001.json`
- `U30_EXECUTION_CONTRACT_0001.json`

These referenced evidence files are not present at the current `master` root.

A release manifest cannot be considered self-contained while mandatory parent evidence named by the manifest is absent from the release tree.

### 2.5 Physical readback is still explicitly pending

The same release JSON contains:

- `physical_readback.status: PENDING_REVIEW`
- blocker: `00 promotion and physical readback`
- blocker state: `AWAITING_SUPERVISOR`

This is incompatible with treating the release as globally promoted/final.

### 2.6 Evidence timestamps are future-dated relative to this audit

Multiple U30 evidence documents use validator/document date `2026-10-11`.

This audit is performed on `2026-09-20`. Future-dated validation metadata cannot establish that validation occurred before this audit cutoff.

The original files remain unchanged for provenance; replacement receipts must use factual observation timestamps.

## 3. Canonical execution-trace identity to freeze

The outstanding execution-contract gate requires one representation for semantic operations/effects and exactly one digest identity. The following is the proposed canonical v1 contract.

### 3.1 Trace envelope

Canonical trace bytes are UTF-8 bytes produced from this typed structure:

```json
{"schema":"unico-semantic-trace/v1","events":[]}
```

Rules:

1. Serialize a typed struct, never an unordered map.
2. Field order is fixed by the schema and Rust struct declaration.
3. Use compact JSON; no whitespace and no trailing newline.
4. Event fields are ordered: `seq`, `operation`, `effects`.
5. Effect fields are ordered: `kind`, `target`, `value`.
6. `seq` is an unsigned decimal integer starting at 0.
7. Operation names are canonical IR names, not debug/display strings.
8. Integer values use typed fixed-width lowercase hexadecimal payloads.
9. Floating-point values use IEEE bit-pattern hexadecimal, never locale/decimal formatting.
10. Byte strings use lowercase hexadecimal.
11. No timestamps, wall-clock durations, addresses, or nondeterministic metadata occur inside trace bytes.
12. Digest is lowercase SHA-256 hex of the exact trace bytes.

### 3.2 Exact pre-execution Reject identity

A Reject that occurs before the first semantic operation MUST have an empty trace.

Exact bytes:

```text
{"schema":"unico-semantic-trace/v1","events":[]}
```

Byte length: `48`

SHA-256:

```text
7237ae5f82a2081a557c32e809b15f07a7a01537f77941b9ec2deb96b05830bd
```

There is no alternate empty-trace encoding, compressed representation, omitted-trace identity, or digest of an empty byte string.

### 3.3 Receipt identity

A v2 execution receipt must bind at minimum:

```text
receipt_schema
module_sha256
runtime_commit
contract_sha256
trace_schema
trace_sha256
result_status
result_digest
```

The trace digest is authoritative for semantic execution identity. Any compressed trace is storage/transport only and MUST decompress to the canonical trace bytes before verification. Compression bytes never define receipt identity.

## 4. Required remediation gates

The U30 execution-contract blocker is closed only when all of these are true:

1. **Contract freeze** — one accepted `SPEC_U30_EXECUTION_CONTRACT.md` revision is marked FROZEN and its SHA-256 is recorded.
2. **Implementation binding** — runtime/test receipts name the exact source commit that contains the executed implementation.
3. **Parent-evidence closure** — every evidence file referenced by the release manifest exists in the canonical tree or the manifest is replaced by a self-contained successor.
4. **Trace conformance tests** — tests cover:
   - empty pre-execution Reject trace;
   - deterministic repeated execution;
   - integer/floating/bytes canonical value encodings;
   - operation/effect ordering;
   - compression-independent receipt identity;
   - digest changes on any semantic effect change.
5. **Fresh runtime verification** — build/test is rerun against the bound implementation commit after the contract is frozen.
6. **Fresh receipt** — verifier timestamp is factual and not future-dated.
7. **Independent readback** — promotion/physical-readback status is no longer pending.

Until all seven pass, the correct state is **U30 EXECUTION CONTRACT OPEN / RELEASE NO-GO**.

## 5. Migration policy

Do not delete or rewrite `U30_RUNTIME_0001.json`, `U30_RELEASE_0001.json`, or the existing spec. They are historical evidence.

Produce successor artifacts (for example `U30_EXECUTION_CONTRACT_0002.json`, `U30_RUNTIME_0002.json`, `U30_RELEASE_0002.json`) that reference this reconciliation and bind a factual source commit.

## 6. Reusable rule

Evidence files are not implementation identities.

A valid promotion chain is:

```text
frozen contract hash
  -> exact source commit
  -> reproducible build/test receipt
  -> canonical semantic trace digest
  -> release manifest
  -> independent readback
```

If any link points to a documentation/evidence-only commit, an absent parent artifact, a future timestamp, or a pending authority decision, promotion fails closed.
