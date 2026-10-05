# Findings from Stage 0 that belong to later stages

Recorded 2026-10-05, at the end of Stage 0. These came out of building and
reviewing the measurement harness, not from the design work that preceded it.
They are not Stage 0 scope; they are inputs to the stages that follow.

## 1. Severity under-rating is a distinct defect class the design does not name

The spec's quality analysis (§1.3) is built around surfaces the audit never
opened. Building the golden set surfaced a second, different failure: of the
nine reference CRITICALs our audit *did* find, **four were rated below the
reference**.

| Reference | Our finding | Our rating |
|---|---|---|
| REF-12 dispatcher missing authorization | G1-F4 | MEDIUM |
| REF-14 hardcoded fallback credentials | G1-F2 | HIGH |
| REF-16 `setLockStatus` missing access-info auth | G3-F4 | HIGH |
| REF-17 KLAP handshake-1 auth bypass | G1-F7 | **LOW** |

REF-17 is the sharpest. We found a pre-authentication authentication bypass
and filed it LOW, because we scored the check-after-copy overrun on its own
and never traced it to the authentication gate it overwrites — even though
our own finding names the consumer branch (`klap_handshake1_handle@0x0E043264`).

So recall understates the problem. Half the findings we made were
under-rated, and one of them was a critical bypass filed as a low-severity
overflow. A finding's severity is a claim about reachability and consequence,
and nothing in the pipeline re-derives it after the chain is understood.

**Implication:** `bench` should score severity agreement alongside recall, and
the audit pipeline needs a step that re-rates findings once reachability and
chain composition are known, rather than fixing severity at discovery time.

## 2. The scorer has no memory of rejected candidates

`matches.json` records adjudicated matches. Nothing records adjudicated
*rejections*. The two false REF-10 pairs (produced by a bare three-character
`tss` token) will resurface on every future run and demand re-adjudication,
and the cost grows with every target added to the golden set.

**Implication:** a `rejections.json` beside `matches.json`, consulted by
`score()` when generating candidates.

## 3. Golden location tokens are simultaneously too sparse and too coarse

Candidate generation is case-insensitive substring containment over a
reference entry's `locations`. Two problems observed in the shipped golden:

- **Too sparse.** Several entries omit addresses their source report cites
  (REF-11 omits `0x0E08D9FC-0x0E08D9FE` and `0x0E08D9E8-0x0E08D9F8`; REF-13
  omits SRAM `0x2000BE34`). A future run finding that cites only an omitted
  address will not surface as a candidate at all.
- **Too coarse.** REF-10 carries the bare token `tss`; REF-14 carries the bare
  token `test`, which is strictly worse and currently masked only because
  REF-14 is already adjudicated. If it ever becomes unmatched it will pair
  against every finding whose location contains `test`, `latest`,
  `attestation`, and so on.

**Implication:** a minimum token length for containment matching (or exact
matching for short tokens), plus a pass over the golden to add every cited
address. Worth doing before the Stage 4 gate, which is scored against this
data.

## 4. A measurement tool needs an external cross-check, not just a pinned input

Stage 0 pinned each transcript's byte length and SHA-256 so a baseline could
not drift under a growing file. That proved the *input* was stable while the
*interpretation* was 2.33x and 7.8x wrong — the hash was correct and
reproducible, and the numbers derived from it were not.

What caught it was `modelUsage`, an authoritative model-reported token total
that the parser had been reading and discarding since Task 2. One
reconciliation line would have exposed both defects on the first real run
instead of surviving eight task reviews and reaching a whole-branch review.

**Implication, stated generally:** regenerating a figure from a tool is only
better than computing it by hand if the tool is validated against something
it did not produce. Any later stage that introduces a new measurement must
introduce its external check in the same commit.
