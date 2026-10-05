# Golden: TP-Link Tapo DL110 v2

**Firmware under test:** `DL110V2_US_1.0.11_Build_260506_Rel.164323`

**Reference set source:** `reference.json` transcribes the 19 findings rated
CRITICAL in the independent third-party firmware security audit
`~/Documents/Offsec/Opswat/Devices/tplink/findings.txt` (section `# CRITICAL
(19)`, entries F-1 through F-19 of that document, renumbered here as
`REF-1`..`REF-19` in document order to avoid colliding with our own audit's
`F-N` / `G#-F#` finding ids). That document is itself the product of a
multi-cluster review process with its own false-positive and refutation
passes (see its `# Refuted claims` section); it is treated here as the
external ground truth our own audit's recall is measured against, not as a
claim that is itself beyond question.

**Date derived:** 2026-10-05

**Our audit's findings:** read from
`~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db`,
table `cba_findings` (45 rows, primary key format `G<group>-F<n>`, e.g.
`G1-F1`). Note that this primary key is *not* the same as the flat `F-N`
numbering used in that report's own `report.md` prose/summary table — the two
numbering schemes were cross-checked by title and location before any id was
written into `matches.json`.

## matches.json: the adjudication rule

`matches.json` maps a reference finding id to the id of the run finding judged
to be the same underlying defect. **A pair is appended to this file only
after a human has looked at both sides — the reference entry's root cause and
location, and the run finding's root cause and location — and confirmed they
describe the same defect mechanism, not merely a similar symptom or the same
file.** A scorer may *propose* candidate matches (e.g. by shared location
tokens or similar root_cause_key text); a proposal is not a match until a
human adjudicates it and it is added here. This file must never be
auto-populated by a scoring run.

The eight entries currently in `matches.json` were established by a prior
post-mortem review and independently re-confirmed against `audit.db` while
building this golden: each reference id's title/location was checked against
the candidate run finding's title/location in `cba_findings` before the pair
was recorded. See `task-6-report.md` for the per-pair justification and for
two cases where the two reports score the finding at very different
severities despite describing the same mechanism (this is expected and does
not disqualify the match — recall scoring is about root-cause identity, not
severity agreement).

## Adjudication log

### 2026-10-05 — candidates raised by the first scoring run

Running `audit.py bench` against `audit.db` surfaced three candidates by
location overlap. All three were adjudicated by reading both sides in full.

**REF-19 ~ G5-F1 — ACCEPTED, appended to `matches.json`.** Both describe the
Telink TLSR9 TBTP BLE reassembler reached through
`tbtp_handle_characteristic_received`. REF-19 cites `0x2001CA22` and
`0x2001CA2E`; G5-F1 cites `@0x2001CA2C` in the same callback plus the
continuation `memcpy` at `0x2001CD0C`. Both are rated CRITICAL and both
describe unauthenticated remote memory corruption on the lock-controller MCU
caused by unbounded fragment reassembly into a fixed buffer. REF-19 names the
trigger (a 2-byte GATT write underflowing the fragment length); G5-F1 names
the missing bounds check that lets the resulting length run. One defect
described from two vantages — the same relationship REF-17 and G1-F7 have.

**REF-10 ~ G6-F3 — REJECTED.** A false pair produced by the bare
three-character token `tss` in REF-10's `locations` matching
`TssRSASecretKey` / `osal_tss_*`. REF-10 is a degenerate-`strncpy` heap
overflow in `update_bind_token`; G6-F3 is disclosure of the RSA private key
over the debug UART via `ATTPGV`. Different defects.

**REF-10 ~ G6-F4 — REJECTED.** The same bare-`tss` false pair. G6-F4 is
`ATTPSK`/`ATTPSV` overwriting the key store in flash. Different defect.

Two rejections out of three candidates is the mechanism working as designed:
substring overlap on a short token is deliberately permissive, and nothing
reaches `matches.json` without this step.

**Effect on the baseline: recall moves from 8/19 to 9/19 (47.4%).** The
baseline document records the post-adjudication figure.

## rejections.json: the adjudication log, made machine-readable

The two REJECTED pairs above now also live in `rejections.json`, quoting the
same reasons. `bench` loads that file and suppresses those pairs from the
candidate list, so a second scoring run does not charge a second adjudication
for a question a human already answered.

`rejections.json` is **human-written and append-only**, exactly like
`matches.json`, and no scoring run may write to it. Each entry must carry a
`reason`: a rejection without one is indistinguishable from a mistake, and it
silences a candidate permanently. `goldens.load_rejections` refuses the file
if any entry omits `reference_id`, `finding_id` or `reason`.

A rejection suppresses a *candidate*, never a *match*. `matches.json` is
consulted first and wins; a pair that appears in both is still scored as a
match. `tests/test_goldens.py` pins that the two files do not contradict each
other and that every rejected `reference_id` names a real reference entry.

As of the token-based candidate rule (below), neither of these two pairs
would be raised in the first place — the bare three-character token `tss` is
now under the four-character floor. The file is kept anyway: the floor is a
*heuristic* and could be tuned or reverted, whereas the adjudication is a
*fact* about those two pairs that stays true however the heuristic changes.

## Candidate generation: whole tokens of four or more characters

Candidates are now proposed by intersecting `text.location_tokens` of the
reference's `locations` with those of the run finding's `location`, instead of
testing substring containment. Tokens are lowercased, split on everything that
is not `[A-Za-z0-9_]`, and anything shorter than `text.MIN_LOCATION_TOKEN`
(4) is dropped.

This changes which *candidates* are proposed and nothing else. The match path
reads `matches.json` only, so recall cannot move because of it, and did not:
`9/19 (47.4%)` before and after.

Consequences worth naming:

- REF-10's bare `tss` is three characters and is now dropped entirely. It is
  left in `locations` as documentation of the object name the source report
  uses; it no longer proposes anything.
- **Five generic word tokens survive the floor and remain latent.**
  Tokenizing the whole golden for short all-alphabetic tokens yields exactly
  these:

  | Token | Carried by | Comes from |
  |---|---|---|
  | `test` | REF-14 | the literal `"test"` |
  | `link` | REF-14 | `test@tp-link.net`, split on `@`, `-` and `.` |
  | `lock` | REF-16 | `/service/lock`, split on `/` |
  | `service` | REF-12, REF-16 | `/service/passthrough`, `/service/lock` |
  | `wreg` | REF-3 | `AT+WREG`, split on `+` |

  None of them was added by the 2026-10-05 location sweep; all predate it.
  Whole-token matching is what defuses them: `test` no longer pairs with
  every location containing `latest` or `attestation`, and `lock` no longer
  pairs with `unlock`, `lock_status` or `deadbolt_lock_cb`. Each can still
  pair with a finding whose own location tokenizes to exactly that word, so
  if one of these references ever becomes unmatched and starts producing
  noise, these five tokens are the first place to look.

Address strings written as ranges (`0x0E08D9FC-0x0E08D9FE`) tokenize into
their two endpoints, so a range may be stored exactly as the source report
writes it.

### What the tokenizer splits on, and the one asymmetry

`text._TOKEN` is `[A-Za-z0-9_]+`: it treats `_` as a word character but
splits on `-`, `@`, `.`, `/` and `+`. That is why `test@tp-link.net` yields
four tokens and `sub_E08E554` yields one.

The asymmetry has a real cost in the stricter direction, and it is the price
this change pays. A future run citing `sub_E08E554_1`, `tbtp_receive_data_cb`
or `klap_handshake1_handle_v2` shares **no** token with the golden's
`sub_E08E554`, `tbtp_receive_data` or `klap_handshake1_handle`, because the
suffix is joined by `_` rather than separated by a delimiter. The old
substring rule *would* have raised those candidates. This is the intended
trade — the rule that stops `tss` matching `TssRSASecretKey` is the same rule
that stops `sub_E08E554` matching `sub_E08E554_1` — but a reference that goes
unmatched against a run whose tooling renamed symbols with suffixes is a
plausible way for this scorer to under-propose, and that should be checked
before concluding a reference was genuinely missed.

## 2026-10-05 — locations added from the source report

Stage 0 finding #3's second half: several entries omitted addresses their
source entry cites, so a future run citing only an omitted address would
surface as nothing at all. Every one of the 19 `# CRITICAL (19)` entries in
`~/Documents/Offsec/Opswat/Devices/tplink/findings.txt` was re-read and its
**Location.** line diffed against this file's `locations`.

**Scope rule.** The **Location.** line is taken as the entry's canonical
citation set. Addresses that appear only in the `Root cause` / `Data flow` /
`FP-check` prose are deliberately *not* harvested: that prose cites
intermediate instruction addresses, immediates that are not addresses at all
(`0x2002FFFF`, `0xFFFFFFFE`, `0x08000000`), and functions named only as
context — several of which belong to *other* entries in this set (F-13's
prose names `sub_E043184` and `sub_E095544`, which are REF-17's locations).
Classifying those one by one would be guessing, and a wrong location token is
worse than a missing one: it manufactures a candidate that costs a human
adjudication.

67 location strings were added across all 19 entries. Nothing was removed and
`matches.json` was not touched.

| Ref | Added | From |
|---|---|---|
| REF-1 | `0x0C025C46`, `0x0C025C2E-0x0C025C3C`, `0x0C025C28`, `0x0C025C3E-0x0C025C42`, `0x0C025B3A-0x0C025B52` | missing cumulative bound, shared copy block, correct sibling check, accumulator update, loop advance |
| REF-2 | `0x0C023FF6`, `0x0C023FEA` | frame allocation `sub sp,#0x44`; end of the saved-register range |
| REF-3 | `0x0E00A525`, `0x2000B344`, `0x0E0C2CD4` | table handler pointer, AT dispatch table base, `"+WREG"` name string |
| REF-4 | `0x0E0092F8`, `0x0E009728`, `0x0E0099FE`, `0x0E007B58` | the four tokenizer call sites, one per listed caller |
| REF-5 | `0x0E0D0E88`, `0x0E0D0E8C` | rodata name/handler pair for `get_doorlock_records` |
| REF-6 | `0x0E0547B2`, `0x0E054A6C` | end of the missing-guard fall-through; literal-pool word holding `0x2001CBEC` |
| REF-7 | `0x0E069F30`, `0x0E072CFE`, `0x0E072D06`, `0x0E072D0A`, `0x0E072D0C`, `0x0E072D6C`, `0x0E072D70`, `0x0E072CBA` | address form of `sub_E069F30`; the length load / pass / reuse chain and the spilled frame length |
| REF-8 | `0x0E07D9BA`, `0x2001E468` | initial capacity set to 32; the capacity global |
| REF-9 | `sub_E08EC78`, `0x0E08EC78`, `0x0E08EC9C` | the device_key hex encoder and its literal-pool slot |
| REF-10 | `0x0E0EB160`, `0x0E08E555`, `off_E08E72C`, `0x0E0EAFE4`, `off_E08E730`, `0x0E0EAFF4`, `off_E08E748` | rodata name/handler pair, handler pointer, the two field-name pointers and their string literals, the module-context pointer |
| REF-11 | `0x0E08D9FC-0x0E08D9FE`, `0x0E08D9E8-0x0E08D9F8` | record allocation; gate — the two omissions Stage 0 finding #3 names |
| REF-12 | `0x0E08F77C`, `0x0E08F600`, `0x0E08F7E4`, `0x0E0F4D88-0x0E0F4D90` | address forms of the three dispatch stages; the `/service/passthrough` topic-table entry |
| REF-13 | `0x2000BE34`, `0x0E0ECEB4`, `0x0E095B8D` | SRAM route entry — the omission Stage 0 finding #3 names — plus the route path string and the thunk pointer |
| REF-14 | `off_E0948F8`, `off_E094918` | the two literal-pool pointers that select the hardcoded fallbacks |
| REF-15 | `0x0E0CE494`, `0x0E0CF908`, `0x0E0EE2B4`, `0x0E0EE2B8` | the two JSON key literals; the rodata method-registration pair |
| REF-16 | `0x0E0CFBDC`, `0x0E0CE9E4`, `0x0E0F4E84-0x0E0F4E8C`, `0x0E0EC1B4` | the `access_info` / `sa_user_id` key strings; the `/service/lock` dispatch entry; the `setLockStatus` method-table entry |
| REF-17 | `0x0E043470`, `0x0E043268`, `0x0E0437E8` | the two branch targets of the bypass; address form of `sub_E0437E8` |
| REF-18 | `0x2001CBB8-0x2001CBBC`, `0x2001CF28-0x2001CFEC`, `0x2001CF34-0x2001CF48`, `0x2001CFBE-0x2001CFC6`, `0x2001CFF0-0x2001D010`, `0x2003C066` | window-flush trigger, partial-send builder, big-endian offset store, hard-coded length, window slide, wire-length store |
| REF-19 | `0x2001CB28` | end of the first-fragment header-size range already half-present |

### Added with a known collision — REF-3's `0x2000B344`

One addition is not cleanly specific to its entry, and is recorded here
rather than only in the task report.

`0x2000B344` is the SRAM base of the AT dispatch table that holds `"+WREG"`.
F-3's **Location.** line cites it ("table record `0x2000B344`+10*16 =
`0x2000B444`") and its root cause turns on it — the entry's thesis is that
AT+WREG is entry 10 of the 11-entry table at that address. It is a location
of this defect.

It is also **shared registration infrastructure**. The same base is cited in
the source report's `# HIGH (38)` section as one of five AT registration
tables built by `sub_E02365C`, and one run finding in the pinned audit
(`G4-F3`) already cites `AT table @0x2000B344` for an unrelated OTA-signature
defect.

It was added rather than left out because the table *is* the defect's
mechanism, but the collision is real and is named so it is not discovered as
a surprise. **It is inert today**: REF-3 is adjudicated to G6-F1, and
adjudicated references are skipped by candidate generation entirely. If REF-3
ever becomes unmatched, this token will pair it with every AT-table finding.
That may well be correct — such a finding plausibly *is* REF-3 — but if REF-3
starts producing candidate noise, this is the token to remove first.

No other addition in the table above has a known collision; `wreg`,
`service`, `lock` and `link` are discussed under the token rule above and
were all present before this sweep.

### Cited but deliberately left out

Each of these appears on a **Location.** line and was *not* added. The rule is
the one Stage 0 finding #3 states in reverse: a shared symbol pairs unrelated
defects, which is the `tss` failure in address form.

| Not added | Cited by | Why |
|---|---|---|
| `sub_E085F2C` (malloc), `sub_E019D14`, `sub_E08EB78` (calloc), `sub_E0BD070` (strlen), `sub_E0BCFD8` / `0xe0bcfd8` (memcpy), `sub_E0BD080` (memset), `0x2003d6ac` (MCU1 memcpy) | REF-8, REF-10, REF-15, REF-18, REF-19 | Firmware-wide libc-style helpers. Every heap and copy defect in the set calls them, so a token hit means nothing. |
| `sub_E07B94C` / `0x0E07B94C` | REF-8 | Cited as the *safe* sibling that "cannot reach the equivalent state". It is a counterexample to the defect, not a location of it. |
| `sub_E02365C` | REF-3 | The shared AT-registration routine, used by every AT module; the entry gives no detail that narrows it to WREG. |
| `sub_E064204` | REF-14 | The shared SHA-1/compare helper, called at both fallback sites and elsewhere; the entry does not identify it. |
| `0x0E0E8314` | REF-9 | The `"%02X"` format literal. A format string is shared firmware-wide. |
| `0x2001EFB8` | REF-9 | The iot_cloud account-struct base, cited only to express `0x2001F704` as base+`0x74C`. It is shared with REF-15's subsystem, so it is ambiguous as a location for *this* defect. |

### Effect

`bench` re-run after these edits: `recall 9/19 (47.4%)`, `findings 45`, `cost
per matched finding $73.15` — identical to before. The candidate list went
from two pairs to zero: both were the `tss` pairs, removed twice over by the
four-character floor and by `rejections.json`. No addition produced a new
candidate against the pinned run.
