# P0.3E.2R — local security review closure

All new/updated controller hashes: **PENDING INDEPENDENT REVIEW**.
Runtime/workflow execution and release remain **BLOCKED**. Nothing in this revision
authorizes Docker, SQL, Supabase, firewall changes, GitHub writes or production access.
README.md and original P0.3B/P0.3D.1 evidence stay byte-identical.

## Deterministic C0 result assertions

`harness/c0_results.py` is an offline JSONL evaluator; it opens only its explicit
input and the proposed `harness/contracts/c0-assertions.json`. It cannot connect to
a database, invoke Docker/CLI or grant runtime approval. Future collection requires
an owned local container, reviewed SQL bytes, process exit status and strict client
formatting (psql `-X -q -tA`, no command tags, headers or diagnostics in JSONL).
Successful SQL exit alone is insufficient. The offline CLI's process-exit default
does not attest that SQL ran; future executor must supply its observed status.

The input must contain exactly eight JSON objects, one per line, uniquely identified
by C0-09/10/11/12/13/14/15/17. Every field and nested field is mandatory according
to its shape; unknown/duplicate checks or keys, extra fields, null arrays, nonfinite
numbers, non-JSON text, empty/partial results, integer/boolean coercion and oversized
input fail. Missing prerequisites fail with fixed diagnostic codes; raw payloads or
exceptions never appear in public diagnostics. Any unexpected collector/parser
exception is FAIL, not fallback success. Array order is irrelevant except explicit
history identity; duplicates are rejected.

Assertions:

* PG version number is an integer in major 17, minor agrees with version text;
  major_17 and postgres_session are actual true booleans. Both users must be postgres.
* All ten explicit platform roles must exist, with every required attribute represented
  as a JSON boolean. Canonical authenticated no-super/no-bypass and service-role
  bypass invariants are enforced, plus explicit least-privilege/session minima.
  This is a **minimum role contract**, not a guessed exact Docker-image profile:
  unlisted constraints on a role explicitly permit either boolean while preserving
  field presence/type. Role constraints and accepted platform-owner/preload profiles
  need independent review before runtime authorization; observed data cannot rewrite
  these expectations. No claim of unexamined runtime role semantics is made.
* Auth/storage/public/extensions schemas and owners are pinned by the proposal;
  auth.users and storage.objects/buckets must have the expected owners, RLS true,
  forced RLS false. Cron schema presence must agree with installed pg_cron.
* pgcrypto/pg_cron must be available. They may be uninstalled because canonical
  bootstrap creates them later. If installed, schema/owner/version must be compatible
  and consistent with availability metadata. pgtap is optional. No extension is created.
* pg_cron must be preloaded; only explicit proposed library names are accepted,
  and cron.database_name/current database must both equal postgres. Missing/unknown
  preload/configuration fails. No ownership, grants or cron configuration are changed.
* Exactly the proposed supabase_realtime publication, owner, flags and empty table
  set are accepted. This is a proposed empty-platform expectation, not runtime evidence.

C0-17 uses the complete relevant application table inventory: 13 public canonical
tables and two Managed Identity tables. The explicit names are in c0-assertions.json
and SQL VALUES. Static validation checks their equality. They were reviewed against
CREATE TABLE statements in the immutable candidate SQL, without regenerating any
source hashes. Every named relation must be absent; all public tables, partitions,
views, materialized views, foreign tables and sequences must be absent, as must
non-extension public routines and the entire managed_child_private schema. The old
nonexistent public.managed_child_identities shortcut is removed.

History states accepted, all requiring integer zero migration rows:

1. supabase_migrations schema absent, relation absent, no history relations.
2. Schema exists but is empty, relation absent.
3. Schema exists with exactly ordinary table schema_migrations and zero rows.

Any nonzero count, different relation/type, extra history relation or contradictory
metadata fails. The read-only probe uses to_regclass and conditional count via
query_to_xml only for the exact ordinary history table. It avoids parsing a direct
reference to an absent table; absence returns explicit zero. Non-table relations
are not queried and yield null, which fails evaluation. The XPath/count expression
has **not** been validated on PostgreSQL in this sprint. SQL starts BEGIN READ ONLY
and ends ROLLBACK; it is never executed here. Future SQL syntax/platform qualification
remains mandatory. No platform history table is silently ignored as harmless.

An evaluator PASS has scope SQL_PREREQUISITES_ONLY and explicitly emits runtime
NOT_TESTED, cleanup NOT_TESTED and egress NOT_EXECUTED. It is never complete C0 PASS.

## Controller revision trust model

No real controller commit has independent approval yet. The new revision fixture
has approved_revision **null**, approval_state UNAPPROVED. Its comparison gate
fails before Git inspection. The existing unconditional authorize() denial remains;
static AST checks reject removal/replacement, and workflow guards cannot be skipped
or marked continue-on-error. No environment variable or dispatch input approves a SHA.

The current controller checkout still follows dispatch ref, followed immediately
by the new unapproved-revision guard. **This checker is not a root of trust against
a malicious workflow which replaces the checker or skips it.** Self-verification
from an arbitrary dispatch-controlled checkout cannot establish independent approval.
It only prevents silent acceptance in this reviewed workflow. No arbitrary dispatch
ref has been declared approved; every current real revision remains blocked.

Before future CI execution implement this separate prerequisite:

1. Owner/independent reviewer approves an exact full controller commit externally,
   binding the source inventory and workflow bytes. Never derive expected revision
   from the actual checkout, GITHUB_SHA, branch tip or a self-generated manifest.
2. A protected trusted workflow/bootstrap, itself covered by independent approval,
   enforces its approved workflow revision **before** checking out/executing controller
   code. Pin the controller checkout to the externally approved full SHA. Compare
   workflow identity, dispatch/source context, exact checkout HEAD/tree and approved
   inventory against that external record. Protect default branch/workflow edits and
   restrict who can dispatch; arbitrary workflow refs must be rejected by that trusted
   boundary. Repository-contained approval alone is insufficient if the same ref can
   alter both it and the verifier.
3. Record approved/observed revisions and independent approval provenance. Updating
   either approval or bootstrap requires a new review. No branch tip/PR merge ref
   substitution, dynamically trusted hashes or self-approval is acceptable.

The trusted bootstrap/pinned real approval are **NOT IMPLEMENTED / UNAPPROVED**, not
an implied security PASS. Synthetic tests use fictional aaaa… vs bbbb… SHAs only to
prove the pure comparison rejects mismatches; they approve no real revision.

## Cleanup lifecycle

The final review-only cleanup gate is scheduled with always() for success, failure
and cancellation. It still performs no Docker teardown and still fails closed.
The C0-20 runtime status remains NOT_TESTED. The guard running (or returning an
error) is not completed cleanup. A mutation labeling it PASS is rejected.

Before enabling real cleanup: verify resource ownership against trusted per-run
identity/network/container/volume records, reject preexisting/foreign resources,
preserve required sanitized evidence, stop owned services and confirm their absence
and closed listeners, then restore only the approved network changes. Prove behavior
on success, startup failure, test failure and cancellation. No broad prune/delete,
unowned Docker command or automatic disk remediation is introduced here.

Job timeout, runner cancellation or process death may interrupt even always() steps.
Ephemeral hosted VM termination is a separate containment boundary, not evidence of
completed cleanup or restoration. Missing/incomplete evidence must remain
NOT_EXECUTED/INCOMPLETE/FAIL as appropriate; never PASS. A separately reviewed trusted
supervisor/finalizer and bounded cleanup window may be needed. No such operation is
authorized or executed now.

## Reproduce offline

Use existing Python >=3.11, Bash and a genuine installed YAML parser. No tools are
installed. On Linux preinstalled Ruby/Psych can parse YAML; alternatively set
OMNI_YAML_MODULE to an already installed js-yaml module (Windows evidence used the
existing application dependency read-only). Missing parser fails closed. Optional
OMNI_CANDIDATE_DIR points to an existing approved candidate checkout for the source
proof; without it that particular proof is NOT_TESTED, never downloaded automatically.

```
python3 -B -m unittest discover -s harness/tests -p 'test_*.py' -v
python3 -B review/validate-local.py
python3 -B harness/security.py evaluate harness/tests/fixtures/c0-synthetic-pass.jsonl
```

The 10 original static mutation definitions are retained. Fifteen new disposable-copy
mutations cover malformed/missing/false/empty/partial SQL results, migration state,
incomplete app inventory, runtime guard implementation/scheduling, revision mismatch
and fake approval, cleanup scheduling and false cleanup PASS. Each requires its own
actual passing baseline and expected nonzero detection. ShellCheck/actionlint run
only if already installed; otherwise NOT_TESTED. No Docker, SQL or CLI is run.

The sanitized ZIP includes README and all 21 original paths (updated where explicitly
listed), six narrowly added source files, original manifest copies, reproduction
script, selected provenance/help/schema evidence, sanitized test logs and exact diff.
Private profiles, sessions, source snapshots, caches, env files and raw startup/status
logs are excluded by an exact packaging file list. No broad directory upload.

Remaining egress implementation/proofs, Linux CLI/image/resource qualification,
owned-container SQL collection and cancellation-safe teardown are still blockers.
GO is limited to another independent local security review; workflow execution and
release remain NO-GO.
