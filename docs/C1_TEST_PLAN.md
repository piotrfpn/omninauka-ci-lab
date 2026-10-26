# C1 — future application bootstrap/Auth/RLS qualification, PLAN ONLY

Start only after independently reviewed **runtime** C0 PASS, comprehensive egress
proof, and separate explicit owner execution authorization. Static C0 validation
is not sufficient. No C1 command or migration runner is in the workflow. No hosted
project, production credential, data snapshot or real child/parent is involved.

Immutable inventory: `harness/contracts/c1-migrations.json`. Source is approved Git
commit `bdbb31ef00a2d35bd63cce3f6c8c24f401f67fce`. All 16 paths and full raw SHA-256
are recorded. No migration EOL conversion is allowed. Verify all raw bytes and
chronological ordering before any future execution. The 11 earlier `history_anchor`
files are comments marking history, **not executable schema bootstrap**. The first
executable file must be `20261010073638_canonical_baseline.sql`, followed by:

1. `20261010073843_priv02_soft_deleted_session_access.sql`
2. `20261010131220_priv02_session_deletion_barrier.sql`
3. `20261010174000_priv02_legacy_storage_owner.sql`
4. `20261020204341_auth_u13_managed_identity_foundation.sql`

The 42 SQL files in `supabase/migration_archive/legacy_pre_baseline` must **never**
be replayed. History-anchor success is not canonical bootstrap success. Do not
assume PG17 alone guarantees compatibility. C0 must establish required platform
roles/attributes/ownership, `postgres` session, auth/storage relations and RLS,
extensions, `pg_cron` preload/database/schema/owner and Realtime publication metadata.
Canonical baseline expects pgcrypto in `extensions` and pg_cron in `pg_catalog`;
an incompatible existing extension/schema/owner or missing prerequisite is FAIL,
not permission to alter the baseline or privileged grants to get green.

| Domain | Positive control | Negative/concurrency proof |
|---|---|---|
| Canonical bootstrap | Apply exact reviewed sequence to empty isolated app schema | Fail wrong role, PG version, missing prerequisites and altered SQL bytes |
| ACL/default privileges | Expected application role privileges/owners | PUBLIC/anon cannot acquire forbidden rights; future objects inherit reviewed ACL |
| RLS | Own permitted records under actual JWT roles | Anonymous/cross-parent/cross-child access denied; service-role bypass not a user test |
| SECURITY DEFINER | Correct owner, search_path and callers | Unauthorized caller/forged claims/search_path cannot escalate |
| Auth triggers | Real local GoTrue signup produces reviewed state | No metadata role escalation, no confirmation bypass; inspect trigger ownership |
| Parent ownership/preapproval | Synthetic authorized parent links own pending child | Cross-parent binding/preapproval replay, malformed identifiers and races rejected |
| Managed Identity | Foundation is dormant/disabled; NULL auth binding | Public provisioning disabled, unauthorized auth binding/profile insert/upsert fails |
| Uniqueness/concurrency | Reviewed unique/idempotent outcomes | Parallel duplicate requests cannot create extra identity/family binding |
| Deletion/FKs | Synthetic account lifecycle meets reviewed constraints | Deletion cannot leak/cascade unrelated family data; retained sessions denied |
| Failure recovery | Isolated disposable rebuild from same bytes | Partial failure does not silently record success or change migration provenance |
| Retention/reminder | Reviewed pending/expired/deadline transitions | Seven-day boundary, HMAC, cooldown/backoff/idempotency tampering fails |

Later Auth tests must call actual **LOCAL GoTrue API**, capture email exclusively
in local Mailpit, follow local confirmation/recovery links and exercise sessions,
invalid credentials/unconfirmed email, signup, recovery, error mapping and request
concurrency. Mocks or direct INSERT into auth.users do not prove Auth contracts.
Use reserved synthetic addresses/data; never production users. Avoid external SMTP,
OAuth/SMS/webhooks. Keys stay private process-local, with no log/artifact leakage.

Separate future prerequisites: scoped SQL fixtures with rollback/disposable-db
cleanup, local JWT identities, RLS-role test harness, pgTAP availability review,
synthetic Auth fixture lifecycle, expected ownership/ACL assertions and safe failure
rebuild plan. Existing static tests provide expected contracts but not runtime PASS.
Existing `supabase/tests` fixtures must be reviewed for target/privilege assumptions
before execution. No account creation, migration, SQL or RLS E2E was executed here.
