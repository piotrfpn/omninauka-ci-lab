# OmniNauka isolated CI lab — P0.3E.2

**LOCAL REVIEW PACKAGE ONLY. EXECUTION / RELEASE BLOCKED.**

No repository has been created remotely; no workflow has been installed or run.
No Docker, SQL, migration, Auth operation, firewall change or deployment was executed.

Start with [the review report](review/REPORT.md), then
[the runbook](docs/C0_RUNBOOK.md), [security model](docs/C0_SECURITY_MODEL.md),
[egress design](docs/C0_EGRESS_DESIGN.md) and [C1 plan](docs/C1_TEST_PLAN.md).

The manual-only workflow has an unconditional execution denial before any runtime
step. This is intentional. Egress enforcement, container ownership discovery, SQL
expectation evaluation and cancellation-safe cleanup require separately authorized
implementation and independent runtime proof. Do not remove the guard to try C0.

Controller files are UTF-8/LF. Original reviewed manifest copies preserve their
exact original bytes. Source checkout SQL is never normalized. `review/` is local
audit evidence, not an automatic public artifact-upload directory. Do not publish
source snapshots or the CLI profile/scratch subdirectories without privacy review.
