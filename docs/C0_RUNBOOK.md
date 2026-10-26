# P0.3E.3A v3 — Windows preparation / future GitHub runtime

**No local Docker, Supabase service, PostgreSQL, WSL or VM is needed or permitted.**
Windows preparation uses Python mocks, JSON/YAML/TOML and existing Bash syntax only.
No tool was installed. The earlier runbook below is historical; this section supersedes
its blocked-adapter and checkout/lint descriptions. SQL and parser remain frozen.

Current statuses: DOCKER_LOCAL_NOT_AVAILABLE (expected, accepted),
GITHUB_RUNTIME_NOT_EXECUTED, EGRESS_NOT_VERIFIED, SQL_NOT_EXECUTED,
CLEANUP_NOT_EXECUTED. These are not local development failures.

## Prepared future entry points

Existing Bash wrappers remain unchanged. security.py routes network/start/resources/
C0/cleanup to github_runtime.py and the two lint gates to github_lint.py. Real IO
independently invokes the unchanged unconditional authorize() guard before filesystem,
Docker/CLI lookup, download or subprocess. There is no allow-execution flag or env
bypass. Pure Lab logic accepts mock ports; production uses only the guarded GitHubIO.
It additionally requires GitHub-hosted Ubuntu 24.04 and the exact controller repository.
No real runtime I/O was executed; constructor guards were exercised only to assert denial.

Proposed manual-only workflow sequence: external approval/default-ref bootstrap;
byte-preserving checkout; controller revision comparison; static policy; unconditional
execution denial; mandatory ShellCheck/actionlint; immutable application checkout;
Node 24.13.0 and CLI 2.108.0; empty standalone C0 config; numeric resource preflight;
owned internal bridge; private CLI start; post-start resource check; verified local
SQL; source recheck; always() scoped cleanup/final C0 result. Everything after the
unconditional denial remains unreachable. No workflow was installed or dispatched.

The externally controlled, non-secret repository variables C0_APPROVED_CONTROLLER_SHA
and C0_APPROVED_WORKFLOW_SHA must eventually contain independently approved full SHAs.
They are not workflow inputs. Bootstrap compares actual GitHub/workflow SHAs and
protected refs/heads/main BEFORE checkout, and the checkout ref uses the approved
controller variable. Internal revision fixture remains UNAPPROVED/null. No variables,
repository settings, approval or branch protection were created remotely. GitHub
selects YAML before checks: a malicious replacement workflow can omit them. Protected
default branch, trusted admins, reviewed bootstrap and restricted/default-ref dispatch
are separate prerequisites; code in an arbitrary dispatch ref cannot authenticate itself.

## Future lint gates

ShellCheck must already exist on Ubuntu; missing executable fails. Record version and
binary hash. Severity is style (includes warnings/errors). Check the exact seven Bash
files, reject missing files/symlinks, plus the inline bootstrap as a private syntax file.
No empty glob or skip. actionlint 1.7.7 is fetched ONLY on the authorized future runner
from the official versioned release; archive SHA-256 is
023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757.
Verify before extracting exactly the regular actionlint member (no extractall or
symlink), record version, lint the actual YAML. Official source tag resolves to
03d0035246f3e81f36aed592ffb4bebf33a03106 (unsigned commit; no signature claim).
Checksum provenance is official HTTPS release metadata, not a reproduced build.
Both gates are mandatory and precede Docker/CLI startup. Missing checksum fails
ACTIONLINT_PROVENANCE_BLOCKED. Windows absence is NOT_TESTED_LOCAL, not sprint failure.

## Future runtime and known qualification gates

Dedicated internal bridge, discovered IPAM/interface/backend, loopback host bindings;
no public host-port access assumption. Same-network executor plan requires an externally
reviewed digest-pinned image (currently null), no socket, privilege, host/secondary
network; read-only root, dropped capabilities and bounded resources. C0 SQL uses
owned PostgreSQL container exec and fixed Unix socket, not 127.0.0.1 mapped ports,
remote DSNs or generated credentials. env -i, psql -X -q -w and ON_ERROR_STOP keep
output deterministic and READ ONLY SQL/parser bytes are checked/preserved.

Actual probe receipts must bind executor/network identities, process netns, both
address families/DNS, before-success controls, after-denial witnesses, local DB/API/
Mailpit success and control-plane survival. Timeout/crash/DNS outage is not policy
proof. The metadata assessor is prepared; the real receipt-provenance collector
still fails closed until separately qualified on GitHub. No hand-written private
JSON is accepted as live proof. No real image profile or public probe destination
was invented: those approvals remain null. Startup's CLI-internal error cleanup
is unreviewed for runtime and defaults false, so activation cannot silently proceed.

Numeric preflight requires proposed >=8 GiB before / >=2 GiB after on Docker's actual
data filesystem AND RUNNER_TEMP, >=100000 inodes, >=4 CPU, >=8 GiB available RAM,
local Docker socket, driver/usage metadata. Floors are source policy; no env weakening.
No Android SDK/system-directory deletion. Measurements remain NOT_EXECUTED.

Final C0 aggregation requires separate TRUST/LINT/RESOURCES/NETWORK/POSTGRESQL/
SQL_ASSERTIONS/RUNTIME/CLEANUP PASS receipts from real authorized IO. Any missing,
FAIL, BLOCKED or NOT_TESTED stage blocks final PASS. A synthetic origin always blocks
runtime PASS, even if all modeled stages say PASS. SQL success is intermediate;
cleanup is the final gate. Non-green cleanup/aggregate exits nonzero. Lint receipts
are private and tied to approved controller/workflow SHAs. They are not public logs.

Cleanup removes only re-inspected exact native container/network IDs with creation,
project-label, approved-image and network evidence. Stop does not force/remove volumes.
Unknown objects are retained and prevent PASS. Ordinary local volume API has Name,
not a native immutable Id: record id=null / OWNERSHIP_UNVERIFIED, never substitute a
name/hash or delete by prefix. This means real Supabase volume teardown remains a
separate review blocker, not a claimed successful cleanup. Known-ID cleanup is
idempotent, handles partial startup/nonzero/timeout observations and retains evidence.
Temporary deletion requires the exact owned RUNNER_TEMP child, owner marker, no
symlinks/mount escapes and no remaining/unaccounted resources. All cleanup tests
use mocks only; no local resource or temporary directory was deleted by these routines.

always() covers ordinary success/failure/cancellation scheduling, but not hard runner
termination. Timeout/death may interrupt teardown. VM destruction is containment,
not completed cleanup proof. GitHub runtime remains blocked until independent review,
external revision approval, separate authorization, image/volume/egress qualification.

## Allowed local reproduction

Use existing Python and YAML parser; no Docker/CLI needed. Optional existing Bash is
used with -n only. The existing offline driver preserves all 25 mutation definitions.

    python -B -m unittest discover -s harness/tests -p 'test_*.py' -v
    python -B review/validate-local.py

Set OMNI_YAML_MODULE only to an already installed js-yaml module, or use preinstalled
Ruby/Psych; absence fails YAML parsing closed. OMNI_CANDIDATE_DIR optionally selects
an existing immutable application checkout for read-only source verification. No
automatic checkout/download/installation occurs. No application build/TypeScript or
Auth/RLS/runtime result is claimed for this Python/controller-only work.

---
## Historical P0.3E.2 runbook (superseded where noted above)

# P0.3E.2 — local controller review package

Status: **READY FOR INDEPENDENT REVIEW. EXECUTION BLOCKED.** No remote repository,
workflow installation, commit, push, deployment, container start or SQL execution is
authorized by this package. Production release remains BLOCKED. This controller is
outside all nine protected worktrees and has not been initialized as a Git repository.

## Scope and entry points

The future public repository is `piotrfpn/omninauka-ci-lab`. It is separate from
`piotrfpn/omninauka-mvp`. PR #3 stays Draft and untouched. No application workflow
is added. `workflow_dispatch` must exist on the **controller default branch** to be
dispatchable; changing application main is not a workaround. A future owner must
approve controller publication and a separate runtime authorization. No such operation
was done here. A controller dispatch ref must itself undergo review; GitHub records
its workflow SHA. No arbitrary candidate-ref input is offered.

Prepared workflow: `.github/workflows/isolated-supabase-c0.yml`. Trigger is manual
only; permissions exactly `contents: read`; no environment, secrets, deployments,
OIDC, automatic triggers, cache or artifact-upload action. Public source checkout
requires no application token. Credentials are not persisted. `core.autocrlf=false`
and `core.eol=lf` are configured before checkout; fetch-depth 0 supplies the pinned
parent to freeze tests. No attributes, SQL or fixture content is rewritten.

The workflow **intentionally fails** at `verify-safety.sh authorize`, before the
candidate checkout, CLI installation, config creation and resource queries. The
guard is unconditional and has no dispatch-input/env bypass. Each runtime script
also independently calls it. Removing this guard alone is insufficient: startup,
SQL execution and cleanup have further explicit blocked adapters pending network,
container ownership, prerequisite evaluation and restoration implementation. This
is a complete static review scaffold, not a runnable runtime qualification harness.

## Local static validation

Use Python >=3.11, Bash and a real YAML parser. No dependency installation is needed
or performed. `security.py` uses preinstalled Ruby/Psych on a future Ubuntu runner,
or the explicitly specified existing `js-yaml` module for Windows local validation.
If no genuine parser exists, validation fails closed. Do not use a regex as a YAML parser.

```
bash harness/validate-static.sh
python3 harness/security.py source /absolute/path/to/reviewed-candidate
bash -n harness/prepare-local-config.sh
```

On this Windows audit host `OMNI_YAML_MODULE` selects the already installed
application `node_modules/js-yaml/index.js` read-only. Application dependencies are
not copied, modified or installed. Review evidence records exact commands/exits.
`review/validate-local.py` runs syntax, static mutations, source integrity, and runtime
denial probes without Docker, network, database or application build operations.
ShellCheck/actionlint remain NOT_TESTED if unavailable. Do not treat this custom
validator as a replacement for those tools or a proof of arbitrary-code confinement.

## Tool and schema compatibility

CLI **2.108.0**, Node **24.13.0**, PostgreSQL major **17**, runner **ubuntu-24.04**.
`review/action-provenance.json` records exact commits, signature verification and
URLs. All five main/transitive action commits were read through the public GitHub
API. No tag is used in the workflow. `supabase/setup-cli` v3.0.1 installs the npm
CLI (not the old Go-only release tarball), runs Bun **1.3.10** and a frozen production
lockfile. Its pinned transitive actions are recorded in the security model. npm
metadata/integrities for CLI and Linux-x64 platform package 2.108.0 are recorded in
`review/npm-provenance.json`; packages were **not downloaded or installed** here.
Registry SRI is metadata evidence, not an independently reproduced binary build.
Future execution must verify installed version and platform payload integrity against
this reviewed evidence; installer code alone is not a digest approval of containers.

Windows 2.108.0 `--version` and `start --help` were executed in a separate private
controller-owned profile with a minimal environment. Both exited 0. No start/status
command was executed. See `cli-local-static-evidence.json`, `cli-start-help.txt`.
Linux binary help, actual image identities and service boot: NOT_TESTED.

Actual default legacy start command in this pinned CLI delegates to the Go proxy.
The exact versioned Go template/config types and TS delegation are captured in
`review/cli-config-template.toml`, `cli-config.go.txt`, `cli-start-handler.ts.txt`.
The new experimental stack command has different names; it is not used here.
Correct default-start exclusions: **studio,analytics,vector,imgproxy**. `logflare`
is not a supported default-start alias in observed 2.108.0 help. Do not copy names
from floating documentation. Do not use the health-check override.

Only those four services are proposed for exclusion. Retain db, GoTrue, rest,
storage, kong, local mail capture (the CLI exclusion alias is `inbucket`), realtime,
meta and edge runtime/functions. Additional exclusions await dependency review.
Exclusions do not promise RAM/disk savings; pulls and actual resources must be measured.

All emitted config keys were compared with the versioned template. TOML parse and
canonical equality are static checks; an actual Linux CLI config load remains
NOT_TESTED. The pinned template defaults unspecified external providers/hooks/SMTP
to disabled/unconfigured; fresh config inherits **no application configuration**.
Do not enable `[experimental] stack` or change the command model without re-review.

## Resources

Expected public runner: 4 CPU, 16 GB RAM, 14 GB nominal SSD (not necessarily free
disk). Read current GitHub specifications before execution. Proposed gates: at least
8 GiB available **before pulls**, 2 GiB **after startup**, 100000 available inodes on
both the actual Docker data filesystem and RUNNER_TEMP. Minimum available RAM is
proposed 8 GiB. These are safety thresholds, not measured stack requirements.
Environment overrides may increase but cannot lower floors without policy review.

`resources()` reads numeric statvfs bytes/inodes, CPU, `/proc/meminfo`, local Docker
context, DockerRootDir, driver, and image/volume usage. It rejects a remote daemon.
Unreadable filesystems or Docker failure stop validation. Raw Docker info is never
logged. Resource reports stay local until an allowlisted publication procedure is
reviewed. No numeric threshold is parsed from `df -h`.

Optional remediation is **documentation only**, not code. Prefer a larger runner or
fewer reviewed services. If separately authorized, an ephemeral GitHub-hosted VM
only may remove **one exact target** `/usr/local/lib/android`. Require hosted-VM
identity, explicit enablement, resolved-path equality, no symlinks in any component,
no bind mount/path traversal, and disjointness from RUNNER_TEMP/controller/candidate/
artifacts. Record bytes/inodes before/after and exact removed target. No broad
allowlist, .NET/GHC/CodeQL removal, glob, recursive path construction or developer-PC
cleanup is approved. There is no deletion command or automatic remediation here.

## Future safe runtime sequence — NOT EXECUTED

1. Independent review and explicit owner authorization; implement/qualify missing
   egress, process confinement, image identity, cleanup and SQL-evaluator adapters.
2. Review controller SHA; initialize only the dedicated public controller remotely
   under separately authorized work. Dispatch with contents-read only.
3. Preflight hosted identity; byte-preserving source checkout and exact content
   contracts. Stage Phase A reviewed downloads; measure before each image pull and
   after startup. Record image IDs/RepoDigests for every actual image used/pulled.
4. Create exclusive RUNNER_TEMP workspace and owner marker; verify empty migrations
   and seeds, disabled execution, local redirects, confirmations, Mailpit. Candidate
   checkout must never be the Supabase working directory.
5. Use the approved two-phase network implementation and positive controls described
   in the egress design. Start with private streams, check health without override.
   Transition to Phase B and prove host/container denial with local success.
6. Discover exact owned DB container; execute only `c0-readonly.sql` through a local
   Unix-socket `psql` connection (`docker exec -i`, no DB URL or generated keys).
   JSON values must be evaluated against C0 expectations; mere SQL exit 0 is NOT PASS.
   Fail unmet baseline prerequisites without changing SQL, roles or extensions.
7. Reverify source, stop only owned services, verify no owned leftovers/listeners,
   restore reviewed networking, then publish only sanitized allowlisted evidence.
   Failure/cancellation/timeout cleanup needs qualification before runtime approval.

No C1 application migrations or Auth operations are reachable in this package.
Generated local credentials and raw CLI output remain private, unuploaded; public
diagnostics consist only of check IDs, codes, tool/image identities and approved
metadata. Do not print environment variables or complete inspection output.

References: [GitHub runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[manual workflow dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow),
[Supabase local development](https://supabase.com/docs/guides/local-development).
