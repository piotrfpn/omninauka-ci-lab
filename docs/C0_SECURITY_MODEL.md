# P0.3E.3A security addendum — PENDING INDEPENDENT REVIEW

No local Docker/VM/WSL/PostgreSQL is required, discovered, installed or executed.
The production/application boundary and original contracts remain unchanged. The
unconditional runtime denial is preserved; GitHubIO and lint adapters repeat it
before any real IO. Synthetic validators/ports are not an authorization mechanism.
No mock can promote C0 runtime/SQL/cleanup to PASS through the result aggregator.

Independent non-secret GitHub variables pin controller/workflow SHAs; bootstrap
checks actual event/ref/protection and both SHAs before checkout. This only enforces
the reviewed workflow's policy. YAML is selected before shell execution; protection
against malicious replacement requires independently administered repository/default
branch/workflow/dispatch controls. Internal JSON remains null/UNAPPROVED and is not
an external trust root. No remote setting or approval has been changed. Expected
controller/workflow SHAs must never be derived from current checkout or workflow input.

Production secrets, GitHub write scopes, OIDC, deployments, app migrations and seeds
are absent. CLI invocation uses only fresh standalone config. CLI start/status streams
are captured under private RUNNER_TEMP (0700 dirs, 0600 files, umask 077); exceptions
publish fixed codes. Child environment is allowlisted, with a private HOME. Inspection
may contain generated local credentials: raw inspect/CLI stdout is private and never
uploaded. Public output is structured counts/IDs/versions/digests/check codes only.
C0 psql runs inside the verified owned DB, as postgres via fixed Unix socket with
cleared env and no .psqlrc/password prompt; no arbitrary host/DSN or service-role key.

Ownership is not a name or label match. Ledger records native IDs, project, observed
labels, creation/observation evidence, image/network identity and permitted operation.
A dedicated fresh engine namespace is required (no foreign containers/volumes/custom
networks); standard built-in networks are retained. Unknown resources block cleanup
and are never pruned. Docker ordinary local volumes lack immutable native Id; they
remain OWNERSHIP_UNVERIFIED and are not deleted. No hash is passed off as native Id.
No supabase stop wrapper, prune, force/wildcard delete or prefix-based cleanup exists.
Known IDs are re-inspected before stop/remove; graph leftovers stop temp deletion.
Repeated and partial cleanup are modeled; hard timeout remains containment-only.

Source review found CLI 2.108.0 start itself calls label-scoped DockerRemoveAll on
failure, and stop routes through label-scoped pruning. This is not replaced with
blindly trusted stop. A separate CLI-internal-cleanup review flag stays false. Real
images/executor/probe targets are unapproved/null. Real live egress receipt validation
is intentionally unqualified and blocks. These are explicit remaining dependencies,
not runtime successes or reasons to install Docker locally.

ShellCheck is mandatory on GitHub (severity style, explicit scripts/inline bootstrap).
actionlint has a fixed official release/archive hash, safe single-member extraction
and version gate. Missing tool/hash or nonzero lint fails. No unverified installer or
local tool installation. Official checksum is HTTPS/account provenance; actionlint
source commit is unsigned. Actual downloaded binary verification remains future-only.

Review package records instrumented local subprocesses and guard tests. This is an
audited harness boundary, not an OS-wide process-forensics assertion. No local Docker
lookup/execution was used to infer availability. DOCKER_LOCAL_NOT_AVAILABLE is the
user-provided accepted environment condition. Runtime/Auth/RLS/E2E remain NOT_EXECUTED.

---
## Historical P0.3E.2 security model (superseded where noted above)

# C0 security and public evidence model

PENDING INDEPENDENT REVIEW. Runtime BLOCKED. This document separates intended
controls from enforcement that has actually been tested locally.

## Assets, boundaries and attacker capabilities

Protect production Auth/data/configuration; protected application worktrees; approved
source/SQL/test bytes; generated ephemeral local credentials; public CI logs. Treat
controller changes, third-party Actions, npm packages, images, database extensions
and candidate code as potential execution surfaces. A local stack does not by itself
protect production: an arbitrary process with internet and credentials can call it.
No production credentials or data are admitted. No hosted Supabase project is linked.

GitHub token is contents-read and not persisted; no secrets, environments, OIDC,
deployment scopes or release operations exist. No candidate package installation,
application build, functions serve or candidate code execution occurs during C0.
Canonical SQL and later Auth fixtures remain C1 plan only. C0 seed/migration scope
is empty and disabled. Standalone project ID contains only a local run/attempt ID.

The final source verifier checks immutable candidate and direct parent, clean tracked/
staged/unstaged/nonignored-untracked state, exact 17-path committed delta, untouched
original manifest digest, six policy final digests, 12 retained released paths and
16 active SQL raw digests. Historical `utf8-lf` modes allow comparison normalization
only. SQL and retained raw paths are never normalized. Future clean checkout has
EOL conversion disabled **before** materialization. Existing source files stay intact.

Original P0.3B and P0.3D.1 JSON files are byte-for-byte copies of external evidence,
including their historical status labels. User-supplied approval of that state is
separate from those labels. Newly authored controller/source guards and inventory
are **PENDING INDEPENDENT REVIEW**, not self-approved security contracts. C1 SQL
hashes derive from immutable Git blobs at the supplied approved checkpoint, not
from mutable working-tree code. Controller integrity itself must be independently
reviewed; modifying a validator and its expectations together is outside its threat
model. Full SHA inventory supports that review, not an automatic trust grant.

## Supply chain

| Component | Immutable commit |
|---|---|
| actions/checkout | d23441a48e516b6c34aea4fa41551a30e30af803 |
| actions/setup-node | 249970729cb0ef3589644e2896645e5dc5ba9c38 |
| supabase/setup-cli | 45a513f8c64c0bc8e0e3dfe572b5c95be85f6359 |
| installer fallback setup-node | 48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e |
| installer setup-bun | 0c5077e51419868618aeaa5fe8019c62421857d6 |

Public GitHub API commit provenance and verified signatures are captured, not guessed.
Installer action code, Bun version and main TS source are included as read-only
evidence. Bun 1.3.10 plus frozen lockfile form additional supply-chain edges. The npm
CLI and Linux-x64 platform package are both 2.108.0; SRI metadata is captured. That
does not prove the entire transitive tree or image contents benign. Linux installer
execution/package bytes are NOT_TESTED. GitHub Go-release tarball checksums are not
substitutes for npm platform-package integrity. Future execution must observe every
image RepoDigest, image ID, source registry and role, including excluded images
which might still be pulled. A CLI version alone never approves image digests.

## Credential/log/artifact exposure

Raw CLI start/status can print JWT/anon/service-role/DB material. Ordinary raw calls
are absent. Startup adapter is blocked; the future invocation contract is data, not
executed shell. Before enabling startup implement private 0700 RUNNER_TEMP directory,
0600 create-exclusive stdout/stderr captures, `umask 077`, and an allowlisted child
environment. No raw exception/CLI output is relayed to logs. No `set -x`, environment
dump, credentials in GITHUB_OUTPUT, summary, snapshots, mutations or uploads.
Current runtime helpers emit only fixed sanitized codes. Source diagnostics use
counts and SHA/path metadata, not file contents.

C0 SQL reads metadata, not rows of auth.users or storage objects. A future local
psql connection via verified owned DB container Unix socket needs no key extraction.
Do not inspect entire Docker Config.Env or run raw `supabase status`. Later C1 Auth
keys must stay process-local/private; register masking before loggable use, but never
print them. GitHub masking is defense in depth. Do not claim local default keys are
safe for publication: malicious readers may exploit accidental reachability.

There is deliberately no upload action. ARTIFACT_DIR is a separate future sanitized
output destination, never a glob parent of private data. A later artifact uploader
requires an exact filename whitelist, JSON schema/type/size checks and synthetic
credential-canary negative proofs. Metadata/image references may be public; raw
private streams, environment, database data and credentials must not be uploaded.
Public audit distribution must exclude source snapshots (local paths) and private
CLI profile/telemetry scratch. No secret value is read to construct this package.

## Threats not resolved by static checks

* Host/container network enforcement, socket privilege separation and restoration
  are a design, not implemented security. Docker socket grants powerful VM access.
* Action/installer bootstrap has internet by necessity; supply-chain compromise could
  run code. Read-only GitHub scope and absence of credentials limit exposure, but
  do not create comprehensive confinement.
* Runner identity, Docker backend, exact health labels, image versions/owners,
  extension prerequisites and SQL evaluator expectations need real isolated evidence.
* Regex forbidden-command checks detect reviewed accidental mutations, not arbitrary
  malicious Python/Bash or encoded commands. Independent diff review remains required.
* Failure/cancellation restoration and sanitized evidence transport are unimplemented.
  A hosted ephemeral VM is destroyed eventually, but that is not a tested cleanup gate.

All unresolved items block runtime authorization. Hosted Auth/RLS/E2E and production
email/recovery are NOT_TESTED. Managed Identity remains dormant because no candidate
source, configuration, database or Auth account is changed or executed here.
