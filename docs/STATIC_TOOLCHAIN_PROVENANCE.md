# STATIC toolchain provenance: discovery is not approval

This procedure is prepared for independent review only. Adding these files does
not authorize publication, GitHub settings changes, a workflow run, or C0 runtime.
No executable versions or digests are approved by this document.

## Evidence and trust boundaries

`OBSERVED_NOT_APPROVED` means that one separately approved discovery workflow
observed three system executables. It does not mean that their bytes are trusted,
that STATIC passed, or that C0/runtime/SQL is authorized. A successful job alone
never approves any measurement. Mock tests provide no hosted-runner evidence.

The workflow has no checkout, external actions, downloads, installation, network
commands, secrets, OIDC, artifacts, cache, or GitHub API writes. Its token has
`permissions: {}`. It emits one allowlisted JSON record after all three tools have
been measured, and only a fixed failure marker on an explicitly rejected input.
GitHub itself creates the run and logs; "read-only" refers to the collector's OS,
repository, package-database, and administrative behavior, not zero platform writes.

Paths are fixed to `/usr/bin/python3`, `/usr/bin/ruby`, `/usr/bin/shellcheck`.
Every symlink hop must stay directly within `/usr/bin`, be root-owned, and resolve
within 40 hops. The final regular executable and its parent directories must be
root-owned without group/world write or special permission bits. Digests refer to
resolved executable bytes, not symlink text. Package ownership must be unique,
installed, and amd64. Missing, malformed, unexpected, or ambiguous input fails.
Versions run in a minimal environment; raw version output is never published.
Before/after digests detect executable changes during version measurement.

The OS, Bash, coreutils, package database, loaded libraries and interpreter modules
remain in the GitHub-hosted runner trust boundary. Three executable hashes do not
attest all dependencies, prevent a compromised host from lying, or eliminate
filesystem races. Root ownership alone is not independent provenance. The JSON
is a measurement log, not a signed GitHub artifact attestation. Runner image fields
are bounded informational values, with `UNAVAILABLE` if absent; verify the actual
image against GitHub's `Set up job` log, not those fields alone.

## External approval of the discovery commit

After a separately authorized PR is merged, an independent reviewer must inspect
the resulting exact main commit, including the final workflow bytes. The merge
commit may differ from the branch SHA. The reviewer must record repository,
workflow path, full commit SHA, reviewer identity and explicit approval.

Only after that review and separate user authorization may an administrator set
repository variable `DISCOVERY_APPROVED_COMMIT_SHA` to that exact 40-character
lowercase hexadecimal main commit SHA. No value is set by this implementation.
This variable approves executing the collector; it does not approve tool hashes.
It must never come from dispatch inputs, the current observed SHA as a fallback,
or a workflow that writes its own approval.

Before measuring, the collector requires both `GITHUB_SHA` and
`github.workflow_sha` to equal this external approval, the expected repository
and workflow-ref path, protected `refs/heads/main`, and GitHub-hosted Ubuntu 24.04
Linux/X64. A changed main or missing approval blocks execution. Branch protection
does not by itself prove an independent human reviewed the change; retain the
separate review record and control administrator access to approval variables.

## Independently authenticate Ubuntu packages

Treat every reported package field as an unverified claim. An independent
reviewer/verifier, outside the discovery job, must:

1. Authenticate the Ubuntu archive signing key from an independently trusted
   Ubuntu archive keyring/fingerprint, not a key supplied by the measured runner.
2. Verify the appropriate signed `InRelease`, or `Release` plus `Release.gpg`,
   for Ubuntu Noble, the exact repository pocket and architecture. Check metadata
   validity/freshness and reject unsigned, expired or untrusted metadata.
3. Verify the SHA-256 of the exact `Packages` index through the signed Release
   metadata, then locate the exact package name, full Debian/Ubuntu version and
   architecture. Never substitute the currently newest package silently.
4. Verify the exact `.deb` SHA-256 against that authenticated index. Plain HTTPS,
   a downloaded checksum, `dpkg-query`, or a package name alone is insufficient.
5. Inspect/extract authenticated package payload bytes in an isolated scratch
   directory without installation, maintainer-script execution or database writes.
   Map the reported resolved executable to its exact archive member and hash it.
   Verify symlink-owner packages too where the logical path belongs to a different
   package. Reject any unexplained local modification or ambiguous mapping.
6. Require equality between independently derived executable digests and the
   observations. Independently establish the reported runtime versions from the
   authenticated package's source/build metadata; package revision strings are
   distinct from the `x.y.z` executable versions consumed by STATIC.

The `.deb` digest authenticates the complete package archive; it is NOT the value
for `STATIC_*_SHA256`. Those variables contain the digest of the resolved executable
inside the authenticated package. Unpacking a `.deb` alone does not authenticate it.
Unavailable historical packages, absent verification tooling, invalid signatures,
or an unresolved runtime-version mapping are blockers, not reasons to guess.
Do not install local Docker/WSL/Podman/VMs or new dependencies to bypass a blocker.

References: [APT trust chain](https://manpages.ubuntu.com/manpages/noble/man8/apt-secure.8.html),
[dpkg-deb limitations](https://manpages.ubuntu.com/manpages/noble/man1/dpkg-deb.1.html),
[runner image lifecycle](https://github.com/actions/runner-images#image-releases).

## Independent approval and evidence retention

An independent reviewer must match the GitHub API run identity, actual workflow
SHA and head SHA, event/ref, attempt and completed job to the preapproved commit.
Compare the `Set up job` image/version and its versioned runner-image release
documentation. Preserve the exact workflow source, run URL/ID/attempt, bounded JSON,
system image evidence, signed metadata, package identity/digests, independently
derived executable digests, verifier results, reviewer identity and approval time
in a separately authorized review archive before GitHub logs expire. Do not upload
raw environments, tokens, application snapshots or unrelated personal data.

Only following successful independent verification and a separate user approval
may an administrator enter these six repository variables:

- `STATIC_PYTHON_VERSION`, `STATIC_PYTHON_SHA256`
- `STATIC_RUBY_VERSION`, `STATIC_RUBY_SHA256`
- `STATIC_SHELLCHECK_VERSION`, `STATIC_SHELLCHECK_SHA256`

There is no automatic export, API update, approval, or downstream dispatch. The
two existing `STATIC_PREFLIGHT_APPROVED_*_SHA` variables separately require approval
of the resulting final main commit; neither should retain the old base SHA after
this change is published. Never approve a workflow file's Git blob ID as a commit.

## One-run procedure: separate execution authorization required

1. Obtain explicit authorization for publication/settings changes and exactly one
   discovery run. Verify final main/review approval, active branch protections,
   C0 `disabled_manually`, globally disabled Actions, expected workflow states and
   the expected run-count baseline. Verify the external discovery SHA variable.
2. With separately authorized administrative changes, temporarily disable STATIC;
   ensure only DISCOVERY is active for this window, C0 remains disabled, and then
   enable global Actions. Abort on any unexpected workflow or changed commit.
3. Dispatch only DISCOVERY on protected main, once. Do not run STATIC or C0.
   If the API result is ambiguous, inspect existing runs; never retry blindly.
4. Independently verify the actual run/attempt/workflow commit and collect evidence.
   One new discovery run is expected; any other run is an unexpected state.
5. Re-disable global Actions, disable DISCOVERY, and restore STATIC to its prior
   `active` state while Actions remain globally disabled. Keep C0 disabled. Perform
   fresh API reads of all states, protections, main and run count. Administrative
   API failures must be reported; do not claim successful isolation without proof.
6. Perform independent package verification and obtain approval outside the job.
   Setting six tool variables or running STATIC requires separate authorization.

## Drift, failure and rollback

`ubuntu-24.04` is not an immutable image version. Weekly updates and rolling image
deployment can change executable bytes while retaining an upstream version string.
The unchanged STATIC binary/version gates must fail closed on mismatch. Do not
automatically refresh hashes, broaden to arbitrary hashes, or skip integrity checks.
Repeat the separately authorized measurement/review/approval procedure for changed
bytes. The next STATIC job may receive a different image and correctly fail again.

On discovery failure, approve no values and authorize no automatic rerun. Retain
the run identity and fixed failure status, re-disable Actions/collector under the
execution authorization, and report exact observed administrative state. If source
repair is needed, independently review the new merged main SHA before replacing
the external discovery approval. A stale approval must not be reused.

Rollback means keeping Actions/collector disabled and withdrawing suspect approvals
through separately authorized administration. Preserve evidence. Restoring an old
hash does not restore an old hosted image. Any source rollback must follow protected
main review; never reset/force-push, touch application worktrees, or weaken guards.
