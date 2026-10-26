# P0.3E.3A preferred network and future proof contract

**EGRESS_NOT_VERIFIED / GITHUB_RUNTIME_NOT_EXECUTED. Windows: no Docker or firewall.**
This is code preparation and mocked metadata validation, not an observed network.

ONE preferred approach: dedicated --internal bridge, run/project labels, discovered
native network ID/IPAM, loopback default host port binding. CLI uses the verified
--network-id option with the unique network NAME (the pinned implementation treats
it as network mode/name); ownership/removal decisions always use the observed native
ID, never name alone. Reject additional network attachments, host mode, privileged
containers, added devices/capabilities and Docker/Podman socket exposure. No hardcoded
eth0, subnet, gateway or container IP. Documentation-range addresses in the SYNTHETIC
fixture are not runtime defaults; the runtime create command sets no subnet/gateway.

Docker documents that internal bridges permit communication to the bridge gateway
and appropriately configured host services. Internal=true is therefore NOT proof of
full egress isolation. DNS forwarding, IPv6, host gateway/proxies and existing/NAT flows
must be tested. Host-published 127.0.0.1 ports may behave differently; do not assume
that access works. Main SQL executor uses owned DB container Unix socket. A separate
same-network executor plan needs a reviewed digest image, read-only root, dropped caps,
non-root user, no socket/privilege/host network/secondary network. The image is null
pending review; no image was guessed or pulled. All traffic-bearing product/probe
processes must run inside the verified executor boundary. Trusted host orchestration
keeps the GitHub control plane; it is not asserted globally internet-isolated.

Future proof requires exact executor/native network identity, one attachment, observed
netns matching container but differing from host, positive controls before isolation,
then numeric IPv4, container IPv4/DNS, DNS policy, IPv6 denial or witnessed disable,
unapproved host-gateway-service denial and network-mode bypass rejection. Local DB,
Auth/API, Mailpit and runner control plane must still work. Validate every expected
probe; classify policy denial vs timeout, DNS failure, dead endpoint/container or
missing positive control. A failing curl, internal flag or hand-written result JSON
never constitutes proof. Actual probe target/endpoint approvals remain null.

The metadata proof assessor is implemented and mock-tested. A real receipt collector
must bind actual commands, route/filter witnesses, namespace observations and phase
transition identities under trusted GitHub IO before its currently blocking verifier
can qualify results. File presence/origin='GITHUB_RUNTIME' alone cannot approve
proof. This live collector/receipt-provenance qualification remains explicit future
work; there is no silent trust of uploaded/private fixture JSON.

CONDITIONAL alternative ONLY after independent review: dedicated bridge plus verified
host/container egress filtering, discovered Docker backend/interfaces/routes and
allowlisted local endpoints. DOCKER-USER alone does not constrain host traffic;
OUTPUT alone does not constrain forwarded traffic. Cover IPv4/IPv6/DNS, NAT/conntrack
and established bootstrap flows. Do not silently replace internal mode with ordinary
bridge networking when startup/localhost checks fail. No firewall commands are
prepared for local execution or applied in this sprint. Review failure as
REQUIRES_GITHUB_RUNTIME_VERIFICATION and retain EGRESS_NOT_VERIFIED.

Phase A downloads only approved Actions, CLI, lint tool and image identities; record
actual image IDs/digests, including excluded images if CLI pulls them. Phase B runs
only inside the constrained test boundary, with no production credentials. Verify
runner control/evidence transport separately. Stop owned services and restore any
reviewed runtime networking before collecting public sanitized results. always()
may be interrupted; VM termination is containment, not successful cleanup evidence.

References: [Docker internal-network semantics](https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal),
[Docker Engine 1.48 schema](https://docs.docker.com/reference/api/engine/version/v1.48.yaml),
[pinned Supabase Docker implementation](https://github.com/supabase/cli/blob/e26d9c86d2e81bce509b444e64d6e55a10314a4b/apps/cli-go/internal/utils/docker.go).

---
## Historical P0.3E.2 design (superseded where noted above)

# Two-phase egress design — NOT IMPLEMENTED / NOT EXECUTED

**EGRESS_UNVERIFIED. C0-21 NOT_EXECUTED.** No firewall/network command is included
or executed in this sprint. There is no env/input bypass of the static runtime gate.

## Phase A: reviewed bootstrap

Before running candidate code or SQL, fetch only the reviewed Actions, exact CLI /
Node / installer packages and reviewed stack images. Resolve exact identities and
record package SRI and image RepoDigests, including any excluded images pulled by
CLI. Required registries/CDNs and GitHub control channels must be inventoried from
actual traffic and reviewed; do not silently treat an arbitrary HTTPS destination as
an allowlist member. This package does not claim that Phase A has enforced egress
restrictions. No production credentials, linked metadata, source snapshots or data
are provided. Resource gate precedes image pulls; service startup remains blocked.

## Phase B: test isolation

Use a dedicated owned Docker bridge with published host ports bound to 127.0.0.1,
and pass its actual ID via the supported CLI `--network-id`. Binding ports limits
inbound exposure; it does **not** block egress. A bridge `--internal` setting alone
does not establish host-process confinement or prove the CLI supports every service.
No hardcoded interface, bridge subnet, container IP or RFC1918-wide allowance.

Future implementation must discover and record route tables, interfaces, actual
bridge CIDRs, IPv6 state, Docker firewall backend (iptables legacy/nft or native
nftables), NAT/forwarding policy and owning namespace/cgroups. Separate candidate
test processes from GitHub runner/control-plane processes using a reviewed network
namespace or equivalent enforceable boundary. Only known local DB/API/Mailpit
ports/addresses may be reached by tests; deny arbitrary host services. Do not grant
test processes Docker socket or privileges to change network mode/firewall. Bootstrap
controller owning that socket is a separate trusted boundary. A public Docker API
listener or host-networked test container is a NO-GO.

Host OUTPUT rules do not cover forwarded container packets. DOCKER-USER, where
available, does not cover host processes; some backends do not use that chain. Design
must cover host OUTPUT and container FORWARD paths, IPv4 and IPv6, DNS UDP/TCP and
alternate resolvers/DoH, loopback/bridge-local allowed traffic, SNAT/DNAT and Docker
published-port rules. Inspect established connections before transition; an early
ESTABLISHED/RELATED accept can preserve unwanted bootstrap egress. Confine or close
those flows without severing the runner control plane. A broad local-subnet rule
must not permit gateway/proxy escape. Reject host network, privileged containers,
alternate bridges, namespace joins and Docker-socket bypasses in the test context.

Preserve trusted runner control/results channels in a separate namespace/context;
do not whitelist GitHub IP ranges for all tests as an escape hatch. No uploads occur
until services/tests have stopped and safe restoration is verified. Capture only
sanitized test diagnostics locally while blocked. Reliable cancellation/timeout
cleanup, policy rollback and proof of original-network restoration need independent
review. If separation cannot be implemented reliably, choose a different disposable
VM isolation design in a separately authorized sprint, not a weaker PASS criterion.

## Future repeatable proof matrix

Choose owner-approved synthetic public IPv4/IPv6 endpoints and DNS names, not real
production endpoints. Assign stable probe IDs; record expected content/status and
both positive/negative exit codes without tokens or personal data.

| Probe | Before policy | After policy | Required evidence |
|---|---|---|---|
| Host test-namespace external IPv4 | Reachable positive control | Denied | Exact destination/port, policy rule/counter, exit/status |
| Same namespace external IPv6 | Reachable or unsupported established | Denied, or IPv6 disabled across host/container boundary | Addresses/routes/sysctl evidence; no silent skipped probe |
| Host external DNS UDP and TCP | Controlled resolution succeeds | Denied under DNS policy | Resolver route and policy counters; distinguish NXDOMAIN |
| Container external IPv4/IPv6/DNS | Same positive controls succeed | Denied on each enabled family | Container namespace/network identity plus policy counter |
| Numeric-IP request | Succeeds without DNS | Denied | Avoid attributing DNS failure to transport isolation |
| Bootstrap-established connection | Connected before transition | Cannot carry test traffic afterward | Namespace separation or reviewed flow revocation |
| Network-mode/socket escape | Capability/context reviewed | Rejected before launch | No host mode, alternate bridge, privileged or Docker socket |
| Local PostgreSQL | Local connection succeeds | Still succeeds | Owned DB, Unix socket or exact loopback port |
| Local Auth/API | Local health responds | Still responds | Exact loopback endpoint/status, no credentials in response log |
| Local Mailpit | Local health responds | Still responds | Exact loopback endpoint/status; no email body dump |
| GitHub control/evidence transport | Healthy | Retained in separate trusted context | Runner continues, safe artifact publication after restoration |

Run host and container probes independently; correlate denies with enforced policy.
One failed curl, timeout, unavailable endpoint, broken DNS or broken internet cannot
prove isolation. Classify `POLICY_DENIED`, `DNS_UNAVAILABLE`, `REMOTE_UNAVAILABLE`,
`TIMEOUT`, `PROBE_INFRASTRUCTURE_FAILED` separately. A failed positive control makes
the corresponding negative proof invalid, not PASS. If any active path is unproved,
report EGRESS_UNVERIFIED and prevent C1. All rows here remain NOT_EXECUTED.
