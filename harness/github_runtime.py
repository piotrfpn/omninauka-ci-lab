"""Small future GitHub adapter. Pure plans accept mocks; real IO always authorizes.

No Docker/CLI discovery, socket connection or subprocess occurs on import. Windows
does not need Docker. Actual IO remains impossible under the existing hard guard.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
from c0_results import evaluate_jsonl

PROJECT_LABEL = 'com.supabase.cli.project'
RUN_LABEL = 'io.omninauka.c0.run'
SQL_SHA = '2bf4a72e7db6295904ab4a21f465461a56c60e08602ff78abcee7902dd2a7584'
STAGES = ('TRUST','LINT','RESOURCES','NETWORK','POSTGRESQL','SQL_ASSERTIONS','RUNTIME','CLEANUP')
EXPECTED_STAGE_STATUSES = ('DOCKER_LOCAL_NOT_AVAILABLE','GITHUB_RUNTIME_NOT_EXECUTED',
                           'IMAGE_PROFILES_UNAPPROVED','EGRESS_NOT_VERIFIED','SQL_NOT_EXECUTED',
                           'CLEANUP_NOT_EXECUTED','RELEASE_BLOCKED')
BOOTSTRAP = '''set -euo pipefail
umask 077
[[ "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]]
[[ "$GITHUB_REPOSITORY" == "piotrfpn/omninauka-ci-lab" ]]
[[ "$GITHUB_REF" == "refs/heads/main" ]]
[[ "$APPROVED_CONTROLLER_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$APPROVED_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$GITHUB_SHA" == "$APPROVED_CONTROLLER_SHA" ]]
[[ "$EXECUTED_WORKFLOW_SHA" == "$APPROVED_WORKFLOW_SHA" ]]
[[ "$REF_PROTECTED" == "true" ]]
'''


class ReadinessError(ValueError):
    pass


def require(value, code):
    if not value:
        raise ReadinessError(code)


def native_id(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def project_id(run, attempt):
    require(type(run) is str and type(attempt) is str and re.fullmatch(r'[1-9][0-9]{0,14}', run)
            and re.fullmatch(r'[1-9][0-9]{0,14}', attempt), 'RUN_ID_INVALID')
    value = f'omni-c0-{run}-{attempt}'
    require(len(value) <= 40, 'PROJECT_ID_TOO_LONG')
    return value


def trust_revision(observed, anchor):
    require(type(anchor) is dict and anchor.get('origin') == 'INDEPENDENT_ADMIN_APPROVAL', 'TRUST_ANCHOR_MISSING')
    for key in ('controller_sha','workflow_sha'):
        require(type(anchor.get(key)) is str and re.fullmatch('[0-9a-f]{40}', anchor[key]), 'TRUST_ANCHOR_INVALID')
    require(observed.get('repository') == 'piotrfpn/omninauka-ci-lab'
            and observed.get('event') == 'workflow_dispatch' and observed.get('ref') == 'refs/heads/main'
            and observed.get('ref_protected') is True, 'UNTRUSTED_DISPATCH')
    require(observed.get('checkout_sha') == observed.get('github_sha') == anchor['controller_sha']
            and observed.get('workflow_sha') == anchor['workflow_sha'], 'CONTROLLER_REVISION_MISMATCH')
    # This comparison cannot protect a malicious replacement workflow. External
    # repository/dispatcher controls are a separate mandatory trust prerequisite.
    return {'comparison':'PASS','approval_source':'external','runtime':'NOT_EXECUTED'}


def check_network(net, project, identifier=None):
    require(type(net) is dict and native_id(net.get('Id')) and (identifier is None or net['Id'] == identifier), 'NETWORK_ID_INVALID')
    require(net.get('Driver') == 'bridge' and net.get('Internal') is True
            and net.get('EnableIPv6') is False, 'NETWORK_ISOLATION_UNVERIFIED')
    labels = net.get('Labels') or {}
    require(labels.get(PROJECT_LABEL) == project and labels.get(RUN_LABEL) == project, 'NETWORK_OWNER_INVALID')
    require(net.get('Options', {}).get('com.docker.network.bridge.host_binding_ipv4') == '127.0.0.1', 'NETWORK_PUBLISH_UNVERIFIED')
    require(type(net.get('Name')) is str and type(net.get('IPAM',{}).get('Config')) is list
            and bool(net['IPAM']['Config']), 'NETWORK_INSPECT_INCOMPLETE')
    return net['Id']


MANDATORY_ROLES = ('db','auth','rest','storage','kong','inbucket','realtime')
CLI_UPSTREAM = 'e26d9c86d2e81bce509b444e64d6e55a10314a4b'
REST_PATH = '/rest-admin/v1/ready'


def image_digest(value):
    return type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None


def evidence_json(raw):
    require(type(raw) is str and 0 < len(raw.encode('utf-8')) <= 131072, 'IMAGE_EVIDENCE_INVALID')
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, 'IMAGE_EVIDENCE_INVALID')
            obj[key] = value
        return obj
    try:
        obj = json.loads(raw, object_pairs_hook=unique,
                         parse_constant=lambda _: require(False, 'IMAGE_EVIDENCE_INVALID'))
    except (TypeError, ValueError) as error:
        raise ReadinessError('IMAGE_EVIDENCE_INVALID') from error
    require(type(obj) is dict, 'IMAGE_EVIDENCE_INVALID')
    return obj


def text_digest(raw):
    evidence_json(raw)  # Also reject duplicate/nonfinite/malformed evidence.
    return 'sha256:'+hashlib.sha256(raw.encode('utf-8')).hexdigest()


def image_profile(profile, origin='SYNTHETIC'):
    # No real image profile is approved in this offline sprint. This is a mock
    # schema, not an approval authority or a future runtime override.
    require(origin == 'SYNTHETIC' and type(profile) is dict
            and profile.get('origin') == 'SYNTHETIC'
            and profile.get('status') == 'SYNTHETIC_TEST_ONLY'
            and profile.get('cli') == '2.108.0'
            and profile.get('upstream_commit') == CLI_UPSTREAM, 'IMAGE_PROFILE_UNAPPROVED')
    roles = profile.get('roles')
    require(type(roles) is dict and set(MANDATORY_ROLES) <= set(roles)
            and set(roles) <= set(MANDATORY_ROLES + ('executor',)), 'IMAGE_PROFILE_INCOMPLETE')
    for role, row in roles.items():
        require(type(row) is dict and row.get('role') == role
                and type(row.get('create_reference')) is str
                and re.fullmatch(r'[a-z0-9./_-]+:[A-Za-z0-9_.-]+', row['create_reference'])
                and type(row.get('approved_repository_digest')) is str
                and re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', row['approved_repository_digest'])
                and row['create_reference'].rsplit(':',1)[0] == row['approved_repository_digest'].split('@')[0]
                and image_digest(row.get('approved_platform_manifest_digest'))
                and image_digest(row.get('approved_image_id')), 'IMAGE_PROFILE_INVALID')
        platform = row.get('approved_platform')
        require(type(platform) is dict and set(platform) == {'os','architecture'}
                and platform['os'] == 'linux' and platform['architecture'] in ('amd64','arm64'),
                'IMAGE_PLATFORM_UNAPPROVED')
    return roles


def check_image_identity(obj, expected):
    require(obj.get('Image') == expected['approved_image_id'], 'SERVICE_IMAGE_ID_MISMATCH')
    require(obj.get('Config',{}).get('Image') == expected['create_reference'], 'SERVICE_IMAGE_REFERENCE_MISMATCH')
    observed = obj.get('ImageEvidence')
    require(type(observed) is dict and observed.get('Id') == expected['approved_image_id'], 'IMAGE_INSPECT_ID_MISMATCH')
    platform = expected['approved_platform']
    require(observed.get('Os') == platform['os'] and observed.get('Architecture') == platform['architecture'],
            'IMAGE_PLATFORM_MISMATCH')
    digests = observed.get('RepoDigests')
    require(type(digests) is list and expected['approved_repository_digest'] in digests, 'IMAGE_REPOSITORY_DIGEST_MISMATCH')
    config_raw = observed.get('ConfigBytes')
    require(text_digest(config_raw) == expected['approved_image_id'], 'IMAGE_CONFIG_DIGEST_MISMATCH')
    config = evidence_json(config_raw)
    require(all(config.get(k) == v for k,v in platform.items()), 'IMAGE_PLATFORM_MISMATCH')
    manifest_raw = observed.get('ManifestBytes')
    require(text_digest(manifest_raw) == expected['approved_platform_manifest_digest'], 'IMAGE_MANIFEST_DIGEST_MISMATCH')
    manifest = evidence_json(manifest_raw)
    require(type(manifest.get('schemaVersion')) is int and manifest['schemaVersion'] == 2
            and manifest.get('mediaType') in ('application/vnd.oci.image.manifest.v1+json',
                                             'application/vnd.docker.distribution.manifest.v2+json'), 'IMAGE_MANIFEST_INVALID')
    descriptor = manifest.get('config')
    require(type(descriptor) is dict and descriptor.get('digest') == expected['approved_image_id']
            and descriptor.get('mediaType') in ('application/vnd.oci.image.config.v1+json',
                                                'application/vnd.docker.container.image.v1+json')
            and type(descriptor.get('size')) is int and descriptor['size'] == len(config_raw.encode('utf-8')),
            'IMAGE_MANIFEST_CONFIG_MISMATCH')
    require(type(manifest.get('layers')) is list and all(type(x) is dict and image_digest(x.get('digest'))
            and type(x.get('size')) is int and x['size'] >= 0 for x in manifest['layers']), 'IMAGE_MANIFEST_INVALID')
    index_raw = observed.get('RepositoryManifestBytes')
    require(text_digest(index_raw) == expected['approved_repository_digest'].split('@')[1], 'IMAGE_REPOSITORY_MANIFEST_DIGEST_MISMATCH')
    index = evidence_json(index_raw)
    if index.get('mediaType') == manifest['mediaType']:
        # A repository digest can name a single-platform manifest instead of an
        # index. The separately approved identities must still bind exactly.
        require(index_raw == manifest_raw and text_digest(index_raw) == expected['approved_platform_manifest_digest'],
                'IMAGE_PLATFORM_MANIFEST_MISMATCH')
        return
    require(type(index.get('schemaVersion')) is int and index['schemaVersion'] == 2
            and index.get('mediaType') in ('application/vnd.oci.image.index.v1+json',
                                          'application/vnd.docker.distribution.manifest.list.v2+json')
            and type(index.get('manifests')) is list
            and all(type(x) is dict for x in index['manifests']), 'IMAGE_INDEX_INVALID')
    selected = [x for x in index['manifests'] if x.get('platform') == platform]
    require(len(selected) == 1 and selected[0].get('digest') == expected['approved_platform_manifest_digest']
            and selected[0].get('mediaType') == manifest['mediaType']
            and type(selected[0].get('size')) is int and selected[0]['size'] == len(manifest_raw.encode('utf-8')),
            'IMAGE_PLATFORM_MANIFEST_MISMATCH')


def prestart_image_gate(profile, selection, origin='SYNTHETIC'):
    # The pinned CLI cannot enforce our immutable selection through its normal
    # tag/cache/pull interface. No real admission path is implemented or approved.
    require(origin == 'SYNTHETIC', 'IMAGE_PRESTART_TRUST_BLOCKED')
    roles = image_profile(profile, origin)
    require(type(selection) is dict and selection.get('origin') == 'SYNTHETIC'
            and selection.get('phase') == 'BEFORE_CREATE'
            and selection.get('mechanism') == 'SYNTHETIC_IMMUTABLE_SELECTION'
            and type(selection.get('images')) is dict and set(selection['images']) == set(roles),
            'IMAGE_PRESTART_TRUST_BLOCKED')
    for role, expected in roles.items():
        observed = selection['images'][role]
        require(type(observed) is dict, 'IMAGE_PRESTART_TRUST_BLOCKED')
        check_image_identity({'Image':expected['approved_image_id'],
                              'Config':{'Image':expected['create_reference']},'ImageEvidence':observed}, expected)
    return {'validation':'PASS','origin':'SYNTHETIC','runtime':'NOT_EXECUTED',
            'real_start':'IMAGE_PRESTART_TRUST_BLOCKED'}


def service_role(obj, project):
    # CLI v2.108.0 GetId(alias[0]); Mailpit retains the inbucket alias.
    names = {'/supabase_'+role+'_'+project:role for role in MANDATORY_ROLES}
    names['/omni_executor_'+project] = 'executor'  # Controller fixture, not a CLI service.
    require(type(obj.get('Name')) is str and obj['Name'] in names, 'SERVICE_ROLE_UNVERIFIED')
    return names[obj['Name']]


def readiness_time(value):
    try:
        require(type(value) is str, 'READINESS_TIMESTAMP_INVALID')
        result = dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        require(result.tzinfo is not None, 'READINESS_TIMESTAMP_INVALID')
        return result
    except (TypeError, ValueError) as error:
        raise ReadinessError('READINESS_TIMESTAMP_INVALID') from error


def readiness_now():
    return dt.datetime.now(dt.timezone.utc)


def rest_policy(policy):
    require(type(policy) is dict and set(policy) == {'role','mechanism','method','path','status',
            'follow_redirects','timeout_seconds','max_age_seconds'}
            and policy['role'] == 'rest' and policy['mechanism'] == 'rest_head'
            and policy['method'] == 'HEAD' and policy['path'] == REST_PATH
            and type(policy['status']) is int and policy['status'] == 200
            and policy['follow_redirects'] is False
            and type(policy['timeout_seconds']) is int and 0 < policy['timeout_seconds'] <= 10
            and type(policy['max_age_seconds']) is int and 0 < policy['max_age_seconds'] <= 60,
            'REST_POLICY_UNAPPROVED')


class SyntheticRestTransport:
    """Isolated in-memory wire simulation. No URL, hostname, socket or callback.

    Its one-use opaque receipts prevent a supplied JSON PASS from impersonating
    this mock collector. This is NOT a runtime trust root or a real HTTP client.
    """
    def __init__(self, response):
        self._response = json.dumps(response, allow_nan=False) if response is not None else None
        self._issued = {}

    def head_rest(self, binding, policy):
        rest_policy(policy)
        if self._response is None:
            return None
        receipt = object()
        request = {'method':'HEAD','path':REST_PATH,'follow_redirects':False,
                   'timeout_seconds':policy['timeout_seconds'],'binding':binding}
        self._issued[receipt] = (json.dumps(request), self._response)
        return receipt


def assess_rest_receipt(receipt, transport, binding, policy, earliest, now=None):
    rest_policy(policy)
    require(type(transport) is SyntheticRestTransport and type(receipt) is object
            and receipt in transport._issued, 'REST_PROBE_ORIGIN_UNTRUSTED')
    request_raw, response_raw = transport._issued.pop(receipt)
    request, response = json.loads(request_raw), json.loads(response_raw)
    require(request == {'method':'HEAD','path':REST_PATH,'follow_redirects':False,
                        'timeout_seconds':policy['timeout_seconds'],'binding':binding}, 'REST_REQUEST_MISMATCH')
    require(type(response) is dict and set(response) == set(binding) | {
            'origin','method','path','status','redirected','timed_out','response_service_id','started_at','completed_at'}
            and response.get('origin') == 'SYNTHETIC', 'REST_PROBE_ORIGIN_UNTRUSTED')
    require(all(type(response.get(k)) is type(v) and response.get(k) == v for k,v in binding.items())
            and response.get('response_service_id') == binding['rest_id'], 'REST_SERVICE_BINDING_MISMATCH')
    require(response.get('method') == 'HEAD' and response.get('path') == REST_PATH
            and response.get('redirected') is False and response.get('timed_out') is False
            and type(response.get('status')) is int and response['status'] == 200, 'REST_PROBE_FAILED')
    begun, ended = readiness_time(response.get('started_at')), readiness_time(response.get('completed_at'))
    clock = readiness_now() if now is None else now
    require(type(clock) is dt.datetime and clock.tzinfo is not None
            and readiness_time(earliest) <= begun <= ended <= clock
            and (ended-begun).total_seconds() <= policy['timeout_seconds']
            and (clock-ended).total_seconds() <= policy['max_age_seconds'], 'REST_PROBE_STALE')
    return {'validation':'PASS','origin':'SYNTHETIC','runtime':'NOT_EXECUTED',
            'real_probe':'REST_RUNTIME_PROBE_UNVERIFIED'}


def check_rest_readiness(rest, kong, executor, net, profile, project, earliest, transport, origin='SYNTHETIC'):
    require(origin == 'SYNTHETIC', 'REST_RUNTIME_PROBE_UNVERIFIED')
    require(type(transport) is SyntheticRestTransport, 'REST_PROBE_ORIGIN_UNTRUSTED')
    roles = image_profile(profile, origin)
    policy = roles['rest'].get('readiness')
    rest_policy(policy)
    network_id = check_network(net, project)
    for obj, role in ((rest,'rest'),(kong,'kong'),(executor,'executor')):
        check_container(obj,project,network_id,profile,earliest,ready=False,origin=origin)
        require(service_role(obj,project) == role, 'REST_SERVICE_BINDING_MISMATCH')
        require(type(obj.get('State')) is dict and obj['State'].get('Running') is True, 'REST_SERVICE_NOT_RUNNING')
        if role != 'rest':
            check_readiness(obj, roles[role], earliest)
    ns = executor.get('NamespaceEvidence')
    require(type(ns) is dict and ns.get('origin') == 'SYNTHETIC'
            and ns.get('executor_id') == executor['Id'] and ns.get('network_id') == network_id
            and all(type(ns.get(k)) is int and ns[k] > 0 for k in ('netns','container_netns','host_netns'))
            and ns['netns'] == ns['container_netns'] and ns['netns'] != ns['host_netns'], 'REST_EXECUTOR_UNVERIFIED')
    binding = {'project':project,'network_id':network_id,'executor_id':executor['Id'],
               'gateway_id':kong['Id'],'rest_id':rest['Id'],'executor_image_id':executor['Image'],
               'gateway_image_id':kong['Image'],'rest_image_id':rest['Image'],'executor_netns':ns['netns']}
    # Bypass instance overrides: this exact class method only simulates a wire.
    receipt = SyntheticRestTransport.head_rest(transport,binding,policy)
    require(receipt is not None, 'REST_PROBE_MISSING')
    boundary_start = max([readiness_time(earliest)] + [readiness_time(obj[k])
        for obj in (rest,kong,executor) for k in ('Created',)] +
        [readiness_time(obj['State']['StartedAt']) for obj in (rest,kong,executor)])
    return assess_rest_receipt(receipt,transport,binding,policy,boundary_start.isoformat())


def check_readiness(obj, expected, earliest, now=None):
    policy = expected.get('readiness')
    # No alternative probe is qualified offline. Missing HEALTHCHECK cannot fall
    # back to Running, a CLI exit status, or a hand-written receipt/endpoint.
    require(type(policy) is dict and policy.get('mechanism') == 'docker_healthcheck',
            'SERVICE_READINESS_NOT_VERIFIED')
    test, age = policy.get('test'), policy.get('max_age_seconds')
    require(type(test) is list and len(test) > 1 and test[0] in ('CMD','CMD-SHELL')
            and all(type(x) is str and x for x in test)
            and type(age) is int and 0 < age <= 60, 'READINESS_POLICY_INVALID')
    config = obj.get('Config',{}).get('Healthcheck')
    require(type(config) is dict and config.get('Test') == test, 'SERVICE_HEALTHCHECK_MISMATCH')
    state = obj.get('State')
    require(type(state) is dict and state.get('Running') is True, 'SERVICE_HEALTH_UNVERIFIED')
    health = state.get('Health')
    require(type(health) is dict and health.get('Status') == 'healthy'
            and type(health.get('FailingStreak')) is int and health['FailingStreak'] == 0,
            'SERVICE_HEALTH_UNVERIFIED')
    log = health.get('Log')
    require(type(log) is list and bool(log) and type(log[-1]) is dict
            and type(log[-1].get('ExitCode')) is int and log[-1]['ExitCode'] == 0,
            'SERVICE_HEALTH_UNVERIFIED')
    clock = readiness_now() if now is None else now
    require(type(clock) is dt.datetime and clock.tzinfo is not None, 'READINESS_TIMESTAMP_INVALID')
    begun, ended = readiness_time(log[-1].get('Start')), readiness_time(log[-1].get('End'))
    require(max(readiness_time(earliest), readiness_time(obj.get('Created')),
                readiness_time(state.get('StartedAt'))) <= begun <= ended <= clock
            and (clock-ended).total_seconds() <= age, 'SERVICE_READINESS_STALE')


def check_container(obj, project, network_id, profile, earliest, *, ready=True, now=None, origin='SYNTHETIC'):
    require(type(obj) is dict and native_id(obj.get('Id')), 'CONTAINER_ID_INVALID')
    require(type(obj.get('Config')) is dict, 'CONTAINER_INSPECT_MALFORMED')
    labels = obj.get('Config',{}).get('Labels') or {}
    require(type(labels) is dict, 'CONTAINER_INSPECT_MALFORMED')
    require(labels.get(PROJECT_LABEL) == project and labels.get('com.docker.compose.project') == project,
            'CONTAINER_OWNER_INVALID')
    roles = image_profile(profile, origin)
    role = service_role(obj, project)
    expected = roles.get(role)
    require(type(expected) is dict, 'SERVICE_ROLE_UNVERIFIED')
    check_image_identity(obj, expected)
    try:
        created = dt.datetime.fromisoformat(obj['Created'].replace('Z','+00:00'))
        start = dt.datetime.fromisoformat(earliest.replace('Z','+00:00'))
        require(created >= start, 'PREEXISTING_CONTAINER')
    except (KeyError, ValueError, TypeError) as error:
        raise ReadinessError('CREATION_EVIDENCE_INVALID') from error
    host = obj.get('HostConfig',{})
    require(host.get('Privileged') is False and host.get('PidMode','') != 'host'
            and not host.get('Devices') and not host.get('CapAdd'), 'PRIVILEGED_CONTAINER')
    attachments = obj.get('NetworkSettings',{}).get('Networks')
    require(type(attachments) is dict and len(attachments) == 1
            and next(iter(attachments.values())).get('NetworkID') == network_id, 'UNEXPECTED_NETWORK_ATTACHMENT')
    require(host.get('NetworkMode') in (network_id,next(iter(attachments))), 'NETWORK_MODE_BYPASS')
    ports=obj.get('NetworkSettings',{}).get('Ports')
    require(type(ports) is dict,'PUBLISHED_PORT_METADATA_MISSING')
    for bindings in ports.values():
        require(bindings is None or type(bindings) is list,'PUBLISHED_PORT_METADATA_MALFORMED')
        for binding in bindings or []:
            require(type(binding) is dict and binding.get('HostIp') in ('127.0.0.1','::1'), 'PUBLISHED_PORT_NOT_LOCAL')
    require(type(obj.get('Mounts')) is list,'MOUNT_INSPECT_INCOMPLETE')
    for mount in obj['Mounts']:
        require(type(mount) is dict and not any('docker.sock' in str(mount.get(k,''))
                or 'podman.sock' in str(mount.get(k,'')) for k in ('Source','Destination')),
                'SOCKET_EXPOSURE')
        require(mount.get('Type') in ('volume','tmpfs','bind'),'MOUNT_TYPE_UNVERIFIED')
        if mount['Type']=='bind':
            require(mount.get('OwnedSourceVerified') is True,'BIND_SOURCE_UNVERIFIED')
    if ready:
        require(role != 'rest', 'REST_RUNTIME_PROBE_UNVERIFIED')
        check_readiness(obj, expected, earliest, now)
    return obj['Id']


def resource_entry(kind, obj, project, network_id, images, earliest, before_ids):
    if kind == 'volume':
        # Docker volume inspect has Name, not an immutable Id. Never invent one.
        return {'type':'volume','id':None,'project':project,'observed_label':(obj.get('Labels') or {}).get(PROJECT_LABEL),
                'native_handle':obj.get('Name'),'created_at':obj.get('CreatedAt'),'immutable_id_available':False,
                'ownership':'OWNERSHIP_UNVERIFIED','cleanup':None,'observation':'native volume lacks immutable ID'}
    identifier = check_network(obj, project) if kind == 'network' else check_container(obj, project, network_id, images, earliest, ready=False)
    require(identifier not in before_ids, 'PREEXISTING_RESOURCE')
    return {'type':kind,'id':identifier,'project':project,'observed_label':project,
            'ownership':'VERIFIED_BY_CREATION_AND_INSPECT','creation_after':earliest,'observed_id':identifier,
            'image_id':obj.get('Image'),'cleanup':'remove_exact_id','removed':False}


def executor_plan(project, net_id, image):
    require(native_id(net_id), 'NETWORK_ID_INVALID')
    require(type(image) is str and re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', image), 'EXECUTOR_IMAGE_UNAPPROVED')
    return ['docker','container','create','--network',net_id,'--label',PROJECT_LABEL+'='+project,
            '--label','com.docker.compose.project='+project,
            '--label',RUN_LABEL+'='+project,'--read-only','--cap-drop','ALL','--security-opt',
            'no-new-privileges','--user','65534:65534','--pids-limit','64','--memory','256m',
            '--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,size=32m',image,'sleep','infinity']


NEGATIVE_PROBES = ('ipv4_numeric','container_ipv4','dns','container_dns','host_gateway','network_mode_bypass')
LOCAL_PROBES = ('postgresql','auth_api','mailpit','control_plane')


def assess_proofs(proof, executor_id, network_id):
    require(native_id(executor_id) and native_id(network_id),'PROBE_BOUNDARY_MISMATCH')
    require(type(proof) is dict and proof.get('origin') in ('SYNTHETIC','GITHUB_RUNTIME'), 'EGRESS_NOT_VERIFIED')
    require(proof.get('executor_id') == executor_id and proof.get('network_id') == network_id, 'PROBE_BOUNDARY_MISMATCH')
    boundary = proof.get('process_boundary',{})
    require(all(type(boundary.get(x)) is int and boundary[x]>0 for x in ('netns','container_netns','host_netns'))
            and boundary.get('netns') == boundary.get('container_netns')
            and boundary.get('netns') != boundary.get('host_netns') and boundary.get('socket_exposed') is False
            and boundary.get('privileged') is False, 'TEST_PROCESS_UNCONFINED')
    probes = proof.get('probes')
    require(type(probes) is dict and set(probes) == set(NEGATIVE_PROBES + LOCAL_PROBES + ('ipv6',)), 'PROBE_SET_INCOMPLETE')
    for name in NEGATIVE_PROBES:
        row = probes[name]
        require(row.get('before_success') is True and row.get('after_success') is False
                and type(row.get('exit')) is int and row['exit'] != 0
                and row.get('classification') == 'POLICY_DENIED'
                and row.get('witness') in ('verified_route_isolation','verified_filter_counter','verified_capability_rejection'),
                'EGRESS_NOT_VERIFIED')
    six = probes['ipv6']
    require((six.get('disabled') is True and six.get('routes') == [] and six.get('disable_witness') is True)
            or (six.get('before_success') is True and six.get('after_success') is False
                and type(six.get('exit')) is int and six['exit'] != 0
                and six.get('classification') == 'POLICY_DENIED' and six.get('witness') == 'verified_filter_counter'), 'IPV6_EGRESS_UNVERIFIED')
    require(all(probes[x].get('after_success') is True and type(probes[x].get('exit')) is int
                and probes[x]['exit'] == 0 for x in LOCAL_PROBES), 'LOCAL_OR_CONTROL_PLANE_FAILED')
    return {'validation':'PASS','runtime':'NOT_EXECUTED' if proof['origin']=='SYNTHETIC' else 'OBSERVED',
            'egress':'EGRESS_NOT_VERIFIED' if proof['origin']=='SYNTHETIC' else 'OBSERVED_DENIAL'}


def resource_gate(values, phase):
    require(phase in ('before','after') and type(values) is dict, 'RESOURCE_PRECHECK_FAILED')
    floor = (8 if phase == 'before' else 2) * 1024**3
    require(type(values.get('cpu')) is int and values['cpu'] >= 4
            and type(values.get('memory_available')) is int and values['memory_available'] >= 8*1024**3,
            'RESOURCE_PRECHECK_FAILED')
    require(set(values.get('filesystems',{})) == {'docker','runner_temp'}, 'RESOURCE_PRECHECK_FAILED')
    for row in values['filesystems'].values():
        require(type(row.get('bytes')) is int and row['bytes'] >= floor
                and type(row.get('inodes')) is int and row['inodes'] >= 100000, 'RESOURCE_PRECHECK_FAILED')
    require(values.get('local_socket') is True and bool(values.get('driver')), 'DOCKER_TARGET_UNVERIFIED')
    return {'validation':'PASS','origin':values.get('origin','SYNTHETIC')}


def aggregate(results, origin='SYNTHETIC'):
    complete = type(results) is dict and set(results) == set(STAGES)
    ready = complete and all(results[x] == 'PASS' for x in STAGES)
    return {'overall':'PASS' if ready and origin == 'GITHUB_RUNTIME' else 'BLOCKED',
            'origin':origin,'missing_or_nonpass':[x for x in STAGES if not complete or results.get(x) != 'PASS'],
            'stage_statuses':list(EXPECTED_STAGE_STATUSES) if origin != 'GITHUB_RUNTIME' else [],
            'note':'Synthetic checks cannot promote runtime, SQL or cleanup to PASS'}


def validate_temp(path, runner_temp, project):
    path, base = Path(path), Path(runner_temp).resolve(strict=True)
    require(path.name == project and not path.is_symlink() and path.parent.resolve() == base, 'TEMP_SCOPE_INVALID')
    require(path.resolve(strict=True).parent == base, 'TEMP_SCOPE_INVALID')
    owner = json.loads((path/'owner.json').read_bytes())
    require(owner.get('project') == project and owner.get('candidate') == 'bdbb31ef00a2d35bd63cce3f6c8c24f401f67fce', 'TEMP_OWNER_INVALID')
    device = path.stat().st_dev
    for item in path.rglob('*'):
        require(not item.is_symlink() and item.stat().st_dev == device, 'TEMP_SYMLINK_OR_MOUNT')
    return path


class Lab:
    """Protocol over an injected port. Unit tests supply mocks, never host commands."""
    def __init__(self, port, state):
        self.io, self.state = port, state
        require(project_id(state['run'],state['attempt']) == state['project'], 'PROJECT_MISMATCH')

    def network(self):
        s = self.state
        require(self.io.inventory() == {'container':[],'volume':[],'network':[]}, 'RUNNER_RESOURCES_NOT_FRESH')
        args = ['docker','network','create','--driver','bridge','--internal','--opt',
                'com.docker.network.bridge.host_binding_ipv4=127.0.0.1','--label',PROJECT_LABEL+'='+s['project'],
                '--label',RUN_LABEL+'='+s['project'],s['project']+'-net']
        code,out = self.io.command(args)
        require(code == 0 and native_id(out.strip()), 'NETWORK_CREATE_FAILED')
        net = self.io.inspect('network',out.strip())
        check_network(net,s['project'],out.strip())
        s['network_id'], s['network_name'] = net['Id'],net['Name']
        s['ledger'].append(resource_entry('network',net,s['project'],net['Id'],[],s['started'],[]))
        return {'network_id':net['Id'],'runtime':'NOT_EXECUTED' if self.io.origin=='SYNTHETIC' else 'OBSERVED'}

    def start(self, local):
        s = self.state
        image_profile(s.get('image_profile'), self.io.origin)
        prestart_image_gate(s['image_profile'],s.get('image_selection'),self.io.origin)
        require(s.get('cli_internal_cleanup_reviewed') is True, 'CLI_START_READINESS_UNVERIFIED')
        check_network(self.io.inspect('network',s['network_id']),s['project'],s['network_id'])
        code,version = self.io.command(['supabase','--version'])
        require(code == 0 and version.strip() == '2.108.0', 'CLI_VERSION')
        code,help_text = self.io.command(['supabase','start','--help'])
        require(code == 0 and '--network-id' in help_text
                and all(x in help_text for x in ('studio','analytics','vector','imgproxy')), 'CLI_HELP')
        args = ['supabase','--workdir',str(local),'--network-id',s['network_name'],'start',
                '--exclude','studio,analytics,vector,imgproxy']
        try:
            code,_ = self.io.command(args)  # Both streams stay private in real IO.
        except ReadinessError:
            code=-1  # Still inspect/record partial startup after a private command timeout.
        # Even on failure, observe partial startup. Never assume CLI internal cleanup completed.
        observed = self.io.inventory()
        uncertain = False
        for identifier in observed['container']:
            obj = self.io.inspect('container',identifier)
            try:
                entry = resource_entry('container',obj,s['project'],s['network_id'],s['image_profile'],s['started'],[])
                if obj.get('Name') == '/supabase_db_'+s['project']:
                    s['db_id'] = identifier  # Role selection only, after identity/ownership proof.
                s['ledger'].append(entry)
            except ReadinessError:
                s['ledger'].append({'type':'container','id':identifier,'project':s['project'],
                                    'ownership':'OWNERSHIP_UNVERIFIED','cleanup':None})
                uncertain = True
        for name in observed['volume']:
            s['ledger'].append(resource_entry('volume',self.io.inspect('volume',name),s['project'],s['network_id'],[],s['started'],[]))
        require(code == 0, 'CLI_START_FAILED_PARTIAL_STATE_RECORDED')
        require(not uncertain and observed['network'] == [s['network_id']], 'STARTUP_OWNERSHIP_UNVERIFIED')
        roles={}
        for identifier in observed['container']:
            obj=self.io.inspect('container',identifier)
            require(type(obj) is dict and obj.get('Id') == identifier, 'CONTAINER_ID_INVALID')
            check_container(obj,s['project'],s['network_id'],s['image_profile'],s['started'],ready=False,origin=self.io.origin)
            role=service_role(obj,s['project'])
            require(role not in roles,'REQUIRED_SERVICE_MISSING')
            roles[role]=obj
        require(set(MANDATORY_ROLES + ('executor',)) <= set(roles), 'REQUIRED_SERVICE_MISSING')
        for role,obj in roles.items():
            if role != 'rest':
                check_readiness(obj,image_profile(s['image_profile'])[role],s['started'])
        check_rest_readiness(roles['rest'],roles['kong'],roles['executor'],
            self.io.inspect('network',s['network_id']),s['image_profile'],s['project'],s['started'],
            self.io.rest_transport(),self.io.origin)
        return {'startup':'OBSERVED' if self.io.origin=='GITHUB_RUNTIME' else 'NOT_EXECUTED'}

    def resources(self, phase):
        values=self.io.measure()
        require(values.get('origin')==self.io.origin,'RESOURCE_ORIGIN_MISMATCH')
        return resource_gate(values,phase)

    def sql(self, sql_bytes, db_id, proof):
        s = self.state
        require(hashlib.sha256(sql_bytes).hexdigest() == SQL_SHA, 'SQL_HASH_MISMATCH')
        entries = [x for x in s['ledger'] if x.get('id') == db_id and x['type']=='container' and not x.get('removed')]
        require(native_id(db_id) and len(entries)==1 and db_id == s.get('db_id'), 'OWNED_POSTGRES_REQUIRED')
        obj = self.io.inspect('container',db_id)
        check_container(obj,s['project'],s['network_id'],s['image_profile'],s['started'],origin=self.io.origin)
        require(obj['Image'] == s.get('postgres_image'), 'POSTGRES_IMAGE_UNVERIFIED')
        executor_entries=[x for x in s['ledger'] if x.get('id')==s.get('executor_id') and x['type']=='container' and not x.get('removed')]
        require(len(executor_entries)==1,'OWNED_EXECUTOR_REQUIRED')
        check_container(self.io.inspect('container',s['executor_id']),s['project'],s['network_id'],s['image_profile'],s['started'],origin=self.io.origin)
        assess_proofs(proof,s['executor_id'],s['network_id'])
        require(proof['origin'] == self.io.origin, 'PROBE_ORIGIN_MISMATCH')
        self.io.verify_proof_origin(proof)
        args = ['docker','container','exec','--user','postgres','-i',db_id,
                'env','-i','PATH=/usr/local/bin:/usr/bin:/bin','psql','-X','-q','-w',
                '-h','/var/run/postgresql','-p','5432','-U','postgres','-d','postgres',
                '-v','ON_ERROR_STOP=1','-tA']
        code,out = self.io.command(args,data=sql_bytes)
        result = evaluate_jsonl(out,sql_exit=code)
        return {**result,'origin':self.io.origin,'sql_execution':'NOT_EXECUTED' if self.io.origin=='SYNTHETIC' else 'OBSERVED'}

    def cleanup(self, lifecycle):
        require(lifecycle in ('SUCCESS','FAILURE','PARTIAL_START','HEALTH_FAILURE','EGRESS_FAILURE',
                              'SQL_FAILURE','CANCELLATION','TIMEOUT'), 'CLEANUP_LIFECYCLE_UNKNOWN')
        s = self.state
        blocked = []
        for kind in ('container','volume','network'):
            for entry in [x for x in s['ledger'] if x['type']==kind]:
                if entry.get('removed'):
                    continue
                if kind == 'volume' or not native_id(entry.get('id')) or entry.get('observed_id') != entry['id'] or entry.get('ownership') != 'VERIFIED_BY_CREATION_AND_INSPECT' or entry.get('project') != s['project']:
                    blocked.append('OWNERSHIP_UNVERIFIED')
                    continue
                try:
                    obj = self.io.inspect(kind,entry['id'])
                    if obj is not None:
                        require(obj.get('Id') == entry['id'], 'RESOURCE_ID_MISMATCH')
                        if kind == 'container':
                            check_container(obj,s['project'],s['network_id'],s['image_profile'],entry['creation_after'],ready=False,origin=self.io.origin)
                            code,_ = self.io.command(['docker','container','stop','--time','10',entry['id']])
                            require(code == 0,'CLEANUP_STOP_FAILED')
                            obj = self.io.inspect(kind,entry['id'])
                            require(obj is not None and obj.get('Id') == entry['id'], 'CLEANUP_REINSPECT_FAILED')
                            check_container(obj,s['project'],s['network_id'],s['image_profile'],entry['creation_after'],ready=False,origin=self.io.origin)
                        else:
                            check_network(obj,s['project'],entry['id'])
                            require(not obj.get('Containers'), 'NETWORK_HAS_REMAINING_ENDPOINTS')
                        code,_ = self.io.command(['docker',kind,'rm',entry['id']])
                        require(code == 0, 'CLEANUP_REMOVE_FAILED')
                        require(self.io.inspect(kind,entry['id']) is None,'CLEANUP_POSTCONDITION_FAILED')
                    entry['removed'] = True
                except ReadinessError:
                    blocked.append('OWNERSHIP_OR_TEARDOWN_UNVERIFIED')
        # No wildcard/global deletion. Private workspace deletion only after all
        # objects are proven gone; unknown volumes retain state/evidence safely.
        remaining=self.io.inventory()
        if any(remaining.values()):
            blocked.append('UNACCOUNTED_OR_RETAINED_RESOURCES')
        if not blocked and not s.get('temp_removed'):
            self.io.remove_temp(s['local'],s['project'])
            s['temp_removed'] = True
        return {'validation':'BLOCKED' if blocked else 'PASS','blocked':blocked,
                'cleanup':'NOT_EXECUTED' if self.io.origin=='SYNTHETIC' else ('FAIL' if blocked else 'OBSERVED'),
                'origin':self.io.origin}


class GitHubIO:
    """Only real command boundary. Every entry independently hits the hard guard."""
    origin = 'GITHUB_RUNTIME'

    def __init__(self, private):
        self.guard()
        self.private = Path(private)
        require(not self.private.is_symlink() and Path(os.environ['RUNNER_TEMP']).resolve() in self.private.absolute().parents,
                'PRIVATE_OUTPUT_SCOPE_INVALID')
        self.private.mkdir(mode=0o700,parents=True,exist_ok=True)
        require(self.private.stat().st_uid==os.getuid() and self.private.stat().st_mode & 0o077 == 0,
                'PRIVATE_OUTPUT_PERMISSIONS_INVALID')

    @staticmethod
    def guard():
        from security import authorize
        authorize()  # Always raises today. No override flag, environment or callback.
        require(sys.platform == 'linux' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
                and os.environ.get('GITHUB_REPOSITORY') == 'piotrfpn/omninauka-ci-lab'
                and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'GITHUB_RUNNER_REQUIRED')
        os_release = Path('/etc/os-release').read_text(encoding='utf-8')
        require('VERSION_ID="24.04"' in os_release and 'ID=ubuntu' in os_release, 'RUNNER_OS_MISMATCH')

    def command(self, argv, data=None):
        self.guard()
        require(not (type(argv) is list and argv and argv[0] == 'supabase' and 'start' in argv
                     and '--help' not in argv), 'IMAGE_PRESTART_TRUST_BLOCKED')
        require(type(argv) is list and argv and argv[0] in ('docker','supabase'), 'COMMAND_NOT_REVIEWED')
        require(not any(x in argv for x in ('prune','--privileged','--ignore-health-check')), 'COMMAND_NOT_REVIEWED')
        if '--all' in argv:
            require(argv == ['docker','container','ls','--all','--no-trunc','--format','{{.ID}}'], 'COMMAND_NOT_REVIEWED')
        require(not (argv[0]=='supabase' and 'stop' in argv), 'CLI_STOP_NOT_AUTHORIZED')
        if argv[0]=='docker':
            require(tuple(argv[1:3]) in (('container','ls'),('container','inspect'),('container','create'),
                    ('container','start'),('container','exec'),('container','stop'),('container','rm'),
                    ('network','ls'),('network','inspect'),('network','create'),('network','rm'),
                    ('volume','ls'),('volume','inspect'),('info','--format'),('context','inspect'),('system','df')),
                    'COMMAND_NOT_REVIEWED')
        else:
            require(argv in (['supabase','--version'],['supabase','start','--help'])
                    or (len(argv)==8 and argv[1]=='--workdir' and argv[3]=='--network-id' and argv[5:] ==
                        ['start','--exclude','studio,analytics,vector,imgproxy']), 'COMMAND_NOT_REVIEWED')
        os.umask(0o077)
        token = uuid.uuid4().hex
        env = {'PATH':os.environ['PATH'],'HOME':str(self.private/'home'),'TMPDIR':str(self.private),
               'NO_COLOR':'1','CI':'true'}
        (self.private/'home').mkdir(mode=0o700,exist_ok=True)
        with (self.private/(token+'.out')).open('xb') as out, (self.private/(token+'.err')).open('xb') as err:
            try:
                p = subprocess.run(argv,input=data,stdout=out,stderr=err,env=env,check=False,timeout=900)
            except subprocess.TimeoutExpired as error:
                raise ReadinessError('PRIVATE_COMMAND_TIMED_OUT') from error
        output = (self.private/(token+'.out')).read_text(encoding='utf-8')
        return p.returncode,output

    def inventory(self):
        out = {}
        for kind in ('container','volume','network'):
            args=['docker',kind,'ls','--format','{{.ID}}'] if kind!='volume' else ['docker','volume','ls','--format','{{.Name}}']
            if kind=='container':
                args[3:3]=['--all','--no-trunc']
            if kind=='network':
                args=['docker','network','ls','--no-trunc','--format','{{json .}}']
            code,data=self.command(args)
            require(code==0,'INVENTORY_UNVERIFIED')
            ids=data.splitlines()
            if kind=='network':
                rows=[json.loads(x) for x in ids]
                ids=[x['ID'] for x in rows if (x.get('Name'),x.get('Driver')) not in
                     (('bridge','bridge'),('host','host'),('none','null'))]
            if kind!='volume':
                require(all(native_id(x) for x in ids),'INVENTORY_ID_INVALID')
            out[kind]=ids
        return out

    def inspect(self, kind, identifier):
        require(kind in ('container','network','volume'), 'RESOURCE_TYPE_UNKNOWN')
        code,data=self.command(['docker',kind,'inspect',identifier])
        if code==0:
            rows=json.loads(data)
            require(type(rows)is list and len(rows)==1,'INSPECT_UNVERIFIED')
            if kind=='container':
                # Ordinary bind names do not prove absence of a renamed socket.
                # Verify native host metadata only on the authorized future runner.
                local=Path(os.environ['LOCAL_SUPABASE_DIR']).resolve(strict=True)
                for mount in rows[0].get('Mounts',[]):
                    if mount.get('Type')=='bind':
                        source=Path(mount['Source'])
                        resolved=source.resolve(strict=True)
                        allowed=resolved==local or local in resolved.parents
                        chain=[source,*source.parents]
                        no_links=not any(x.is_symlink() for x in chain if x==local or local in x.parents)
                        mount['OwnedSourceVerified']=allowed and no_links and not stat.S_ISSOCK(source.stat().st_mode)
            return rows[0]
        # A failing inspect is not proof of absence. Require a successful inventory.
        require(identifier not in self.inventory()[kind], 'INSPECT_UNVERIFIED')
        return None

    def verify_proof_origin(self, proof):
        self.guard()
        # Never turn a hand-written private JSON file into live egress proof.
        # The collector must bind actual probe receipts/netns observations first.
        raise ReadinessError('LIVE_EGRESS_COLLECTOR_REQUIRES_GITHUB_QUALIFICATION')

    def rest_transport(self):
        self.guard()
        raise ReadinessError('REST_RUNTIME_PROBE_UNVERIFIED')

    def prestart_images(self):
        self.guard()
        raise ReadinessError('IMAGE_PRESTART_TRUST_BLOCKED')

    def measure(self):
        self.guard()
        code,data=self.command(['docker','info','--format','{{json .}}'])
        require(code==0,'RESOURCE_PRECHECK_FAILED')
        info=json.loads(data)
        code,data=self.command(['docker','context','inspect'])
        require(code==0,'DOCKER_TARGET_UNVERIFIED')
        contexts=json.loads(data)
        filesystems={}
        for key,path in (('docker',info['DockerRootDir']),('runner_temp',os.environ['RUNNER_TEMP'])):
            stats=os.statvfs(path)
            filesystems[key]={'bytes':stats.f_bavail*stats.f_frsize,'inodes':stats.f_favail,'path':path}
        memory=int(re.search(r'MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(encoding='utf-8'))[1])*1024
        code,usage=self.command(['docker','system','df','--format','{{json .}}'])
        require(code==0,'RESOURCE_USAGE_UNVERIFIED')
        return {'origin':self.origin,'cpu':os.cpu_count(),'memory_available':memory,'filesystems':filesystems,
                'driver':info['Driver'],'docker_cpu':info['NCPU'],'docker_memory':info['MemTotal'],
                'local_socket':len(contexts)==1 and contexts[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock',
                'usage':[json.loads(line) for line in usage.splitlines()]}

    def remove_temp(self,path,project):
        self.guard()
        target=validate_temp(path,os.environ['RUNNER_TEMP'],project)
        shutil.rmtree(target)  # Only exact validated, owned RUNNER_TEMP child.


def dispatch(command, root, argument=None):
    """Future entry point. Current guard prevents even filesystem/command access."""
    GitHubIO.guard()
    from security import controller_revision, safe_workspace
    controller_revision()
    project=project_id(os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'])
    base=Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    local=base/project
    require(Path(os.environ['LOCAL_SUPABASE_DIR']).absolute()==local and not local.is_symlink(),'TEMP_SCOPE_INVALID')
    state_path=base/(project+'-ledger.json')
    require(not state_path.is_symlink(),'LEDGER_PATH_INVALID')
    if state_path.exists():
        require(state_path.is_file() and state_path.stat().st_uid==os.getuid()
                and state_path.stat().st_mode & 0o077 == 0,'LEDGER_PERMISSIONS_INVALID')
    require(command!='cleanup' or state_path.is_file(),'CLEANUP_OWNERSHIP_UNVERIFIED_NO_LEDGER')
    state=json.loads(state_path.read_bytes()) if state_path.exists() else {
        'project':project,'run':os.environ['GITHUB_RUN_ID'],'attempt':os.environ['GITHUB_RUN_ATTEMPT'],
        'started':dt.datetime.now(dt.timezone.utc).isoformat(),'local':str(local),'ledger':[],
        'image_profile':{'status':'UNAPPROVED','roles':{}},'cli_internal_cleanup_reviewed':False,
        'stages':{name:'NOT_TESTED' for name in STAGES}}
    require(state['project']==project and state['local']==str(local),'LEDGER_OWNER_INVALID')
    require(set(state['stages'])==set(STAGES),'RESULT_LEDGER_INCOMPLETE')
    state['stages']['TRUST']='PASS'
    lint_path=base/(project+'-lint')
    lint_receipts=[]
    for name in ('shellcheck','actionlint'):
        receipt=lint_path/(name+'-receipt.json')
        if receipt.is_file() and not receipt.is_symlink():
            value=json.loads(receipt.read_bytes())
            if (value.get('origin')=='GITHUB_RUNTIME' and value.get('status')=='PASS'
                    and value.get('controller_sha')==os.environ['GITHUB_SHA']
                    and value.get('workflow_sha')==os.environ.get('EXECUTED_WORKFLOW_SHA')):
                lint_receipts.append(name)
    if set(lint_receipts)=={'shellcheck','actionlint'}:
        state['stages']['LINT']='PASS'
    if command!='cleanup' or not state.get('temp_removed'):
        require(safe_workspace()==local,'TEMP_SCOPE_INVALID')
    private=base/(project+'-cleanup-check') if state.get('temp_removed') else local/'private/commands'
    port=GitHubIO(private);lab=Lab(port,state)
    try:
        if command=='resources':
            result=lab.resources(argument or 'before')
            state.setdefault('resource_phases',[]).append(argument or 'before')
            if {'before','after'}<=set(state['resource_phases']):
                state['stages']['RESOURCES']='PASS'
        elif command=='network':
            result=lab.network()
        elif command=='start':
            result=lab.start(local)
            state['stages']['RUNTIME']='PASS'
        elif command=='c0':
            proof_path=local/'private/network-proof.json'
            require(proof_path.is_file() and not proof_path.is_symlink(),'EGRESS_NOT_VERIFIED')
            result=lab.sql((root/'harness/sql/c0-readonly.sql').read_bytes(),state.get('db_id'),json.loads(proof_path.read_bytes()))
            state['stages']['NETWORK']='PASS'
            state['stages']['POSTGRESQL']='PASS'
            state['stages']['SQL_ASSERTIONS']='PASS'
        elif command=='cleanup':
            lifecycle={'success':'SUCCESS','failure':'FAILURE','cancelled':'CANCELLATION'}.get(os.environ.get('JOB_RESULT'),'FAILURE')
            result=lab.cleanup(lifecycle)
            state['stages']['CLEANUP']='PASS' if result['validation']=='PASS' else 'BLOCKED'
        else:
            raise ReadinessError('RUNTIME_ADAPTER_NOT_QUALIFIED')
    except (ReadinessError,ValueError):
        stage={'resources':'RESOURCES','network':'NETWORK','start':'RUNTIME','c0':'SQL_ASSERTIONS','cleanup':'CLEANUP'}.get(command)
        if stage:
            state['stages'][stage]='BLOCKED'
        raise
    finally:
        # Ledger has IDs/labels only, never generated Auth/DB credentials. Do not upload.
        os.umask(0o077)
        require(not state_path.is_symlink(),'LEDGER_PATH_INVALID')
        state_path.write_text(json.dumps(state,indent=2),encoding='utf-8')
    final=aggregate(state['stages'],port.origin)
    print(json.dumps({'component':command,'result':result,'c0':final}))
    if command=='cleanup':
        require(final['overall']=='PASS','C0_MANDATORY_RESULTS_INCOMPLETE')
