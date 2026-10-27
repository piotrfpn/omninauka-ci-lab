"""Offline contract/mocked Bash tests. No real runner, tools or provenance proof.

Only the existing native Git Bash on Windows (never System32/WSL Bash), or system
Bash on Linux, is used. OS command/file predicates are replaced with explicit
in-memory fakes. Tests never measure local Python/Ruby/ShellCheck or access dpkg.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security import yaml_load

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/static-toolchain-discovery.yml'
MARKER = '# Evidence is emitted only after every measurement succeeds.'
# Independently review changes to this frozen inline contract and the behavior
# tests together. This digest is NOT an executable/runner approval value.
SCRIPT_SHA256 = '5409f3feba2a42f6f6b3193dfeb83596cc23446f87f5b1793589bbef961b0eff'


def validate_workflow(document):
    expected_env = {
        'DISCOVERY_APPROVED_COMMIT_SHA': '${{ vars.DISCOVERY_APPROVED_COMMIT_SHA }}',
        'EXECUTED_WORKFLOW_SHA': '${{ github.workflow_sha }}',
        'REF_PROTECTED': '${{ github.ref_protected }}', 'BASH_ENV': '', 'ENV': ''}
    expected = {
        'name': 'Static toolchain discovery - observations only',
        'on': {'workflow_dispatch': None}, 'permissions': {},
        'concurrency': {'group': 'static-toolchain-discovery', 'cancel-in-progress': False},
        'jobs': {'discovery': {
            'runs-on': 'ubuntu-24.04', 'timeout-minutes': 5,
            'defaults': {'run': {'shell': 'bash --noprofile --norc -euo pipefail {0}'}},
            'env': expected_env,
            'steps': [{'name': 'Measure approved system paths without approving observations',
                       'run': document['jobs']['discovery']['steps'][0]['run']}]}}}
    if document != expected:
        raise ValueError('DISCOVERY_WORKFLOW_CONTRACT_MISMATCH')
    script = expected['jobs']['discovery']['steps'][0]['run']
    if hashlib.sha256(script.encode('utf-8')).hexdigest() != SCRIPT_SHA256:
        raise ValueError('DISCOVERY_INLINE_CONTRACT_MISMATCH')


def native_bash():
    if os.name == 'nt':
        return next((str(p) for p in (Path('C:/Program Files/Git/bin/bash.exe'),
                                     Path('C:/Program Files/Git/usr/bin/bash.exe'))
                     if p.is_file()), None)
    return shutil.which('bash')


def synthetic_environment(**overrides):
    # All versions, digests and package names below are explicitly synthetic.
    env = {
        'PATH': os.environ.get('PATH', ''), 'LC_ALL': 'C.UTF-8',
        'GITHUB_EVENT_NAME': 'workflow_dispatch',
        'GITHUB_REPOSITORY': 'piotrfpn/omninauka-ci-lab',
        'GITHUB_REF': 'refs/heads/main', 'REF_PROTECTED': 'true',
        'GITHUB_WORKFLOW_REF': 'piotrfpn/omninauka-ci-lab/.github/workflows/'
                               'static-toolchain-discovery.yml@refs/heads/main',
        'DISCOVERY_APPROVED_COMMIT_SHA': 'a' * 40, 'GITHUB_SHA': 'a' * 40,
        'EXECUTED_WORKFLOW_SHA': 'a' * 40, 'RUNNER_ENVIRONMENT': 'github-hosted',
        'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64',
        'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
        'MOCK_DIGEST': '1' * 64}
    for name in ('SYSTEMROOT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP'):
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(overrides)
    return env


# Replaces only the measured OS boundaries, after the actual functions are defined.
# No real OS package lookup, version execution, network, or filesystem write occurs.
FAKES = r'''
is_link() {
  [[ "${MOCK_LINK:-}" == cycle || ( "${MOCK_LINK:-}" == single && "$1" == /usr/bin/python3 ) ]]
}
is_executable() { [[ "${MOCK_MISSING:-}" != yes ]]; }
mock_stat() {
  [[ "${MOCK_STAT_FAIL:-}" != yes ]] || return 1
  if [[ "$2" == '%u' ]]; then printf '%s' "${MOCK_LINK_UID:-0}"
  else printf '%s' "${MOCK_METADATA:-0:755}"; fi
}
mock_readlink() {
  [[ "${MOCK_UNRESOLVED:-}" != yes ]] || return 1
  if [[ "$1" == -e ]]; then
    if [[ -n "${MOCK_RESOLVED:-}" ]]; then printf '%s' "$MOCK_RESOLVED"
    elif [[ "${MOCK_LINK:-}" == single && "${@: -1}" == /usr/bin/python3 ]]; then printf /usr/bin/python3.99
    else printf '%s' "${@: -1}"; fi
  else printf '%s' "${MOCK_LINK_TARGET:-python3.99}"; fi
}
mock_uname() { printf '%s' "${MOCK_MACHINE:-x86_64}"; }
mock_sha256sum() {
  if [[ "${MOCK_HASH_FAIL:-}" == yes ]]; then return 1; fi
  if [[ "${MOCK_HASH_INVALID:-}" == yes ]]; then printf invalid; return; fi
  printf '%s  %s' "$MOCK_DIGEST" "${@: -1}"
}
mock_dpkg_query() {
  [[ "${MOCK_DPKG_FAIL:-}" != yes ]] || return 1
  if [[ "$1" == --search ]]; then
    if [[ "${MOCK_OWNER+x}" == x ]]; then printf '%s' "$MOCK_OWNER"
    else printf 'synthetic-tool: %s' "${@: -1}"; fi
  else
    if [[ "${MOCK_PACKAGE_METADATA+x}" == x ]]; then printf '%s' "$MOCK_PACKAGE_METADATA"
    else printf 'synthetic-tool\t0.0.0-1synthetic\tamd64\tinstalled'; fi
  fi
}
mock_env() {
  [[ "${MOCK_VERSION_FAIL:-}" != yes ]] || return 1
  local target="${@: -2:1}"
  [[ "${MOCK_FAIL_TOOL:-}" != "$target" ]] || return 1
  if [[ "${MOCK_VERSION+x}" == x ]]; then printf '%s' "$MOCK_VERSION"; return; fi
  case "$target" in
    /usr/bin/python*) printf 'Python 0.0.0' ;;
    /usr/bin/ruby) printf 'ruby 0.0.0 (synthetic fixture) [synthetic]' ;;
    /usr/bin/shellcheck) printf 'ShellCheck - synthetic fixture\nversion: 0.0.0\nlicense: synthetic' ;;
    *) return 1 ;;
  esac
}
'''


class DiscoveryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = yaml_load(WORKFLOW)
        cls.script = cls.document['jobs']['discovery']['steps'][0]['run']

    def test_actual_workflow_matches_frozen_contract(self):
        validate_workflow(self.document)

    def test_structural_mutations_are_rejected(self):
        mutations = [
            ('automatic push', lambda w: w['on'].update(push=None)),
            ('automatic PR', lambda w: w['on'].update(pull_request=None)),
            ('schedule', lambda w: w['on'].update(schedule=[])),
            ('inputs', lambda w: w['on'].update(workflow_dispatch={'inputs': {}})),
            ('write token', lambda w: w.update(permissions={'contents': 'write'})),
            ('OIDC', lambda w: w.update(permissions={'id-token': 'write'})),
            ('self hosted', lambda w: w['jobs']['discovery'].update({'runs-on': 'self-hosted'})),
            ('different OS', lambda w: w['jobs']['discovery'].update({'runs-on': 'ubuntu-latest'})),
            ('unbounded timeout', lambda w: w['jobs']['discovery'].pop('timeout-minutes')),
            ('job permissions', lambda w: w['jobs']['discovery'].update(permissions={'actions': 'write'})),
            ('approval omitted', lambda w: w['jobs']['discovery']['env'].pop('DISCOVERY_APPROVED_COMMIT_SHA')),
            ('self approval', lambda w: w['jobs']['discovery']['env'].update(DISCOVERY_APPROVED_COMMIT_SHA='${{ github.sha }}')),
            ('workflow self approval', lambda w: w['jobs']['discovery']['env'].update(DISCOVERY_APPROVED_COMMIT_SHA='${{ github.workflow_sha }}')),
            ('checkout', lambda w: w['jobs']['discovery']['steps'].append({'uses': 'actions/checkout@main'})),
            ('artifacts', lambda w: w['jobs']['discovery']['steps'].append({'uses': 'actions/upload-artifact@main'})),
            ('cache', lambda w: w['jobs']['discovery']['steps'].append({'uses': 'actions/cache@main'})),
            ('container', lambda w: w['jobs']['discovery'].update(container='ubuntu')),
            ('ignored failure', lambda w: w['jobs']['discovery']['steps'][0].update({'continue-on-error': True})),
            ('skipped measurement', lambda w: w['jobs']['discovery']['steps'][0].update({'if': '${{ false }}'})),
        ]
        for name, change in mutations:
            with self.subTest(mutation=name):
                mutated = copy.deepcopy(self.document)
                change(mutated)
                with self.assertRaises(ValueError):
                    validate_workflow(mutated)

    def test_executable_input_mutations_are_rejected(self):
        commands = ('curl forbidden.invalid', 'wget forbidden.invalid', 'apt-get install example',
                    'pip install example', 'gh api --method PUT forbidden',
                    'gh variable set STATIC_PYTHON_SHA256 --body synthetic',
                    'gh workflow run example', 'docker version', 'supabase status',
                    'psql --version', 'sudo example', 'env', 'printenv',
                    'set ' + '-' + 'x', 'DISCOVERY_APPROVED_COMMIT_SHA=$GITHUB_SHA',
                    'echo approved', 'printf arbitrary-filesystem-content')
        for command in commands:
            with self.subTest(command=command):
                mutated = copy.deepcopy(self.document)
                mutated['jobs']['discovery']['steps'][0]['run'] += '\n' + command + '\n'
                with self.assertRaises(ValueError):
                    validate_workflow(mutated)


class DiscoveryBashTests(DiscoveryContractTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.bash = native_bash()
        if cls.bash is None:
            raise unittest.SkipTest('NOT_TESTED: native Bash unavailable; never use WSL')
        cls.definitions, cls.entry = cls.script.split(MARKER)
        boundaries = {'stat': 'mock_stat', 'readlink': 'mock_readlink',
                      'uname': 'mock_uname', 'sha256sum': 'mock_sha256sum',
                      'dpkg-query': 'mock_dpkg_query', 'env': 'mock_env'}
        for original, fake in boundaries.items():
            cls.definitions = cls.definitions.replace('/usr/bin/' + original, fake)
        cls.definitions = cls.definitions.replace(
            '. /etc/os-release', 'ID="${MOCK_OS_ID:-ubuntu}"; VERSION_ID="${MOCK_OS_VERSION:-24.04}"')

    def execute_mocked(self, command=None, **overrides):
        script = self.definitions + '\n' + FAKES + '\n' + (self.entry if command is None else command)
        return subprocess.run([self.bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', script],
                              env=synthetic_environment(**overrides), capture_output=True,
                              text=True, encoding='utf-8', timeout=10, check=False)

    def assert_denied(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '', 'No partial evidence may be published')
        self.assertNotIn('Traceback', result.stderr)

    def test_bash_syntax_without_execution(self):
        result = subprocess.run([self.bash, '--noprofile', '--norc', '-n'],
                                input=self.script, capture_output=True, text=True,
                                encoding='utf-8', timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_complete_mock_observation_is_bounded_and_never_approved(self):
        result = self.execute_mocked()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(len(result.stdout.encode('utf-8')), 8192)
        record = json.loads(result.stdout)
        self.assertEqual(set(record), {'status', 'repository', 'commit_sha', 'workflow_sha',
                                      'run_id', 'run_attempt', 'image_os', 'image_version', 'observations'})
        self.assertEqual(record['status'], 'OBSERVED_NOT_APPROVED')
        self.assertEqual(record['image_version'], 'UNAVAILABLE')
        self.assertEqual([x['tool'] for x in record['observations']], ['PYTHON', 'RUBY', 'SHELLCHECK'])
        for observation in record['observations']:
            self.assertEqual(set(observation), {'tool', 'original_path', 'resolved_path', 'version',
                                               'sha256', 'package', 'package_version', 'architecture'})
            self.assertEqual(observation['version'], '0.0.0')
            self.assertEqual(observation['sha256'], '1' * 64)

    def test_context_failures_publish_no_observation(self):
        failures = {'DISCOVERY_APPROVED_COMMIT_SHA': ('', 'not-approved', 'b' * 40),
                    'GITHUB_SHA': ('b' * 40,), 'EXECUTED_WORKFLOW_SHA': ('b' * 40,),
                    'GITHUB_EVENT_NAME': ('push', 'pull_request'),
                    'GITHUB_REPOSITORY': ('foreign/repo',), 'GITHUB_REF': ('refs/heads/other', 'refs/tags/main'),
                    'REF_PROTECTED': ('false', ''), 'GITHUB_WORKFLOW_REF': ('foreign/workflow@main',),
                    'RUNNER_ENVIRONMENT': ('self-hosted',), 'RUNNER_OS': ('Windows',),
                    'RUNNER_ARCH': ('ARM64',), 'MOCK_MACHINE': ('aarch64',),
                    'MOCK_OS_ID': ('debian',), 'MOCK_OS_VERSION': ('22.04',),
                    'GITHUB_RUN_ID': ('0', '1\ninjected', '1' * 21),
                    'GITHUB_RUN_ATTEMPT': ('0', '1' * 11),
                    'ImageVersion': ('x' * 65, 'unsafe"value', 'unsafe\nvalue')}
        for name, values in failures.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    self.assert_denied(self.execute_mocked('verify_context', **{name: value}))

    def test_missing_environment_approval_is_not_self_approved(self):
        self.assert_denied(self.execute_mocked('unset DISCOVERY_APPROVED_COMMIT_SHA; verify_context'))

    def test_missing_or_unresolved_tool_denied(self):
        for overrides in ({'MOCK_MISSING': 'yes'}, {'MOCK_UNRESOLVED': 'yes'},
                          {'MOCK_RESOLVED': '/tmp/foreign'}, {'MOCK_RESOLVED': '/usr/bin/../bin/python3'}):
            with self.subTest(overrides=overrides):
                self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3', **overrides))

    def test_relative_and_absolute_root_owned_symlink_success(self):
        for target in ('python3.99', '/usr/bin/python3.99'):
            with self.subTest(target=target):
                result = self.execute_mocked('measure_tool /usr/bin/python3', MOCK_LINK='single', MOCK_LINK_TARGET=target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['resolved_path'], '/usr/bin/python3.99')

    def test_unsafe_symlink_owner_target_and_cycle_denied(self):
        for overrides in ({'MOCK_LINK': 'single', 'MOCK_LINK_UID': '1000'},
                          {'MOCK_LINK': 'single', 'MOCK_LINK_TARGET': '../bin/python3'},
                          {'MOCK_LINK': 'single', 'MOCK_LINK_TARGET': '/tmp/python3'},
                          {'MOCK_LINK': 'cycle', 'MOCK_LINK_TARGET': 'python3'}):
            with self.subTest(overrides=overrides):
                self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3', **overrides))

    def test_unsafe_executable_or_parent_metadata_denied(self):
        for value in ('1000:755', '0:775', '0:757', '0:777', '0:4755', '0:2755', '0:1755', 'invalid'):
            with self.subTest(metadata=value):
                self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3', MOCK_METADATA=value))
                self.assert_denied(self.execute_mocked('verify_context', MOCK_METADATA=value))

    def test_hash_measurement_failures_denied(self):
        for overrides in ({'MOCK_HASH_FAIL': 'yes'}, {'MOCK_HASH_INVALID': 'yes'}, {'MOCK_DIGEST': 'x' * 64}):
            with self.subTest(overrides=overrides):
                self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3', **overrides))
        # Each command substitution has a different BASHPID: both hashes have
        # valid syntax but the post-version digest differs from the first one.
        command = 'mock_sha256sum() { printf "%064d  %s" "$BASHPID" "${@: -1}"; }; measure_tool /usr/bin/python3'
        self.assert_denied(self.execute_mocked(command))

    def test_ambiguous_missing_or_foreign_package_denied(self):
        for owner in ('', 'one, two: /usr/bin/python3',
                      'one: /usr/bin/python3\ntwo: /usr/bin/python3',
                      'one: /usr/bin/other', 'unsafe"package: /usr/bin/python3'):
            with self.subTest(owner=owner):
                self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3', MOCK_OWNER=owner))
        self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3', MOCK_DPKG_FAIL='yes'))

    def test_incomplete_or_unsafe_package_metadata_denied(self):
        values = ('synthetic-tool\t0.0.0-1\tamd64',
                  'synthetic-tool\t0.0.0-1\tamd64\tnot-installed',
                  'synthetic-tool\t0.0.0-1\tarm64\tinstalled',
                  'other-tool\t0.0.0-1\tamd64\tinstalled',
                  'synthetic-tool\tunsafe"version\tamd64\tinstalled',
                  'synthetic-tool\t0.0.0-1\tamd64\tinstalled\textra',
                  'synthetic-tool\t0.0.0-1\tamd64\tinstalled\nforeign')
        for value in values:
            with self.subTest(metadata=value):
                self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3', MOCK_PACKAGE_METADATA=value))

    def test_multiarch_identity_is_unambiguous(self):
        result = self.execute_mocked('measure_tool /usr/bin/python3',
                                     MOCK_OWNER='synthetic-tool:amd64: /usr/bin/python3',
                                     MOCK_PACKAGE_METADATA='synthetic-tool:amd64\t0.0.0-1\tamd64\tinstalled')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3',
                                              MOCK_OWNER='synthetic-tool:arm64: /usr/bin/python3'))

    def test_missing_ambiguous_or_unbounded_versions_denied(self):
        for path, values in {
                '/usr/bin/python3': ('', 'Python 0.0.0\nPython 0.0.1', 'Python latest', 'x' * 1025),
                '/usr/bin/ruby': ('ruby latest', 'ruby 0.0.0\nforeign'),
                '/usr/bin/shellcheck': ('version: latest', 'version: 0.0.0\nversion: 0.0.1',
                                       'version: 0.0.0\nversion: ambiguous')}.items():
            for value in values:
                with self.subTest(path=path, version=value):
                    self.assert_denied(self.execute_mocked('measure_tool ' + path, MOCK_VERSION=value))
        self.assert_denied(self.execute_mocked('measure_tool /usr/bin/python3', MOCK_VERSION_FAIL='yes'))

    def test_late_failure_suppresses_all_partial_evidence(self):
        self.assert_denied(self.execute_mocked(MOCK_FAIL_TOOL='/usr/bin/shellcheck'))

    def test_non_allowlisted_path_denied(self):
        self.assert_denied(self.execute_mocked('measure_tool /tmp/python3'))


if __name__ == '__main__':
    unittest.main()
