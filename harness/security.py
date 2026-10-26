#!/usr/bin/env python3
"""P0.3E.2 controller. Runtime is deliberately unavailable pending isolation review."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
sys.dont_write_bytecode = True
from c0_results import InvalidResult, evaluate_jsonl
from github_runtime import BOOTSTRAP, ReadinessError, trust_revision

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = 'bdbb31ef00a2d35bd63cce3f6c8c24f401f67fce'
MAIN = '009206ec151f98bc7ddf323fb4aef36dfa4827c8'
ORIGINAL = '2dc0e8c663f84a782cf68dc6414046bf225e40bf1fb3af53428794044f132c1e'
PINS = {
    'actions/checkout': 'd23441a48e516b6c34aea4fa41551a30e30af803',
    'actions/setup-node': '249970729cb0ef3589644e2896645e5dc5ba9c38',
    'supabase/setup-cli': '45a513f8c64c0bc8e0e3dfe572b5c95be85f6359',
}
EXCLUDES = ['studio', 'analytics', 'vector', 'imgproxy']


class Denied(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Denied(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def run(args, cwd=None, env=None, data=None):
    # Never relay subprocess output or exception text to public logs.
    result = subprocess.run(args, cwd=cwd, env=env, input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    need(result.returncode == 0, 'SUBPROCESS_FAILED')
    return result.stdout


def git(path, *args):
    return run(['git', '--no-optional-locks', '-C', str(path), *args])


def source(path):
    path = Path(path).resolve(strict=True)
    need(git(path, 'rev-parse', 'HEAD').decode().strip() == CANDIDATE, 'SOURCE_HEAD')
    need(git(path, 'rev-parse', 'HEAD^').decode().strip() == MAIN, 'SOURCE_PARENT')
    need(not git(path, 'status', '--porcelain=v1', '-z', '--untracked-files=all'), 'SOURCE_DIRTY')
    contracts = ROOT / 'harness/contracts'
    raw = (contracts / 'p03b-original.json').read_bytes()
    need(digest(raw) == ORIGINAL, 'ORIGINAL_MANIFEST')
    original = json.loads(raw)
    policy_raw = (contracts / 'p03d1-reviewed-policy.json').read_bytes()
    trust = read_json(contracts / 'controller-contract.json')
    need(digest(policy_raw) == trust['policy_manifest_sha256'], 'POLICY_MANIFEST')
    policy = json.loads(policy_raw)
    need(policy['pinnedMain'] == MAIN and policy['originalP03BManifestSha256'] == ORIGINAL,
         'POLICY_PROVENANCE')
    need(len(policy['changes']) == 6 and set(policy['changes']) == set(policy['testPolicyPaths']),
         'POLICY_SCOPE')
    expected = dict(original['delta'])
    for name, entry in policy['changes'].items():
        expected[name] = {'mode': 'raw-bytes', 'sha256': entry['afterSha256']}
    actual = set(git(path, 'diff', '--name-only', '-z', MAIN, CANDIDATE).decode().strip('\0').split('\0'))
    need(len(actual) == 17 and actual == set(expected), 'SOURCE_DELTA')
    for name, entry in {**expected, **original['retainedReleasedPaths']}.items():
        p = path / name
        need(p.is_file() and not p.is_symlink(), 'SOURCE_PATH_TYPE')
        data = p.read_bytes()
        if entry['mode'] == 'utf8-lf':
            data.decode('utf-8')
            data = data.replace(b'\r\n', b'\n')
        need(digest(data) == entry['sha256'], 'SOURCE_HASH')
        # The approved text mode permits CRLF in a preexisting Windows source. SQL and
        # retained raw-byte paths never receive normalization, even for comparison.
        blob = git(path, 'show', f'{CANDIDATE}:{name}')
        need(data == blob, 'SOURCE_CHECKOUT_EOL')
    migrations = read_json(contracts / 'c1-migrations.json')
    names = git(path, 'ls-tree', '-r', '--name-only', CANDIDATE, 'supabase/migrations').decode().splitlines()
    need(names == [x['path'] for x in migrations['active']], 'MIGRATION_INVENTORY')
    for entry in migrations['active']:
        need(digest((path / entry['path']).read_bytes()) == entry['raw_sha256'], 'MIGRATION_BYTES')
    print(json.dumps({'source': 'PASS', 'candidate': CANDIDATE, 'delta_paths': 17,
                      'retained_paths': 12, 'active_migrations': len(names)}))


def authorize():
    # There is deliberately no env variable, workflow input, or token bypass.
    # Network enforcement/restoration is a DESIGN, not an implemented control.
    raise Denied('EXECUTION_BLOCKED_EGRESS_UNVERIFIED_P03E2_STATIC_ONLY')


def verify_controller_revision(actual_revision, approval):
    # Pure comparison, testable with synthetic independently supplied approvals.
    # The future approval must come from outside the dispatch-controlled checkout.
    need(approval.get('approval_state') == 'INDEPENDENTLY_APPROVED'
         and type(approval.get('approved_revision')) is str
         and re.fullmatch(r'[0-9a-f]{40}', approval['approved_revision']) is not None,
         'CONTROLLER_REVISION_UNAPPROVED')
    need(approval.get('repository') == 'piotrfpn/omninauka-ci-lab'
         and actual_revision == approval['approved_revision'], 'CONTROLLER_REVISION_MISMATCH')


def controller_revision():
    approval = read_json(ROOT / 'harness/contracts/controller-revision.json')
    # Current fixture intentionally has no approved SHA. Fail before looking up Git.
    need(approval.get('approval_state') == 'INDEPENDENTLY_APPROVED', 'CONTROLLER_REVISION_UNAPPROVED')
    verify_controller_revision(git(ROOT, 'rev-parse', 'HEAD').decode().strip(), approval)
    need(not git(ROOT,'status','--porcelain=v1','-z','--untracked-files=all'),'CONTROLLER_CHECKOUT_DIRTY')
    trust_revision({'repository':os.environ.get('GITHUB_REPOSITORY'),'event':os.environ.get('GITHUB_EVENT_NAME'),
        'ref':os.environ.get('GITHUB_REF'),'ref_protected':os.environ.get('REF_PROTECTED')=='true',
        'checkout_sha':git(ROOT,'rev-parse','HEAD').decode().strip(),'github_sha':os.environ.get('GITHUB_SHA'),
        'workflow_sha':os.environ.get('EXECUTED_WORKFLOW_SHA')},
        {'origin':'INDEPENDENT_ADMIN_APPROVAL','controller_sha':os.environ.get('APPROVED_CONTROLLER_SHA'),
         'workflow_sha':os.environ.get('APPROVED_WORKFLOW_SHA')})


def minimal_env(private):
    # Child processes cannot inherit developer or runner cloud credentials.
    return {'PATH': os.environ['PATH'], 'HOME': str(private / 'home'),
            'TMPDIR': str(private / 'tmp'), 'CI': 'true', 'NO_COLOR': '1',
            'SUPABASE_TELEMETRY_DISABLED': '1'}


def local_paths():
    base = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    local = Path(os.environ['LOCAL_SUPABASE_DIR']).absolute()
    need(not local.is_symlink() and local.parent.resolve() == base, 'WORKSPACE_LOCATION')
    need(local.name == f"omni-c0-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}",
         'WORKSPACE_ID')
    for key in ('CONTROLLER_DIR', 'CANDIDATE_DIR', 'ARTIFACT_DIR'):
        other = Path(os.environ[key]).resolve()
        need(other != local and other not in local.parents and local not in other.parents,
             'WORKSPACE_OVERLAP')
    return local


def config_text(project):
    need(re.fullmatch(r'omni-c0-[0-9]+-[0-9]+', project), 'LOCAL_PROJECT_ID')
    return (ROOT / 'harness/contracts/c0-config.toml.in').read_text(encoding='utf-8').replace(
        'PROJECT_ID_PLACEHOLDER', project)


def config_check(text):
    obj = tomllib.loads(text)
    need(obj == tomllib.loads(config_text(obj.get('project_id', ''))), 'CONFIG_NONCANONICAL')
    need(obj['db']['major_version'] == 17 and not obj['db']['migrations']['enabled']
         and not obj['db']['seed']['enabled'] and obj['auth']['email']['enable_confirmations'],
         'CONFIG_SAFEGUARDS')


def prepare():
    local = local_paths()
    local.mkdir(mode=0o700, exist_ok=False)
    for name in ('supabase/migrations', 'supabase/seeds', 'private/home', 'private/tmp'):
        (local / name).mkdir(parents=True, mode=0o700, exist_ok=False)
    text = config_text(local.name)
    config_check(text)
    (local / 'supabase/config.toml').write_text(text, encoding='utf-8', newline='\n')
    (local / 'owner.json').write_text(json.dumps({'project': local.name,
        'run_id': os.environ['GITHUB_RUN_ID'], 'candidate': CANDIDATE}), encoding='utf-8')
    print('{"workspace":"PASS","migrations":0,"seeds":0}')


def safe_workspace():
    local = local_paths().resolve(strict=True)
    need(read_json(local / 'owner.json') == {'project': local.name,
         'run_id': os.environ['GITHUB_RUN_ID'], 'candidate': CANDIDATE}, 'WORKSPACE_OWNER')
    config_check((local / 'supabase/config.toml').read_text(encoding='utf-8'))
    for directory in ('migrations', 'seeds'):
        need(not list((local / 'supabase' / directory).iterdir()), 'NONEMPTY_APPLICATION_SCOPE')
    for p in local.rglob('*'):
        need(not p.is_symlink(), 'WORKSPACE_SYMLINK')
        need(not p.name.startswith('.env') and p.name != 'project-ref', 'INHERITED_CONFIG')
    return local


def resources(phase):
    from github_runtime import dispatch
    return dispatch('resources', ROOT, phase)


def start():
    from github_runtime import dispatch
    return dispatch('start', ROOT)


def c0():
    from github_runtime import dispatch
    return dispatch('c0', ROOT)


def cleanup():
    # No stop/prune/remove or firewall restoration is implemented in this static sprint.
    # Never touch preexisting Docker resources or developer files.
    raise Denied('CLEANUP_RUNTIME_NOT_TESTED_OWNERSHIP_AND_RESTORATION_REVIEW_REQUIRED')


def yaml_load(path):
    module = os.environ.get('OMNI_YAML_MODULE')
    if module:
        code = 'const fs=require("fs");const y=require(process.argv[1]);process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[2],"utf8"))));'
        return json.loads(run(['node', '-e', code, module, str(path)]))
    if shutil.which('ruby'):
        code = 'require "yaml"; require "json"; puts JSON.generate(YAML.safe_load(File.read(ARGV[0]), permitted_classes: [], aliases: false))'
        return json.loads(run(['ruby', '-e', code, str(path)]))
    raise Denied('YAML_PARSER_UNAVAILABLE')


def static():
    tree = ast.parse(Path(__file__).read_text(encoding='utf-8'))
    guard = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'authorize')
    need(len(guard.body) == 1 and isinstance(guard.body[0], ast.Raise)
         and isinstance(guard.body[0].exc, ast.Call)
         and isinstance(guard.body[0].exc.func, ast.Name) and guard.body[0].exc.func.id == 'Denied'
         and not guard.body[0].exc.keywords
         and len(guard.body[0].exc.args) == 1 and isinstance(guard.body[0].exc.args[0], ast.Constant)
         and guard.body[0].exc.args[0].value == 'EXECUTION_BLOCKED_EGRESS_UNVERIFIED_P03E2_STATIC_ONLY',
         'RUNTIME_GUARD_IMPLEMENTATION')
    runtime_tree=ast.parse((ROOT/'harness/github_runtime.py').read_text(encoding='utf-8'))
    io_class=next(n for n in runtime_tree.body if isinstance(n,ast.ClassDef) and n.name=='GitHubIO')
    io_guard=next(n for n in io_class.body if isinstance(n,ast.FunctionDef) and n.name=='guard')
    need(isinstance(io_guard.body[0],ast.ImportFrom) and io_guard.body[0].module=='security'
         and isinstance(io_guard.body[1],ast.Expr) and isinstance(io_guard.body[1].value,ast.Call)
         and isinstance(io_guard.body[1].value.func,ast.Name) and io_guard.body[1].value.func.id=='authorize',
         'FUTURE_IO_GUARD_REQUIRED')
    path = ROOT / '.github/workflows/isolated-supabase-c0.yml'
    w = yaml_load(path)
    need(w['on'] == {'workflow_dispatch': None}, 'MANUAL_TRIGGER_ONLY')
    need(w['permissions'] == {'contents': 'read'}, 'PERMISSIONS_READ_ONLY')
    need(set(w['jobs']) == {'c0'}, 'UNREVIEWED_JOB')
    job = w['jobs']['c0']
    for key,value in {'APPROVED_CONTROLLER_SHA':'${{ vars.C0_APPROVED_CONTROLLER_SHA }}',
                      'APPROVED_WORKFLOW_SHA':'${{ vars.C0_APPROVED_WORKFLOW_SHA }}',
                      'EXECUTED_WORKFLOW_SHA':'${{ github.workflow_sha }}',
                      'REF_PROTECTED':'${{ github.ref_protected }}'}.items():
        need(job.get('env',{}).get(key)==value,'INDEPENDENT_TRUST_VARIABLES_REQUIRED')
    need(job['runs-on'] == 'ubuntu-24.04' and job['timeout-minutes'] == 45, 'RUNNER_CONTRACT')
    need('environment' not in job and 'permissions' not in job and 'secrets' not in job, 'JOB_SCOPE')
    steps = job['steps']
    for step in steps:
        if 'uses' in step:
            repo, pin = step['uses'].split('@')
            need(repo in PINS and pin == PINS[repo], 'ACTION_PIN')
            need(not step.get('continue-on-error', False), 'FAIL_OPEN_STEP')
    checkouts = [s for s in steps if s.get('uses', '').startswith('actions/checkout@')]
    need(len(checkouts) == 2 and checkouts[1]['with'] == {
        'repository': 'piotrfpn/omninauka-mvp', 'ref': CANDIDATE,
        'path': 'candidate', 'fetch-depth': 0, 'persist-credentials': False, 'clean': False},
         'CANDIDATE_CHECKOUT_PIN')
    need(checkouts[0]['with'] == {'path': 'controller', 'persist-credentials': False, 'clean': False,
                                'ref':'${{ vars.C0_APPROVED_CONTROLLER_SHA }}'},
         'CONTROLLER_CHECKOUT_SCOPE')
    ids = [s.get('id') for s in steps]
    need(ids.index('controller_trust') < ids.index('static') < ids.index('blocked'), 'CONTROLLER_TRUST_ORDER')
    need(next(s for s in steps if s.get('id') == 'controller_trust')['run'] ==
         'bash controller/harness/verify-safety.sh controller', 'CONTROLLER_TRUST_GATE')
    need(ids.index('blocked') < ids.index('candidate') < ids.index('cli'), 'GATE_ORDER')
    need(steps[0].get('id') == 'bootstrap' and steps[0]['run'] == BOOTSTRAP
         and 'if' not in steps[0] and not steps[0].get('continue-on-error',False), 'EXTERNAL_BOOTSTRAP_REQUIRED')
    need(steps[1]['run'] == 'git config --global core.autocrlf false\ngit config --global core.eol lf\n',
         'BYTE_PRESERVING_CHECKOUT')
    for ident in ('shellcheck','actionlint'):
        lint_step = next(s for s in steps if s.get('id') == ident)
        need(ids.index('blocked') < ids.index(ident) < ids.index('cli')
             and lint_step.get('run') == 'bash controller/harness/verify-safety.sh '+ident
             and 'if' not in lint_step and not lint_step.get('continue-on-error',False), 'MANDATORY_CI_LINT')
    need(ids.index('cli') < ids.index('network'), 'NETWORK_PREPARATION_ORDER')
    need(next(s for s in steps if s.get('id') == 'blocked')['run'] ==
         'bash controller/harness/verify-safety.sh authorize', 'EXECUTION_GATE')
    for ident in ('controller_trust','blocked'):
        step = next(s for s in steps if s.get('id') == ident)
        need('if' not in step and not step.get('continue-on-error', False), 'MANDATORY_GUARD')
    cleanup_steps = [s for s in steps if s.get('run') == 'bash controller/harness/verify-cleanup.sh']
    need(len(cleanup_steps) == 1 and cleanup_steps[0].get('if') == '${{ always() }}'
         and not cleanup_steps[0].get('continue-on-error', False), 'CLEANUP_LIFECYCLE')
    need(next(s for s in steps if s.get('id') == 'cli')['with'] == {'version': '2.108.0'}, 'CLI_PIN')
    need(next(s for s in steps if s.get('id') == 'node')['with'] == {'node-version': '24.13.0'}, 'NODE_PIN')
    for step in steps:
        if 'run' in step and step is not steps[0] and step is not steps[1]:
            need(re.fullmatch(r'bash controller/harness/[a-z0-9-]+\.sh(?: [a-z]+)?', step['run']) is not None,
                 'WORKFLOW_UNREVIEWED_COMMAND')
            need((ROOT / step['run'].split()[1].removeprefix('controller/')).is_file(), 'MISSING_SCRIPT')
    need('upload-artifact' not in path.read_text(), 'ARTIFACT_UPLOAD_NOT_AUTHORIZED')
    config_check(config_text('omni-c0-123-1'))
    # Executable input scan. Documentation/evidence may name forbidden operations as warnings.
    paths = list((ROOT / 'harness').rglob('*.sh')) + list((ROOT / 'harness').rglob('*.py')) + [path]
    forbidden = [r'\b(?:vercel|netlify)\s+(?:deploy|--prod)', r'\bsupabase\s+(?:link|db\s+push|migration\s+up)',
                 r'\b(?:curl|wget)\s+[^\n]*https?://', r'\bset\s+-[^\n]*x\b',
                 r'\b(?:rm\s+-rf|docker\s+system\s+prune)\b', r'\$\{\{\s*secrets\.',
                 r'\b[a-z]{20}\.supabase\.co\b', r'\bproject_ref\s*=\s*["\'][a-z]{20}',
                 r'\becho\s+.*(?:SERVICE_ROLE|JWT_SECRET|SUPABASE_.*KEY)',
                 r'\bprint\(\s*(?:os\.environ|env|result\.stdout)\s*\)']
    for p in paths:
        if p.name == 'security.py':
            # Exclude only this literal list of regex patterns, not executable statements.
            text = p.read_text(encoding='utf-8').split('    forbidden = [', 1)
            text = text[0] + text[1].split('    for p in paths:', 1)[1] if len(text) == 2 else text[0]
        else:
            text = p.read_text(encoding='utf-8')
        need(not any(re.search(pattern, text, re.I) for pattern in forbidden), 'FORBIDDEN_EXECUTABLE_INPUT')
    sql = (ROOT / 'harness/sql/c0-readonly.sql').read_text()
    need(sql.startswith('BEGIN READ ONLY;') and sql.rstrip().endswith('ROLLBACK;'), 'SQL_READ_ONLY')
    sql_statements = re.sub(r"'(?:[^']|'')*'", "''", sql)
    need(not re.search(r'\b(CREATE|ALTER|DROP|INSERT|UPDATE|DELETE|GRANT|REVOKE|COPY|CALL|DO)\b', sql_statements, re.I),
         'C0_SQL_MUTATION')
    need('server_version_num' in sql and 'pg_available_extensions' in sql and 'cron.database_name' in sql,
         'SQL_PREFLIGHT_SCOPE')
    contract = read_json(ROOT / 'harness/contracts/controller-contract.json')
    need(contract['candidate'] == CANDIDATE and contract['main'] == MAIN
         and contract['execution_authorized'] is False and contract['egress_status'] == 'EGRESS_UNVERIFIED',
         'CONTROLLER_FAIL_CLOSED')
    need(contract['excluded_services'] == EXCLUDES, 'CLI_EXCLUSION_ALIASES')
    from github_lint import ACTIONLINT_VERSION, ACTIONLINT_SHA, ACTIONLINT_URL
    runtime=contract['github_runtime']
    need(runtime['actionlint']['version']==ACTIONLINT_VERSION and runtime['actionlint']['sha256']==ACTIONLINT_SHA
         and runtime['actionlint']['url']==ACTIONLINT_URL,'ACTIONLINT_PROVENANCE_BLOCKED')
    need(runtime['shellcheck']['mandatory'] is True and runtime['shellcheck']['severity']=='style'
         and runtime['actionlint']['mandatory'] is True,'MANDATORY_CI_LINT')
    need(runtime['executor_image'] is None and runtime['approved_images'] is None and runtime['probe_targets'] is None
         and runtime['cli_internal_cleanup_reviewed'] is False,'RUNTIME_NOT_SELF_APPROVED')
    approval = read_json(ROOT / 'harness/contracts/controller-revision.json')
    need(approval['approval_state'] == 'UNAPPROVED' and approval['approved_revision'] is None
         and approval['repository'] == 'piotrfpn/omninauka-ci-lab' and approval['execution'] == 'BLOCKED',
         'CONTROLLER_APPROVAL_NOT_GRANTED')
    policy = read_json(ROOT / 'harness/contracts/c0-assertions.json')
    targets = re.findall(r"\('(public|managed_child_private)','([a-z0-9_]+)'\)", sql)
    need(len(targets) == 15 and {a + '.' + b for a,b in targets} == set(policy['application_tables']), 'C0_APPLICATION_INVENTORY')
    need('query_to_xml' in sql and 'migration_row_count' in sql and 'migration_schema_exists' in sql,
         'C0_MIGRATION_HISTORY_PROBE')
    matrix = read_json(ROOT / 'harness/contracts/c0-matrix.json')
    need([x['id'] for x in matrix] == [f'C0-{n:02}' for n in range(1, 22)], 'C0_MATRIX_INCOMPLETE')
    need(all(x['status'] == 'NOT_TESTED' for x in matrix[:-1]) and matrix[-1]['status'] == 'NOT_EXECUTED',
         'RUNTIME_FALSE_PASS')
    for p in paths:
        if p.suffix == '.sh':
            need('set -euo pipefail' in p.read_text() and 'umask 077' in p.read_text(), 'SHELL_SAFETY')
    print(json.dumps({'static': 'PASS', 'yaml': 'PASS', 'manual_only': 'PASS',
        'permissions': 'contents:read', 'candidate_pin': CANDIDATE, 'runtime': 'BLOCKED'}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['static', 'source', 'controller', 'evaluate', 'authorize', 'prepare', 'resources', 'start', 'c0', 'cleanup','network','shellcheck','actionlint'])
    parser.add_argument('argument', nargs='?')
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == 'static':
        static()
    elif args.command == 'source':
        source(args.argument or os.environ['CANDIDATE_DIR'])
    elif args.command == 'controller':
        controller_revision()
    elif args.command == 'evaluate':
        # Offline JSON only. Does not call SQL or authorize runtime execution.
        need(args.argument is not None, 'RESULT_FILE_REQUIRED')
        print(json.dumps(evaluate_jsonl(Path(args.argument).read_text(encoding='utf-8'))))
    else:
        authorize()  # Must precede ALL runtime access, resource queries and filesystem creation.
        controller_revision()
        if args.command in ('shellcheck','actionlint'):
            from github_lint import ci_lint
            ci_lint(args.command,ROOT)
        elif args.command in ('network','cleanup'):
            from github_runtime import dispatch
            dispatch(args.command,ROOT,args.argument)
        else:
            {'prepare': prepare, 'resources': lambda: resources(args.argument or 'before'),
             'start': start, 'c0': c0}[args.command]()


if __name__ == '__main__':
    try:
        main()
    except (Denied, InvalidResult, ReadinessError) as error:
        print(json.dumps({'status': 'BLOCKED' if 'BLOCKED' in str(error) else 'FAIL', 'code': str(error)}))
        sys.exit(2)
    except Exception:
        # Do not expose exception text: it might contain a subprocess output or credential path.
        print('{"status":"FAIL","code":"UNEXPECTED_ERROR_DETAILS_WITHHELD"}')
        sys.exit(3)
