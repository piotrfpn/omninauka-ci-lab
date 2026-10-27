"""Static-only GitHub path. Does not grant or call any C0 runtime operation.

Import is offline/pure. Actual lint acquisition/execution requires an independently
approved workflow/controller and tool hashes on the future GitHub Ubuntu runner.
The hosted OS and external administration remain trust prerequisites, not a sandbox.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
from github_lint import ACTIONLINT_SHA, ACTIONLINT_URL, ACTIONLINT_VERSION, SCRIPTS, artifact_bytes
from github_runtime import ReadinessError, require

REPOSITORY = 'piotrfpn/omninauka-ci-lab'
WORKFLOW = '.github/workflows/static-controller-preflight.yml'
DISCOVERY_WORKFLOW = '.github/workflows/static-toolchain-discovery.yml'
LINT_WORKFLOWS = ('.github/workflows/isolated-supabase-c0.yml', WORKFLOW, DISCOVERY_WORKFLOW)
CHECKOUT = 'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803'
TOOLS = {'PYTHON':'/usr/bin/python3','RUBY':'/usr/bin/ruby','SHELLCHECK':'/usr/bin/shellcheck'}
BOOTSTRAP = r'''set -euo pipefail
umask 077
[[ "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]]
[[ "$GITHUB_REPOSITORY" == "piotrfpn/omninauka-ci-lab" ]]
[[ "$GITHUB_REF" == "refs/heads/main" ]]
[[ "$GITHUB_WORKFLOW_REF" == "piotrfpn/omninauka-ci-lab/.github/workflows/static-controller-preflight.yml@refs/heads/main" ]]
[[ "$STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$STATIC_PREFLIGHT_APPROVED_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$GITHUB_SHA" == "$STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA" ]]
[[ "$EXECUTED_WORKFLOW_SHA" == "$STATIC_PREFLIGHT_APPROVED_WORKFLOW_SHA" ]]
[[ "$REF_PROTECTED" == "true" ]]
[[ "$RUNNER_ENVIRONMENT" == "github-hosted" && "$RUNNER_OS" == "Linux" && "$RUNNER_ARCH" == "X64" ]]
# shellcheck source=/dev/null
. /etc/os-release
[[ "$ID" == "ubuntu" && "$VERSION_ID" == "24.04" ]]
for tool in PYTHON RUBY SHELLCHECK; do
  version_key="STATIC_${tool}_VERSION"
  hash_key="STATIC_${tool}_SHA256"
  [[ "${!version_key}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
  [[ "${!hash_key}" =~ ^[0-9a-f]{64}$ ]]
  binary="${tool,,}"
  if [[ "$tool" == "PYTHON" ]]; then binary=python3; fi
  actual="$(sha256sum "/usr/bin/$binary")"
  [[ "${actual%% *}" == "${!hash_key}" ]]
done
'''


def workflow_contract():
    env = {key:'${{ vars.'+key+' }}' for key in (
        'STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA','STATIC_PREFLIGHT_APPROVED_WORKFLOW_SHA',
        *('STATIC_'+tool+'_'+field for tool in TOOLS for field in ('VERSION','SHA256')))}
    env.update(EXECUTED_WORKFLOW_SHA='${{ github.workflow_sha }}',REF_PROTECTED='${{ github.ref_protected }}',
               PYTHONDONTWRITEBYTECODE='1',PYTHONPATH='',PYTHONHOME='',BASH_ENV='',ENV='',RUBYOPT='',RUBYLIB='',
               OMNI_YAML_MODULE='')
    return {'name':'Static controller preflight — NO runtime','on':{'workflow_dispatch':None},
        'permissions':{'contents':'read'},'concurrency':{'group':'static-controller-preflight','cancel-in-progress':False},
        'jobs':{'static':{'runs-on':'ubuntu-24.04','timeout-minutes':15,
            'defaults':{'run':{'shell':'bash --noprofile --norc -euo pipefail {0}'}},'env':env,
            'steps':[{'id':'bootstrap','name':'External STATIC approval and tool integrity BEFORE checkout','run':BOOTSTRAP},
                     {'name':'Preserve source bytes','run':'git config --global core.autocrlf false\ngit config --global core.eol lf\n'},
                     {'name':'Checkout independently approved controller only','uses':CHECKOUT,
                      'with':{'path':'controller','ref':'${{ vars.STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA }}',
                              'persist-credentials':False,'clean':False}},
                     {'name':'Mandatory static lint, tests and policy — no runtime',
                      'run':'/usr/bin/python3 -B controller/harness/static_preflight.py'}]}}}


def validate_workflow(document):
    require(document == workflow_contract(), 'STATIC_WORKFLOW_CONTRACT_MISMATCH')


def validate_context(env, system, release, machine):
    require(system == 'linux' and release.get('ID') == 'ubuntu' and release.get('VERSION_ID') == '24.04'
            and machine == 'x86_64' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('RUNNER_OS') == 'Linux' and env.get('RUNNER_ARCH') == 'X64', 'STATIC_RUNNER_UNVERIFIED')
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and env.get('GITHUB_REPOSITORY') == REPOSITORY
            and env.get('GITHUB_REF') == 'refs/heads/main' and env.get('REF_PROTECTED') == 'true'
            and env.get('GITHUB_WORKFLOW_REF') == REPOSITORY+'/'+WORKFLOW+'@refs/heads/main', 'STATIC_DISPATCH_UNTRUSTED')
    for approval, observed in (('STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA','GITHUB_SHA'),
                               ('STATIC_PREFLIGHT_APPROVED_WORKFLOW_SHA','EXECUTED_WORKFLOW_SHA')):
        require(type(env.get(approval)) is str and re.fullmatch('[0-9a-f]{40}',env[approval])
                and env.get(observed) == env[approval], 'STATIC_EXTERNAL_APPROVAL_MISSING_OR_MISMATCHED')
    for tool in TOOLS:
        require(type(env.get('STATIC_'+tool+'_VERSION')) is str
                and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',env['STATIC_'+tool+'_VERSION'])
                and type(env.get('STATIC_'+tool+'_SHA256')) is str
                and re.fullmatch('[0-9a-f]{64}',env['STATIC_'+tool+'_SHA256']), 'STATIC_TOOL_APPROVAL_MISSING')
    require(all(not env.get(k) for k in ('PYTHONPATH','PYTHONHOME','BASH_ENV','ENV','RUBYOPT','RUBYLIB','OMNI_YAML_MODULE')),
            'STATIC_INTERPRETER_HOOK_FORBIDDEN')


def require_runner():
    require(sys.platform == 'linux', 'STATIC_RUNNER_UNVERIFIED')  # Before FS/download/tool lookup on Windows.
    release = dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    validate_context(os.environ,sys.platform,{k:v.strip('"') for k,v in release.items()},os.uname().machine)


def verify_tool_bytes(data, expected):
    require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected)
            and hashlib.sha256(data).hexdigest() == expected, 'STATIC_TOOL_HASH_MISMATCH')


def check_guard(root):
    tree = ast.parse((Path(root)/'harness/security.py').read_text(encoding='utf-8'))
    guard = next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name == 'authorize')
    require(len(guard.body) == 1 and isinstance(guard.body[0],ast.Raise)
            and isinstance(guard.body[0].exc,ast.Call) and isinstance(guard.body[0].exc.func,ast.Name)
            and guard.body[0].exc.func.id == 'Denied' and len(guard.body[0].exc.args) == 1
            and not guard.body[0].exc.keywords
            and isinstance(guard.body[0].exc.args[0],ast.Constant)
            and guard.body[0].exc.args[0].value == 'EXECUTION_BLOCKED_EGRESS_UNVERIFIED_P03E2_STATIC_ONLY',
            'STATIC_RUNTIME_GUARD_CHANGED')
    from security import authorize, Denied
    try:
        authorize()
    except Denied as error:
        require(str(error) == 'EXECUTION_BLOCKED_EGRESS_UNVERIFIED_P03E2_STATIC_ONLY','STATIC_RUNTIME_GUARD_CHANGED')
    else:
        raise ReadinessError('STATIC_RUNTIME_GUARD_CHANGED')


class VerifiedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(newurl)
        require(target.scheme == 'https' and target.hostname in
                ('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'),
                'STATIC_TOOL_REDIRECT_UNREVIEWED')
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def actionlint_bytes():
    require_runner()
    opener = urllib.request.build_opener(VerifiedRedirect())
    with opener.open(ACTIONLINT_URL,timeout=20) as response:
        blob = response.read(40*1024**2+1)
    return artifact_bytes(blob,ACTIONLINT_SHA)  # Fixed reviewed archive digest, before extraction/execution.


def workflow_inlines(root):
    from security import yaml_load
    inlines = []
    for workflow in LINT_WORKFLOWS:
        for job in yaml_load(Path(root)/workflow)['jobs'].values():
            for step in job['steps']:
                if 'run' not in step:
                    continue
                script = step['run']
                if workflow == DISCOVERY_WORKFLOW:
                    # Preserve the workflow bytes. Annotate only the generated lint copy:
                    # dpkg-query, not Bash, expands these literal package fields.
                    literal = r'''metadata="$(/usr/bin/dpkg-query --show --showformat='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n' "$owner" 2>/dev/null)" || deny'''
                    lines = script.splitlines(keepends=True)
                    matches = [i for i,line in enumerate(lines) if line.strip() == literal]
                    require(len(matches) == 1, 'STATIC_DISCOVERY_LINT_INPUT_CHANGED')
                    index = matches[0]
                    indent = lines[index][:len(lines[index])-len(lines[index].lstrip())]
                    lines.insert(index, indent+'# shellcheck disable=SC2016\n')
                    script = ''.join(lines)
                inlines.append(script)
    return inlines


def command_plan(root, private, inlines):
    root, private = Path(root), Path(private)
    python = TOOLS['PYTHON']
    return {'shellcheck-version':[TOOLS['SHELLCHECK'],'--version'], 'ruby-version':[TOOLS['RUBY'],'--version'],
        'actionlint-version':[str(private/'actionlint'),'-version'],
        'shellcheck':[TOOLS['SHELLCHECK'],'--norc','--shell=bash','--severity=style',
                      *[str(root/'harness'/name) for name in SCRIPTS],*[str(x) for x in inlines]],
        'actionlint':[str(private/'actionlint'),'-shellcheck=','-pyflakes=',
                      *[str(root/workflow) for workflow in LINT_WORKFLOWS]],
        'python-tests':[python,'-B','-m','unittest','discover','-s','harness/tests','-p','test_*.py','-v'],
        'static-policy':[python,'-B','harness/security.py','static'],
        **{'bash-syntax-'+str(i):['/usr/bin/bash','--noprofile','--norc','-n',str(p)]
           for i,p in enumerate([*[root/'harness'/name for name in SCRIPTS],*inlines])}}


def execute_stage(label, plan, root, private, env):
    expected = command_plan(root,private,env['_inlines'])
    require(label in plan and label in expected, 'STATIC_COMMAND_NOT_ALLOWED')
    argv = plan[label]
    require(argv == expected[label], 'STATIC_COMMAND_NOT_ALLOWED')
    child = {'PATH':'/usr/bin:/bin','HOME':str(private),'TMPDIR':str(private),'LC_ALL':'C.UTF-8',
             'PYTHONDONTWRITEBYTECODE':'1','CI':'true','NO_COLOR':'1'}
    with (private/(label+'.out')).open('xb') as out, (private/(label+'.err')).open('xb') as err:
        result = subprocess.run(argv,cwd=root,env=child,stdout=out,stderr=err,timeout=180,check=False)
    require(type(result.returncode) is int and result.returncode == 0,'STATIC_CHECK_FAILED_'+label.upper())
    return (private/(label+'.out')).read_text(encoding='utf-8')


def main():
    require_runner()
    require(len(sys.argv) == 1,'STATIC_ARGUMENTS_FORBIDDEN')
    os.environ['PATH'] = '/usr/bin:/bin'  # yaml_load must select the verified system Ruby.
    root = Path(__file__).resolve().parents[1]
    for tool, name in TOOLS.items():
        path = Path(name).resolve(strict=True)
        require(path.is_file() and path.stat().st_uid == 0 and path.stat().st_mode & 0o022 == 0,
                'STATIC_TOOL_PATH_UNTRUSTED')
        verify_tool_bytes(path.read_bytes(),os.environ['STATIC_'+tool+'_SHA256'])
    require(sys.version.split()[0] == os.environ['STATIC_PYTHON_VERSION'] and sys.version_info >= (3,11),
            'STATIC_PYTHON_VERSION_MISMATCH')
    child = {'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'}
    def git(*args):
        p = subprocess.run(['/usr/bin/git','--no-optional-locks','-C',str(root),*args],env=child,
                           capture_output=True,timeout=30,check=False)
        require(p.returncode == 0,'STATIC_CHECKOUT_UNVERIFIED')
        return p.stdout.decode().strip()
    require(git('rev-parse','HEAD') == os.environ['STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA']
            and not git('status','--porcelain=v1','--untracked-files=all'),'STATIC_CHECKOUT_UNVERIFIED')
    from security import yaml_load
    validate_workflow(yaml_load(root/WORKFLOW))
    check_guard(root)
    for path in (root/'harness').rglob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'))
    for path in (root/'harness').rglob('*.json'):
        json.loads(path.read_bytes())
    tomllib.loads((root/'harness/contracts/c0-config.toml.in').read_text(encoding='utf-8'))
    os.umask(0o077)
    base = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    run, attempt = os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT']
    require(re.fullmatch('[1-9][0-9]{0,19}',run) and re.fullmatch('[1-9][0-9]{0,9}',attempt),'STATIC_RUN_ID_INVALID')
    private = base/('static-preflight-'+run+'-'+attempt)
    require(not private.is_symlink(),'STATIC_PRIVATE_SCOPE_INVALID')
    private.mkdir(mode=0o700,exist_ok=False)
    inlines = []
    for script in workflow_inlines(root):
        path = private/('inline-'+str(len(inlines))+'.sh')
        path.write_text('#!/usr/bin/env bash\n'+script+'\n',encoding='utf-8')
        inlines.append(path)
    plan = command_plan(root,private,inlines)
    def run_stage(label):return execute_stage(label,plan,root,private,{'_inlines':inlines})
    for tool,label,pattern in (('RUBY','ruby-version',r'^ruby ([0-9]+\.[0-9]+\.[0-9]+)'),
                               ('SHELLCHECK','shellcheck-version',r'version:\s*([0-9]+\.[0-9]+\.[0-9]+)')):
        match = re.search(pattern,run_stage(label))
        require(match is not None and match[1] == os.environ['STATIC_'+tool+'_VERSION'],'STATIC_TOOL_VERSION_MISMATCH')
    raw = actionlint_bytes()
    binary = private/'actionlint'
    with binary.open('xb') as handle:handle.write(raw)
    binary.chmod(0o700)
    require(run_stage('actionlint-version').splitlines()[0].strip() == ACTIONLINT_VERSION,'STATIC_TOOL_VERSION_MISMATCH')
    for label in ('shellcheck','actionlint','static-policy','python-tests',
                  *[x for x in plan if x.startswith('bash-syntax-')]):run_stage(label)
    check_guard(root)
    require(not git('status','--porcelain=v1','--untracked-files=all'),'STATIC_SOURCE_CHANGED')
    print(json.dumps({'status':'STATIC_PREFLIGHT_EXECUTED_PASS','controller_sha':os.environ['GITHUB_SHA'],
        'workflow_sha':os.environ['EXECUTED_WORKFLOW_SHA'],'actionlint_version':ACTIONLINT_VERSION,
        'actionlint_archive_sha256':ACTIONLINT_SHA,'tools':{t:{'version':os.environ['STATIC_'+t+'_VERSION'],
        'sha256':os.environ['STATIC_'+t+'_SHA256']} for t in TOOLS},'c0_runtime_approved':False,
        'runtime':'GITHUB_RUNTIME_NOT_EXECUTED','sql':'SQL_NOT_EXECUTED','cleanup':'CLEANUP_NOT_EXECUTED'}))


if __name__ == '__main__':
    try:
        main()
    except ReadinessError as error:
        print(json.dumps({'status':'STATIC_PREFLIGHT_FAILED','code':str(error),'c0_runtime_approved':False}))
        sys.exit(2)
    except Exception:
        print('{"status":"STATIC_PREFLIGHT_FAILED","code":"DETAILS_WITHHELD","c0_runtime_approved":false}')
        sys.exit(3)
