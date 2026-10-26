"""Mandatory future GitHub lint gates; no installation or execution on import."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.parse
import urllib.request

from github_runtime import GitHubIO, ReadinessError, project_id, require, BOOTSTRAP

ACTIONLINT_VERSION = '1.7.7'
ACTIONLINT_SHA = '023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757'
ACTIONLINT_URL = 'https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_linux_amd64.tar.gz'
SCRIPTS = ('prepare-local-config.sh','verify-safety.sh','verify-resources.sh','start-platform.sh',
           'verify-c0.sh','verify-cleanup.sh','validate-static.sh')


def lint_exit(code):
    require(type(code) is int and code==0,'MANDATORY_LINT_FAILED')


def artifact_bytes(blob, expected_sha):
    require(type(expected_sha) is str and re.fullmatch('[0-9a-f]{64}',expected_sha), 'ACTIONLINT_PROVENANCE_BLOCKED')
    require(type(blob) is bytes and len(blob) <= 40*1024**2
            and hashlib.sha256(blob).hexdigest() == expected_sha, 'ACTIONLINT_CHECKSUM_FAILED')
    with tarfile.open(fileobj=io.BytesIO(blob),mode='r:gz') as archive:
        matches=[x for x in archive.getmembers() if x.name=='actionlint']
        require(len(matches)==1 and matches[0].isfile() and not matches[0].issym()
                and 0 < matches[0].size <= 32*1024**2, 'ACTIONLINT_ARCHIVE_INVALID')
        stream=archive.extractfile(matches[0])
        require(stream is not None,'ACTIONLINT_ARCHIVE_INVALID')
        return stream.read()


def shellcheck_arguments(root, executable, bootstrap_file):
    require(executable is not None,'SHELLCHECK_MISSING')
    scripts=[Path(root)/'harness'/name for name in SCRIPTS]
    require(all(p.is_file() and not p.is_symlink() for p in scripts) and Path(bootstrap_file).is_file(), 'LINT_SCRIPT_MISSING')
    return [str(executable),'--norc','--shell=bash','--severity=style',*[str(x) for x in scripts],str(bootstrap_file)]


def ci_lint(kind, root):
    GitHubIO.guard()  # Hard authorization block BEFORE tool lookup, FS or download.
    os.umask(0o077)
    project=project_id(os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'])
    private=Path(os.environ['RUNNER_TEMP'])/(project+'-lint')
    require(not private.is_symlink(),'LINT_WORKSPACE_INVALID')
    private.mkdir(mode=0o700,exist_ok=True)
    require(private.stat().st_uid==os.getuid() and private.stat().st_mode & 0o077 == 0,'LINT_PERMISSIONS_INVALID')
    env={'PATH':os.environ['PATH'],'HOME':str(private),'NO_COLOR':'1'}

    def execute(argv, label):
        GitHubIO.guard()
        with (private/(label+'.out')).open('xb') as out, (private/(label+'.err')).open('xb') as err:
            p=subprocess.run(argv,env=env,stdout=out,stderr=err,timeout=120,check=False)
        lint_exit(p.returncode)
        return (private/(label+'.out')).read_text(encoding='utf-8')

    if kind=='shellcheck':
        binary=shutil.which('shellcheck')
        require(binary is not None and Path(binary).is_file() and os.access(binary,os.X_OK),'SHELLCHECK_MISSING')
        version=execute([binary,'--version'],'shellcheck-version')
        match=re.search(r'version:\s*([0-9.]+)',version)
        require(match is not None,'SHELLCHECK_VERSION_UNVERIFIED')
        inline=private/'bootstrap.sh'
        inline.write_text('#!/usr/bin/env bash\n'+BOOTSTRAP,encoding='utf-8',newline='\n')
        execute(shellcheck_arguments(root,binary,inline),'shellcheck')
        data={'tool':'ShellCheck','version':match[1],'severity':'style','status':'PASS',
              'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest()}
    else:
        require(kind=='actionlint','LINT_KIND_UNKNOWN')
        policy=json.loads((Path(root)/'harness/contracts/controller-contract.json').read_bytes())['github_runtime']['actionlint']
        require(policy['version']==ACTIONLINT_VERSION and policy['sha256']==ACTIONLINT_SHA
                and policy['url']==ACTIONLINT_URL,'ACTIONLINT_PROVENANCE_BLOCKED')
        GitHubIO.guard()
        with urllib.request.urlopen(ACTIONLINT_URL,timeout=60) as response:
            address=urllib.parse.urlparse(response.geturl())
            require(address.scheme=='https' and address.hostname in ('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'), 'ACTIONLINT_REDIRECT_UNREVIEWED')
            blob=response.read(40*1024**2+1)
        raw=artifact_bytes(blob,ACTIONLINT_SHA)
        binary=private/'actionlint'
        with binary.open('xb') as handle:
            handle.write(raw)
        binary.chmod(0o700)
        version=execute([str(binary),'-version'],'actionlint-version')
        require(version.splitlines()[0].strip()==ACTIONLINT_VERSION,'ACTIONLINT_VERSION_UNVERIFIED')
        execute([str(binary),str(Path(root)/'.github/workflows/isolated-supabase-c0.yml')],'actionlint')
        data={'tool':'actionlint','version':ACTIONLINT_VERSION,'status':'PASS','archive_sha256':ACTIONLINT_SHA}
    data['origin']='GITHUB_RUNTIME'
    data['controller_sha']=os.environ.get('GITHUB_SHA')
    data['workflow_sha']=os.environ.get('EXECUTED_WORKFLOW_SHA')
    # Private structured receipt, never raw stdout/stderr in public output.
    (private/(kind+'-receipt.json')).write_text(json.dumps(data),encoding='utf-8')
    print(json.dumps(data))
