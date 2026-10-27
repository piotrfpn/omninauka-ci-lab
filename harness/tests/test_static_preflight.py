"""Offline contracts only: synthetic context is never hosted execution evidence."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import static_preflight as preflight
from security import Denied, authorize, yaml_load
from github_runtime import ReadinessError

ROOT = Path(__file__).resolve().parents[2]


def synthetic_context():
    env = {'RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','RUNNER_ARCH':'X64',
        'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':preflight.REPOSITORY,
        'GITHUB_REF':'refs/heads/main','REF_PROTECTED':'true',
        'GITHUB_WORKFLOW_REF':preflight.REPOSITORY+'/'+preflight.WORKFLOW+'@refs/heads/main',
        'GITHUB_SHA':'a'*40,'STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA':'a'*40,
        'EXECUTED_WORKFLOW_SHA':'b'*40,'STATIC_PREFLIGHT_APPROVED_WORKFLOW_SHA':'b'*40}
    for tool in preflight.TOOLS:
        env['STATIC_'+tool+'_VERSION'] = '0.0.0'
        env['STATIC_'+tool+'_SHA256'] = '0'*64
    return env


def context_check(env):
    return preflight.validate_context(env,'linux',{'ID':'ubuntu','VERSION_ID':'24.04'},'x86_64')


class StaticPreflightTests(unittest.TestCase):
    def test_actual_workflow_matches_reviewable_contract(self):
        preflight.validate_workflow(yaml_load(ROOT/preflight.WORKFLOW))

    def test_workflow_mutations_fail_from_passing_baseline(self):
        baseline = yaml_load(ROOT/preflight.WORKFLOW)
        preflight.validate_workflow(baseline)
        mutations = []
        def mutate(name, change):
            value = copy.deepcopy(baseline)
            change(value)
            mutations.append((name,value))
        mutate('automatic trigger',lambda w:w.update(on={'push':None}))
        mutate('dispatch input',lambda w:w['on'].update(workflow_dispatch={'inputs':{'sha':{'type':'string'}}}))
        mutate('write token',lambda w:w.update(permissions={'contents':'write'}))
        mutate('job permission override',lambda w:w['jobs']['static'].update(permissions={'contents':'write'}))
        mutate('self hosted',lambda w:w['jobs']['static'].update({'runs-on':'self-hosted'}))
        mutate('services',lambda w:w['jobs']['static'].update(services={'db':{'image':'postgres'}}))
        mutate('container',lambda w:w['jobs']['static'].update(container='ubuntu'))
        mutate('skip bootstrap',lambda w:w['jobs']['static']['steps'][0].update({'if':'${{ false }}'}))
        mutate('fail open',lambda w:w['jobs']['static']['steps'][0].update({'continue-on-error':True}))
        mutate('floating action',lambda w:w['jobs']['static']['steps'][2].update(uses='actions/checkout@main'))
        mutate('self approved checkout',lambda w:w['jobs']['static']['steps'][2]['with'].update(ref='${{ github.sha }}'))
        mutate('candidate checkout',lambda w:w['jobs']['static']['steps'][2]['with'].update(repository='piotrfpn/omninauka-mvp'))
        mutate('persist token',lambda w:w['jobs']['static']['steps'][2]['with'].update({'persist-credentials':True}))
        mutate('self approved controller',lambda w:w['jobs']['static']['env'].update(STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA='${{ github.sha }}'))
        mutate('self approved workflow',lambda w:w['jobs']['static']['env'].update(STATIC_PREFLIGHT_APPROVED_WORKFLOW_SHA='${{ github.workflow_sha }}'))
        mutate('omit tool approval',lambda w:w['jobs']['static']['env'].pop('STATIC_SHELLCHECK_SHA256'))
        mutate('skip mandatory lint',lambda w:w['jobs']['static']['steps'][-1].update({'if':'${{ false }}'}))
        mutate('ignored mandatory lint',lambda w:w['jobs']['static']['steps'][-1].update({'continue-on-error':True}))
        mutate('cleanup step',lambda w:w['jobs']['static']['steps'].append({'if':'${{ always() }}','run':'bash controller/harness/verify-cleanup.sh'}))
        mutate('runtime step',lambda w:w['jobs']['static']['steps'].append({'run':'docker version'}))
        mutate('nested workflow',lambda w:w['jobs'].update(extra={'uses':'./.github/workflows/isolated-supabase-c0.yml'}))
        for name,value in mutations:
            with self.subTest(mutation=name), self.assertRaisesRegex(ReadinessError,'STATIC_WORKFLOW_CONTRACT_MISMATCH'):
                preflight.validate_workflow(value)

    def test_external_context_comparison_does_not_authorize_runtime(self):
        self.assertIsNone(context_check(synthetic_context()))
        with self.assertRaisesRegex(Denied,'EXECUTION_BLOCKED'):
            authorize()

    def test_missing_or_mismatched_approval_fails(self):
        baseline = synthetic_context()
        context_check(baseline)
        for key in ('STATIC_PREFLIGHT_APPROVED_CONTROLLER_SHA','STATIC_PREFLIGHT_APPROVED_WORKFLOW_SHA',
                    'GITHUB_SHA','EXECUTED_WORKFLOW_SHA'):
            for value in (None,'', 'c'*40,'UNAPPROVED'):
                env = dict(baseline);env[key] = value
                with self.subTest(key=key,value=value), self.assertRaises(ReadinessError):
                    context_check(env)

    def test_untrusted_context_mutations_fail(self):
        baseline = synthetic_context()
        context_check(baseline)
        for key,value in {'RUNNER_ENVIRONMENT':'self-hosted','RUNNER_OS':'Windows','RUNNER_ARCH':'ARM64',
            'GITHUB_EVENT_NAME':'pull_request','GITHUB_REPOSITORY':'foreign/controller',
            'GITHUB_REF':'refs/heads/candidate','REF_PROTECTED':'false',
            'GITHUB_WORKFLOW_REF':'foreign/workflow@refs/heads/main'}.items():
            env = dict(baseline);env[key] = value
            with self.subTest(key=key), self.assertRaises(ReadinessError):context_check(env)

    def test_wrong_system_release_or_machine_fails(self):
        context_check(synthetic_context())
        for system,release,machine in (
            ('win32',{'ID':'ubuntu','VERSION_ID':'24.04'},'x86_64'),
            ('linux',{'ID':'ubuntu','VERSION_ID':'22.04'},'x86_64'),
            ('linux',{'ID':'debian','VERSION_ID':'24.04'},'x86_64'),
            ('linux',{'ID':'ubuntu','VERSION_ID':'24.04'},'aarch64')):
            with self.subTest(system=system,release=release,machine=machine), self.assertRaises(ReadinessError):
                preflight.validate_context(synthetic_context(),system,release,machine)

    def test_no_observed_tool_can_approve_itself(self):
        baseline = synthetic_context()
        context_check(baseline)
        for tool in preflight.TOOLS:
            for field,value in (('VERSION',None),('VERSION','latest'),('SHA256',None),('SHA256','not-reviewed')):
                env = dict(baseline);env['STATIC_'+tool+'_'+field] = value
                with self.subTest(tool=tool,field=field,value=value), self.assertRaises(ReadinessError):context_check(env)

    def test_interpreter_hooks_rejected(self):
        context_check(synthetic_context())
        for key in ('PYTHONPATH','PYTHONHOME','BASH_ENV','ENV','RUBYOPT','RUBYLIB','OMNI_YAML_MODULE'):
            env = synthetic_context();env[key] = 'foreign-hook'
            with self.subTest(key=key), self.assertRaisesRegex(ReadinessError,'STATIC_INTERPRETER_HOOK_FORBIDDEN'):
                context_check(env)

    def test_tool_integrity_requires_independent_expected_hash(self):
        raw = b'offline synthetic tool bytes'
        approved = hashlib.sha256(raw).hexdigest()
        preflight.verify_tool_bytes(raw,approved)
        for changed,expected in ((raw+b'tamper',approved),(raw,'0'*64),(raw,None),(raw,'')):
            with self.subTest(expected=expected), self.assertRaisesRegex(ReadinessError,'STATIC_TOOL_HASH_MISMATCH'):
                preflight.verify_tool_bytes(changed,expected)

    def test_static_command_plan_has_no_runtime_execution(self):
        plan = preflight.command_plan(ROOT,Path('private-synthetic'),[Path('inline-synthetic.sh')])
        self.assertEqual(set(plan),{'shellcheck-version','ruby-version','actionlint-version','shellcheck',
            'actionlint','python-tests','static-policy',*('bash-syntax-'+str(i) for i in range(8))})
        self.assertIn('--norc',plan['shellcheck'])
        self.assertIn('--severity=style',plan['shellcheck'])
        self.assertEqual(plan['actionlint'][1:3],['-shellcheck=','-pyflakes='])
        self.assertEqual(plan['actionlint'][3:],[str(ROOT/name) for name in (
            '.github/workflows/isolated-supabase-c0.yml',
            '.github/workflows/static-controller-preflight.yml',
            '.github/workflows/static-toolchain-discovery.yml')])
        self.assertEqual(plan['python-tests'][1:5],['-B','-m','unittest','discover'])
        self.assertEqual(plan['static-policy'][-1],'static')
        self.assertTrue(all('-n' in args for name,args in plan.items() if name.startswith('bash-syntax-')))
        self.assertFalse(any(Path(args[0]).stem in {'docker','supabase','psql','podman','wsl'} for args in plan.values()))
        self.assertFalse(any('verify-cleanup.sh' in x for name,args in plan.items() if not name.startswith('bash-syntax-')
                             and name!='shellcheck' for x in args))

    def test_tampered_command_denied_before_process_or_output_file(self):
        private = Path('private-synthetic')
        baseline = preflight.command_plan(ROOT,private,[])
        for label,argv in (('injected',['docker','version']),('static-policy',['python','harness/security.py','start']),
                           ('actionlint',baseline['actionlint'][:-1]),
                           ('shellcheck',['bash','harness/verify-cleanup.sh'])):
            plan = copy.deepcopy(baseline);plan[label] = argv
            with self.subTest(label=label), patch.object(preflight.subprocess,'run') as run, \
                    patch.object(Path,'open') as opened, self.assertRaisesRegex(ReadinessError,'STATIC_COMMAND_NOT_ALLOWED'):
                preflight.execute_stage(label,plan,ROOT,private,{'_inlines':[]})
            run.assert_not_called();opened.assert_not_called()

    def test_local_windows_refused_before_any_tool_or_network(self):
        for function in (preflight.require_runner,preflight.actionlint_bytes,preflight.main):
            with self.subTest(function=function.__name__), patch.object(preflight.sys,'platform','win32'), \
                    patch.object(preflight.urllib.request,'build_opener') as opener, \
                    patch.object(preflight.subprocess,'run') as run, patch.object(Path,'read_text') as read, \
                    patch.object(Path,'mkdir') as mkdir, self.assertRaisesRegex(ReadinessError,'STATIC_RUNNER_UNVERIFIED'):
                function()
            opener.assert_not_called();run.assert_not_called();read.assert_not_called();mkdir.assert_not_called()

    def test_three_workflows_cover_actionlint_shellcheck_and_bash_syntax(self):
        workflows = ('.github/workflows/isolated-supabase-c0.yml',
                     '.github/workflows/static-controller-preflight.yml',
                     '.github/workflows/static-toolchain-discovery.yml')
        self.assertEqual(preflight.LINT_WORKFLOWS,workflows)
        raw = [[step['run'] for job in yaml_load(ROOT/name)['jobs'].values()
                for step in job['steps'] if 'run' in step] for name in workflows]
        self.assertEqual([len(scripts) for scripts in raw],[16,3,1])
        scripts = preflight.workflow_inlines(ROOT)
        self.assertEqual(len(scripts),20)
        self.assertEqual(scripts[:-1],raw[0]+raw[1])
        paths = [Path('private-synthetic')/('inline-'+str(i)+'.sh') for i in range(len(scripts))]
        plan = preflight.command_plan(ROOT,Path('private-synthetic'),paths)
        self.assertEqual(plan['actionlint'][3:],[str(ROOT/name) for name in workflows])
        self.assertEqual(plan['shellcheck'],[preflight.TOOLS['SHELLCHECK'],'--norc','--shell=bash','--severity=style',
            *[str(ROOT/'harness'/name) for name in preflight.SCRIPTS],*[str(p) for p in paths]])
        syntax = [argv for name,argv in plan.items() if name.startswith('bash-syntax-')]
        self.assertEqual(len(syntax),27)
        self.assertEqual([argv[-1] for argv in syntax],
                         [str(ROOT/'harness'/name) for name in preflight.SCRIPTS]+[str(p) for p in paths])
        self.assertTrue(all(argv[:4] == ['/usr/bin/bash','--noprofile','--norc','-n'] for argv in syntax))

    def test_dpkg_format_annotation_is_one_instruction_in_generated_copy_only(self):
        raw = yaml_load(ROOT/preflight.DISCOVERY_WORKFLOW)['jobs']['discovery']['steps'][0]['run']
        lint_copy = preflight.workflow_inlines(ROOT)[-1]
        lines = lint_copy.splitlines(keepends=True)
        annotated = [i for i,line in enumerate(lines) if line.strip() == '# shellcheck disable=SC2016']
        self.assertEqual(len(annotated),1)
        index = annotated[0]
        self.assertIn("--showformat='${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Status}\\n'",lines[index+1])
        self.assertEqual(''.join(lines[:index]+lines[index+1:]),raw)
        self.assertNotIn('disable=all',lint_copy)

    def test_changed_dpkg_instruction_fails_instead_of_broadening_lint_exception(self):
        documents = {str(ROOT/name):yaml_load(ROOT/name) for name in preflight.LINT_WORKFLOWS}
        for replacement in ('--showformat-changed=', '--showformat='):
            changed = copy.deepcopy(documents)
            step = changed[str(ROOT/preflight.DISCOVERY_WORKFLOW)]['jobs']['discovery']['steps'][0]
            if replacement == '--showformat=':
                step['run'] += next(line for line in step['run'].splitlines(keepends=True) if '--showformat=' in line)
            else:
                step['run'] = step['run'].replace('--showformat=',replacement)
            with self.subTest(replacement=replacement), patch('security.yaml_load',side_effect=lambda path:changed[str(path)]), \
                    self.assertRaisesRegex(ReadinessError,'STATIC_DISCOVERY_LINT_INPUT_CHANGED'):
                preflight.workflow_inlines(ROOT)

    def test_each_mandatory_check_fails_closed_and_filters_child_environment(self):
        private = Path('private-synthetic')
        plan = preflight.command_plan(ROOT,private,[])
        for label in ('shellcheck','actionlint','static-policy','python-tests','bash-syntax-0'):
            with self.subTest(label=label), patch.object(Path,'open',MagicMock()), \
                    patch.object(Path,'read_text',return_value='synthetic-private-output'), \
                    patch.object(preflight.subprocess,'run') as run:
                run.return_value.returncode = 0
                self.assertEqual(preflight.execute_stage(label,plan,ROOT,private,{'_inlines':[]}),
                                 'synthetic-private-output')
                child = run.call_args.kwargs['env']
                self.assertEqual(set(child),{'PATH','HOME','TMPDIR','LC_ALL','PYTHONDONTWRITEBYTECODE','CI','NO_COLOR'})
                self.assertFalse(run.call_args.kwargs.get('shell',False))
                for code in (1,2,True,None):
                    run.return_value.returncode = code
                    with self.subTest(exit=code), self.assertRaisesRegex(ReadinessError,'STATIC_CHECK_FAILED_'):
                        preflight.execute_stage(label,plan,ROOT,private,{'_inlines':[]})

    def test_runtime_guard_remains_unconditional_deny(self):
        preflight.check_guard(ROOT)
        with self.assertRaisesRegex(Denied,'EXECUTION_BLOCKED_EGRESS_UNVERIFIED_P03E2_STATIC_ONLY'):
            authorize()

    def test_tool_redirect_rejects_foreign_origin_before_request(self):
        for target in ('http://github.com/untrusted','https://foreign.invalid/tool','https://github.com.foreign.invalid/tool'):
            with self.subTest(target=target), self.assertRaisesRegex(ReadinessError,'STATIC_TOOL_REDIRECT_UNREVIEWED'):
                preflight.VerifiedRedirect().redirect_request(None,None,302,'',{},target)


if __name__ == '__main__':
    unittest.main()
