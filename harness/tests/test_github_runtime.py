"""SYNTHETIC/MOCK ONLY. Real subprocess/network adapters are explicitly blocked."""
import copy
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tomllib
import unittest
from unittest.mock import MagicMock, patch

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from security import Denied
from github_runtime import (GitHubIO, Lab, ReadinessError, STAGES, aggregate, assess_proofs,
    check_container, check_network, executor_plan, project_id, resource_entry, resource_gate, image_profile,
    trust_revision, validate_temp, prestart_image_gate, check_rest_readiness,
    SyntheticRestTransport, assess_rest_receipt, rest_policy, MANDATORY_ROLES)
from github_lint import artifact_bytes, lint_exit, shellcheck_arguments

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).parent/'fixtures/github-runtime-synthetic.json'


class MockPort:
    origin='SYNTHETIC'
    def __init__(self, fixture, network=True):
        self.f=copy.deepcopy(fixture)
        self.objects={'container':{},'volume':{},'network':{}}
        if network:
            self.objects['network'][self.f['network']['Id']]=self.f['network']
        self.calls=[]
        self.start_exit=0
        self.sql_output=(Path(__file__).parent/'fixtures/c0-synthetic-pass.jsonl').read_text(encoding='utf-8')
        self.temp_calls=0
        self.rest_response=copy.deepcopy(self.f['rest_response'])

    def inventory(self):
        return {k:list(v) for k,v in self.objects.items()}

    def inspect(self,kind,identifier):
        return copy.deepcopy(self.objects[kind].get(identifier))

    def prepare_role(self,obj,role):
        expected=self.f['state']['image_profile']['roles'][role]
        obj['Image']=expected['approved_image_id']
        obj['Config']['Image']=expected['create_reference']
        obj['ImageEvidence']=copy.deepcopy(self.f['images'][role])
        if role=='rest':
            obj['Config'].pop('Healthcheck',None);obj['State'].pop('Health',None)
        else:
            obj['Config']['Healthcheck']={'Test':copy.deepcopy(expected['readiness']['test'])}
        if role=='executor':obj['NamespaceEvidence']=copy.deepcopy(self.f['namespace'])
        obj['Name']=('/omni_executor_' if role=='executor' else '/supabase_'+role+'_')+self.f['state']['project']

    def seed_executor(self):
        obj=copy.deepcopy(self.f['container']);obj['Id']=self.f['state']['executor_id']
        self.prepare_role(obj,'executor');self.objects['container'][obj['Id']]=obj

    def rest_transport(self):
        return SyntheticRestTransport(self.rest_response)

    def seed(self,roles=('db',)):
        for index,role in enumerate(('db','auth','rest','storage','kong','inbucket','realtime')):
            if role in roles:
                obj=copy.deepcopy(self.f['container'])
                obj['Id']=('2'*64) if role=='db' else format(index+4,'064x')
                self.prepare_role(obj,role)
                self.objects['container'][obj['Id']]=obj

    def command(self,args,data=None):
        self.calls.append(copy.deepcopy(args))
        if args[:3]==['docker','network','create']:
            self.objects['network'][self.f['network']['Id']]=self.f['network']
            return 0,self.f['network']['Id']
        if args==['supabase','--version']:
            return 0,'2.108.0\n'
        if args==['supabase','start','--help']:
            return 0,'--network-id studio analytics vector imgproxy'
        if args[0]=='supabase' and 'start' in args:
            self.seed(('db',) if self.start_exit else ('db','auth','rest','storage','kong','inbucket','realtime'))
            if not self.start_exit:self.seed_executor()
            return self.start_exit,'PRIVATE SYNTHETIC OUTPUT - NOT A REAL CLI RUN'
        if args[:3]==['docker','container','exec']:
            return 0,self.sql_output
        if args[:3]==['docker','container','stop']:
            return 0,''
        if len(args)==4 and args[0]=='docker' and args[2]=='rm':
            self.objects[args[1]].pop(args[3],None)
            return 0,''
        raise AssertionError('Unprepared mock command; no real subprocess permitted')

    def verify_proof_origin(self,proof):
        if proof.get('origin')!='SYNTHETIC':
            raise ReadinessError('PROBE_ORIGIN_MISMATCH')

    def measure(self):
        return copy.deepcopy(self.f['resources'])

    def remove_temp(self,path,project):
        self.temp_calls+=1  # Never touches filesystem.


class FutureGitHubPreparation(unittest.TestCase):
    def setUp(self):
        self.f=json.loads(FIXTURE.read_bytes())
        self.s=copy.deepcopy(self.f['state'])
        self.port=MockPort(self.f)
        self.lab=Lab(self.port,self.s)
        clock=patch('github_runtime.readiness_now',return_value=dt.datetime.fromisoformat(self.s['synthetic_now']))
        clock.start();self.addCleanup(clock.stop)

    def entries(self,executor=False):
        self.port.seed()
        if executor:
            obj=copy.deepcopy(self.f['container']);obj['Id']=self.s['executor_id'];self.port.prepare_role(obj,'executor')
            self.port.objects['container'][obj['Id']]=obj
        self.s['ledger']=[resource_entry('network',self.f['network'],self.s['project'],self.s['network_id'],[],self.s['started'],[])]
        for obj in self.port.objects['container'].values():
            self.s['ledger'].append(resource_entry('container',obj,self.s['project'],self.s['network_id'],self.s['image_profile'],self.s['started'],[]))

    def test_real_io_guard_precedes_any_local_runtime_attempt(self):
        with patch('subprocess.run',side_effect=AssertionError('Forbidden local runtime')), patch('urllib.request.urlopen',side_effect=AssertionError('Forbidden local download')) as network:
            with self.assertRaisesRegex(Denied,'EXECUTION_BLOCKED'):
                GitHubIO(Path('must-not-be-created'))
            network.assert_not_called()

    def test_authorization_has_no_environment_override(self):
        with patch.dict('os.environ',{'ALLOW_EXECUTION':'true','CI':'true','RUNNER_ENVIRONMENT':'github-hosted'}):
            with self.assertRaisesRegex(Denied,'EXECUTION_BLOCKED'):
                GitHubIO.guard()

    def test_project_rules(self):
        self.assertEqual(project_id('123','1'),self.s['project'])
        for run,attempt in (('production','1'),('1','../x'),('0','1'),('1'*16,'1')):
            with self.subTest(run=run),self.assertRaises(ReadinessError):
                project_id(run,attempt)

    def test_independent_trust_comparison_only(self):
        anchor={'origin':'INDEPENDENT_ADMIN_APPROVAL','controller_sha':'a'*40,'workflow_sha':'b'*40}
        obs={'repository':'piotrfpn/omninauka-ci-lab','event':'workflow_dispatch','ref':'refs/heads/main',
             'ref_protected':True,'checkout_sha':'a'*40,'github_sha':'a'*40,'workflow_sha':'b'*40}
        self.assertEqual(trust_revision(obs,anchor)['runtime'],'NOT_EXECUTED')
        for key,value in (('checkout_sha','c'*40),('workflow_sha','c'*40),('ref','refs/heads/untrusted'),('ref_protected',False)):
            bad={**obs,key:value}
            with self.subTest(key=key),self.assertRaises(ReadinessError):
                trust_revision(bad,anchor)
        with self.assertRaises(ReadinessError):
            trust_revision(obs,{})

    def test_network_creation_is_internal_and_identity_bound(self):
        port=MockPort(self.f,network=False);state=copy.deepcopy(self.s)
        result=Lab(port,state).network()
        self.assertEqual(result['runtime'],'NOT_EXECUTED')
        self.assertIn('--internal',port.calls[0])
        self.assertNotIn('--subnet',port.calls[0])
        self.assertEqual(state['ledger'][0]['id'],self.s['network_id'])

    def test_preexisting_network_not_reused(self):
        with self.assertRaisesRegex(ReadinessError,'RUNNER_RESOURCES_NOT_FRESH'):
            self.lab.network()
        self.assertEqual(self.port.calls,[])

    def test_network_unknown_label_id_ipv6_or_external_fails(self):
        for key,value in (('Internal',False),('EnableIPv6',True),('Id','bad'),('Labels',{})):
            obj=copy.deepcopy(self.f['network']);obj[key]=value
            with self.subTest(key=key),self.assertRaises(ReadinessError):
                check_network(obj,self.s['project'])

    def test_container_ownership_and_attachments(self):
        original=self.f['container']
        check_container(original,self.s['project'],self.s['network_id'],self.s['image_profile'],self.s['started'])
        bad=copy.deepcopy(original);bad['NetworkSettings']['Networks']['external']={'NetworkID':'9'*64}
        with self.assertRaisesRegex(ReadinessError,'UNEXPECTED_NETWORK_ATTACHMENT'):
            check_container(bad,self.s['project'],self.s['network_id'],self.s['image_profile'],self.s['started'])
        for labels in ({},{'com.supabase.cli.project':'foreign'}):
            bad=copy.deepcopy(original);bad['Config']['Labels']=labels
            with self.assertRaises(ReadinessError):
                check_container(bad,self.s['project'],self.s['network_id'],self.s['image_profile'],self.s['started'])

    def test_no_privilege_host_mode_or_docker_socket(self):
        for field,value in (('Privileged',True),('NetworkMode','host'),('CapAdd',['SYS_ADMIN'])):
            bad=copy.deepcopy(self.f['container']);bad['HostConfig'][field]=value
            with self.subTest(field=field),self.assertRaises(ReadinessError):
                check_container(bad,self.s['project'],self.s['network_id'],self.s['image_profile'],self.s['started'])
        bad=copy.deepcopy(self.f['container']);bad['Mounts']=[{'Source':'/var/run/docker.sock','Destination':'/socket'}]
        with self.assertRaisesRegex(ReadinessError,'SOCKET_EXPOSURE'):
            check_container(bad,self.s['project'],self.s['network_id'],self.s['image_profile'],self.s['started'])

    def test_probe_schema_success_is_not_runtime_proof(self):
        result=assess_proofs(self.f['proof'],self.s['executor_id'],self.s['network_id'])
        self.assertEqual(result['runtime'],'NOT_EXECUTED')
        self.assertEqual(result['egress'],'EGRESS_NOT_VERIFIED')

    def test_host_published_ports_must_be_loopback(self):
        bad=copy.deepcopy(self.f['container'])
        bad['NetworkSettings']['Ports']={'5432/tcp':[{'HostIp':'0.0.0.0','HostPort':'54322'}]}
        with self.assertRaisesRegex(ReadinessError,'PUBLISHED_PORT_NOT_LOCAL'):
            check_container(bad,self.s['project'],self.s['network_id'],self.s['image_profile'],self.s['started'])

    def test_renamed_socket_or_unverified_bind_is_rejected(self):
        bad=copy.deepcopy(self.f['container'])
        bad['Mounts']=[{'Type':'bind','Source':'/untrusted/engine-control','Destination':'/control'}]
        with self.assertRaisesRegex(ReadinessError,'BIND_SOURCE_UNVERIFIED'):
            check_container(bad,self.s['project'],self.s['network_id'],self.s['image_profile'],self.s['started'])

    def test_missing_proof_or_incomplete_checks_fail(self):
        for proof in (None,{},dict(self.f['proof'],probes={})):
            with self.assertRaises(ReadinessError):
                assess_proofs(proof,self.s['executor_id'],self.s['network_id'])

    def test_timeout_dns_crash_are_not_policy_denial(self):
        for classification in ('DNS_UNAVAILABLE','TIMEOUT','REMOTE_UNAVAILABLE','CONTAINER_CRASH'):
            bad=copy.deepcopy(self.f['proof']);bad['probes']['ipv4_numeric']['classification']=classification
            with self.subTest(classification=classification),self.assertRaises(ReadinessError):
                assess_proofs(bad,self.s['executor_id'],self.s['network_id'])
        bad=copy.deepcopy(self.f['proof']);bad['probes']['ipv4_numeric']['before_success']=False
        with self.assertRaises(ReadinessError):
            assess_proofs(bad,self.s['executor_id'],self.s['network_id'])

    def test_ipv6_bypass_fails(self):
        bad=copy.deepcopy(self.f['proof']);bad['probes']['ipv6']={'disabled':False,'after_success':True}
        with self.assertRaisesRegex(ReadinessError,'IPV6_EGRESS_UNVERIFIED'):
            assess_proofs(bad,self.s['executor_id'],self.s['network_id'])

    def test_unconfined_process_or_dead_control_plane_fails(self):
        bad=copy.deepcopy(self.f['proof']);bad['process_boundary']['netns']=1
        with self.assertRaisesRegex(ReadinessError,'TEST_PROCESS_UNCONFINED'):
            assess_proofs(bad,self.s['executor_id'],self.s['network_id'])
        bad=copy.deepcopy(self.f['proof']);bad['probes']['control_plane']['after_success']=False
        with self.assertRaises(ReadinessError):
            assess_proofs(bad,self.s['executor_id'],self.s['network_id'])

    def test_executor_image_must_be_immutable(self):
        with self.assertRaises(ReadinessError):
            executor_plan(self.s['project'],self.s['network_id'],None)
        args=executor_plan(self.s['project'],self.s['network_id'],'fixture.invalid/executor@sha256:'+'e'*64)
        self.assertIn('--read-only',args);self.assertIn('no-new-privileges',args)
        self.assertNotIn('--privileged',args);self.assertNotIn('host',args)

    def test_resource_gates_mock_only(self):
        self.lab.resources('before')
        bad=copy.deepcopy(self.f['resources']);bad['filesystems']['docker']['bytes']=1
        with self.assertRaises(ReadinessError):
            resource_gate(bad,'before')
        bad=copy.deepcopy(self.f['resources']);bad['local_socket']=False
        with self.assertRaises(ReadinessError):
            resource_gate(bad,'after')

    def test_start_profiles_and_private_transport(self):
        self.lab.start(self.s['local'])
        call=next(x for x in self.port.calls if x[0]=='supabase' and '--exclude' in x)
        self.assertIn(self.s['network_name'],call)
        self.assertEqual(call[-1],'studio,analytics,vector,imgproxy')
        self.assertEqual(sum(x.get('id')!=self.s['executor_id'] for x in self.s['ledger']),7)
        self.assertEqual(len(self.s['ledger']),8)

    def test_unapproved_images_block_before_cli(self):
        self.s['image_profile']=[]
        with self.assertRaises(ReadinessError):
            self.lab.start(self.s['local'])
        self.assertEqual(self.port.calls,[])

    def test_partial_startup_retains_owned_ids_for_cleanup(self):
        self.s['ledger']=[resource_entry('network',self.f['network'],self.s['project'],self.s['network_id'],[],self.s['started'],[])]
        self.port.start_exit=1
        with self.assertRaisesRegex(ReadinessError,'CLI_START_FAILED_PARTIAL_STATE_RECORDED'):
            self.lab.start(self.s['local'])
        self.assertEqual(len(self.s['ledger']),2)
        result=self.lab.cleanup('PARTIAL_START')
        self.assertEqual(result['cleanup'],'NOT_EXECUTED')

    def test_private_start_timeout_still_records_partial_resources(self):
        self.s['ledger']=[resource_entry('network',self.f['network'],self.s['project'],self.s['network_id'],[],self.s['started'],[])]
        original=self.port.command
        def timeout(args,data=None):
            if args[0]=='supabase' and '--exclude' in args:
                self.port.seed()
                raise ReadinessError('PRIVATE_COMMAND_TIMED_OUT')
            return original(args,data)
        with patch.object(self.port,'command',side_effect=timeout):
            with self.assertRaisesRegex(ReadinessError,'CLI_START_FAILED_PARTIAL_STATE_RECORDED'):
                self.lab.start(self.s['local'])
        self.assertEqual(len(self.s['ledger']),2)

    def test_cleanup_exact_ids_and_repeated_invocation(self):
        self.entries()
        self.assertEqual(self.lab.cleanup('SUCCESS')['validation'],'PASS')
        count=len(self.port.calls)
        self.assertEqual(self.lab.cleanup('SUCCESS')['validation'],'PASS')
        self.assertEqual(len(self.port.calls),count)
        self.assertEqual(self.port.temp_calls,1)
        self.assertTrue(all(x[-1] in (self.s['network_id'],self.s['db_id']) for x in self.port.calls))

    def test_wrong_id_or_foreign_owner_never_deleted(self):
        self.entries();self.s['ledger'][1]['id']='8'*64
        result=self.lab.cleanup('FAILURE')
        self.assertEqual(result['validation'],'BLOCKED')
        self.assertFalse(any(x[-1]=='8'*64 for x in self.port.calls))
        self.assertEqual(self.port.temp_calls,0)

    def test_unknown_volume_has_no_invented_id(self):
        self.entries();volume={'Name':'unknown','Labels':{'com.supabase.cli.project':self.s['project']}}
        entry=resource_entry('volume',volume,self.s['project'],self.s['network_id'],[],self.s['started'],[])
        self.assertIsNone(entry['id']);self.assertIsNone(entry['cleanup'])
        self.s['ledger'].append(entry);self.port.objects['volume']['unknown']=volume
        result=self.lab.cleanup('FAILURE')
        self.assertEqual(result['validation'],'BLOCKED')
        self.assertFalse(any(x[1]=='volume' for x in self.port.calls))

    def test_all_failure_lifecycles_remain_mocked(self):
        for lifecycle in ('HEALTH_FAILURE','EGRESS_FAILURE','SQL_FAILURE','CANCELLATION','TIMEOUT'):
            self.setUp();self.entries()
            result=self.lab.cleanup(lifecycle)
            self.assertEqual(result['cleanup'],'NOT_EXECUTED')

    def test_sql_targets_owned_socket_not_dsn(self):
        self.entries(executor=True)
        result=self.lab.sql((ROOT/'harness/sql/c0-readonly.sql').read_bytes(),self.s['db_id'],self.f['proof'])
        self.assertEqual(result['sql_execution'],'NOT_EXECUTED')
        call=self.port.calls[-1]
        self.assertIn('/var/run/postgresql',call);self.assertIn('-X',call);self.assertIn('ON_ERROR_STOP=1',call)
        self.assertFalse(any('://' in x for x in call))

    def test_sql_rejects_missing_proof_wrong_id_and_bad_output(self):
        self.entries(executor=True);sql=(ROOT/'harness/sql/c0-readonly.sql').read_bytes()
        with self.assertRaises(ReadinessError):self.lab.sql(sql,'9'*64,self.f['proof'])
        with self.assertRaises(ReadinessError):self.lab.sql(sql,self.s['db_id'],None)
        self.port.sql_output='{}'
        with self.assertRaises(ValueError):self.lab.sql(sql,self.s['db_id'],self.f['proof'])

    def test_no_partial_or_mock_c0_pass(self):
        results={key:'PASS' for key in STAGES}
        self.assertEqual(aggregate(results)['overall'],'BLOCKED')
        for stage in STAGES:
            for status in ('FAIL','BLOCKED','NOT_TESTED','NOT_EXECUTED'):
                with self.subTest(stage=stage,status=status):
                    self.assertEqual(aggregate({**results,stage:status},'GITHUB_RUNTIME')['overall'],'BLOCKED')
        self.assertEqual(aggregate({})['overall'],'BLOCKED')

    def test_missing_lint_or_checksum_fails(self):
        lint_exit(0)
        with self.assertRaisesRegex(ReadinessError,'MANDATORY_LINT_FAILED'):
            lint_exit(1)
        with self.assertRaisesRegex(ReadinessError,'SHELLCHECK_MISSING'):
            shellcheck_arguments(ROOT,None,'missing')
        with self.assertRaisesRegex(ReadinessError,'ACTIONLINT_PROVENANCE_BLOCKED'):
            artifact_bytes(b'not executed',None)
        with self.assertRaisesRegex(ReadinessError,'ACTIONLINT_CHECKSUM_FAILED'):
            artifact_bytes(b'not executed','0'*64)

    def test_synthetic_verified_archive_not_executed(self):
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w:gz') as archive:
            item=tarfile.TarInfo('actionlint');item.size=4;archive.addfile(item,io.BytesIO(b'MOCK'))
        blob=buf.getvalue()
        self.assertEqual(artifact_bytes(blob,hashlib.sha256(blob).hexdigest()),b'MOCK')

    def test_owned_temp_scope_and_symlink_rejection(self):
        # Pure metadata mocks: no local directory deletion or symlink privilege.
        base,path=MagicMock(),MagicMock()
        base.resolve.return_value=base
        path.name=self.s['project'];path.is_symlink.return_value=False
        path.parent=base;path.resolve.return_value=path
        path.stat.return_value.st_dev=1;path.rglob.return_value=[]
        (path/'owner.json').read_bytes.return_value=json.dumps({'project':self.s['project'],
            'candidate':'bdbb31ef00a2d35bd63cce3f6c8c24f401f67fce'}).encode()
        with patch('github_runtime.Path',side_effect=lambda value:path if value=='owned' else base):
            self.assertIs(validate_temp('owned','base',self.s['project']),path)
            path.is_symlink.return_value=True
            with self.assertRaises(ReadinessError):validate_temp('owned','base',self.s['project'])
            path.is_symlink.return_value=False;path.name='foreign'
            with self.assertRaises(ReadinessError):validate_temp('owned','base',self.s['project'])

    def validate_container(self,obj=None,profile=None):
        return check_container(self.f['container'] if obj is None else obj,self.s['project'],
            self.s['network_id'],self.s['image_profile'] if profile is None else profile,self.s['started'])

    def test_missing_health_and_running_alone_never_pass(self):
        for value in (None,{},[],True,'healthy',{'Status':'healthy'}):
            bad=copy.deepcopy(self.f['container']);bad['State']['Health']=value
            with self.subTest(health=value),self.assertRaisesRegex(ReadinessError,'SERVICE_HEALTH_UNVERIFIED'):
                self.validate_container(bad)
        bad=copy.deepcopy(self.f['container']);del bad['State']['Health']
        with self.assertRaisesRegex(ReadinessError,'SERVICE_HEALTH_UNVERIFIED'):self.validate_container(bad)

    def test_starting_unhealthy_and_malformed_status_block(self):
        for status in ('starting','unhealthy','',None,True,['healthy']):
            bad=copy.deepcopy(self.f['container']);bad['State']['Health']['Status']=status
            with self.subTest(status=status),self.assertRaisesRegex(ReadinessError,'SERVICE_HEALTH_UNVERIFIED'):
                self.validate_container(bad)

    def test_health_requires_running_and_successful_latest_log(self):
        for field,value in (('Running',False),('Running',1),('Health',{'Status':'healthy','FailingStreak':False,'Log':[]})):
            bad=copy.deepcopy(self.f['container']);bad['State'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ReadinessError):self.validate_container(bad)
        for log in (None,[],[None],[{}],[{'ExitCode':False}],[{'ExitCode':1}]):
            bad=copy.deepcopy(self.f['container']);bad['State']['Health']['Log']=log
            with self.subTest(log=log),self.assertRaises(ReadinessError):self.validate_container(bad)
        bad=copy.deepcopy(self.f['container']);bad['State']['Health']['Log'][-1]['ExitCode']=1
        with self.assertRaisesRegex(ReadinessError,'SERVICE_HEALTH_UNVERIFIED'):self.validate_container(bad)

    def test_stale_future_prestart_and_malformed_readiness_block(self):
        for key,value in (('End','2026-10-23T23:59:00Z'),('End','2026-10-24T00:01:00Z'),
                          ('Start','2026-10-23T23:59:59Z'),('Start','bad'),('End',None),
                          ('End','2026-10-24T00:00:05')):
            bad=copy.deepcopy(self.f['container']);bad['State']['Health']['Log'][-1][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ReadinessError):self.validate_container(bad)
        bad=copy.deepcopy(self.f['container']);bad['State']['StartedAt']='2026-10-24T00:00:05Z'
        with self.assertRaisesRegex(ReadinessError,'SERVICE_READINESS_STALE'):self.validate_container(bad)
        with patch('github_runtime.readiness_now',return_value=dt.datetime.fromisoformat('2026-10-24T00:01:06+00:00')):
            with self.assertRaisesRegex(ReadinessError,'SERVICE_READINESS_STALE'):self.validate_container()

    def test_different_service_healthcheck_does_not_authorize(self):
        bad=copy.deepcopy(self.f['container'])
        bad['Config']['Healthcheck']['Test']=self.s['image_profile']['roles']['auth']['readiness']['test']
        with self.assertRaisesRegex(ReadinessError,'SERVICE_HEALTHCHECK_MISMATCH'):self.validate_container(bad)

    def test_missing_healthcheck_or_unreviewed_alternative_is_not_ready(self):
        for value in (None,{},[],{'Test':['NONE']},{'Test':'healthy'}):
            bad=copy.deepcopy(self.f['container']);bad['Config']['Healthcheck']=value
            with self.subTest(check=value),self.assertRaisesRegex(ReadinessError,'SERVICE_HEALTHCHECK_MISMATCH'):
                self.validate_container(bad)
        for policy in (None,{}, {'mechanism':'alternative_probe','status':'PASS'}, {'mechanism':'NOT_VERIFIED'}):
            profile=copy.deepcopy(self.s['image_profile']);profile['roles']['db']['readiness']=policy
            with self.subTest(policy=policy),self.assertRaisesRegex(ReadinessError,'SERVICE_READINESS_NOT_VERIFIED'):
                self.validate_container(profile=profile)

    def test_readiness_policy_must_be_bounded_and_explicit(self):
        for key,value in (('test',['NONE']),('test',[]),('test',['CMD',None]),
                          ('max_age_seconds',0),('max_age_seconds',61),('max_age_seconds',True)):
            profile=copy.deepcopy(self.s['image_profile']);profile['roles']['db']['readiness'][key]=value
            with self.subTest(key=key,value=value),self.assertRaisesRegex(ReadinessError,'READINESS_POLICY_INVALID'):
                self.validate_container(profile=profile)

    def test_each_mandatory_service_requires_its_own_readiness(self):
        original=self.port.seed
        for role in ('db','auth','rest','storage','kong','inbucket','realtime'):
            self.s['ledger']=[]
            self.port.rest_response=copy.deepcopy(self.f['rest_response'])
            def seed(roles,missing=role):
                original(roles)
                if missing=='rest':self.port.rest_response=None
                for obj in self.port.objects['container'].values():
                    if missing!='rest' and obj['Name']=='/supabase_'+missing+'_'+self.s['project']:obj['State'].pop('Health',None)
            with self.subTest(role=role),patch.object(self.port,'seed',side_effect=seed):
                with self.assertRaisesRegex(ReadinessError,'REST_PROBE_MISSING' if role=='rest' else 'SERVICE_HEALTH_UNVERIFIED'):self.lab.start(self.s['local'])
            self.assertEqual(sum(x.get('id')!=self.s['executor_id'] for x in self.s['ledger']),7)
        self.assertEqual(len(self.s['ledger']),8)  # Identity retained for mock cleanup on health failure.

    def test_correct_image_wrong_role_and_db_as_auth_fail(self):
        for role in ('auth','rest','storage','kong','inbucket','realtime'):
            bad=copy.deepcopy(self.f['container']);bad['Name']='/supabase_'+role+'_'+self.s['project']
            with self.subTest(role=role),self.assertRaisesRegex(ReadinessError,'SERVICE_IMAGE_ID_MISMATCH'):
                self.validate_container(bad)

    def test_correct_role_wrong_image_id_fails(self):
        bad=copy.deepcopy(self.f['container']);bad['Image']=self.s['image_profile']['roles']['auth']['approved_image_id']
        with self.assertRaisesRegex(ReadinessError,'SERVICE_IMAGE_ID_MISMATCH'):self.validate_container(bad)

    def test_digest_reference_is_distinct_from_observed_image_id(self):
        for ref in ('fixture.invalid/db:latest',self.f['container']['Image'],
                    self.s['image_profile']['roles']['auth']['create_reference']):
            bad=copy.deepcopy(self.f['container']);bad['Config']['Image']=ref
            with self.subTest(ref=ref),self.assertRaisesRegex(ReadinessError,'SERVICE_IMAGE_REFERENCE_MISMATCH'):
                self.validate_container(bad)
        profile=copy.deepcopy(self.s['image_profile']);profile['roles']['db']['approved_repository_digest']='fixture.invalid/db:latest'
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PROFILE_INVALID'):self.validate_container(profile=profile)

    def test_unknown_or_foreign_service_name_never_infers_role_from_image(self):
        for name in ('/supabase_db_foreign','/supabase_gotrue_'+self.s['project'],
                     '/supabase_mailpit_'+self.s['project'],'/supabase_realtime_other',None):
            bad=copy.deepcopy(self.f['container']);bad['Name']=name
            with self.subTest(name=name),self.assertRaisesRegex(ReadinessError,'SERVICE_ROLE_UNVERIFIED'):
                self.validate_container(bad)

    def test_missing_unapproved_or_incomplete_image_profile_blocks_before_cli(self):
        for profile in (None,[],{}, {'status':'INDEPENDENTLY_APPROVED'},
                        dict(self.s['image_profile'],roles={}),dict(self.s['image_profile'],status='UNAPPROVED')):
            self.s['image_profile']=profile
            with self.subTest(profile=profile),self.assertRaises(ReadinessError):self.lab.start(self.s['local'])
            self.assertEqual(self.port.calls,[])

    def test_synthetic_profile_never_authorizes_a_runtime_port(self):
        self.port.origin='GITHUB_RUNTIME'
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PROFILE_UNAPPROVED'):self.lab.start(self.s['local'])
        self.assertEqual(self.port.calls,[])
        for status in ('UNAPPROVED','INDEPENDENTLY_APPROVED','SYNTHETIC_TEST_ONLY'):
            with self.subTest(status=status),self.assertRaisesRegex(ReadinessError,'IMAGE_PROFILE_UNAPPROVED'):
                image_profile(dict(self.f['state']['image_profile'],status=status),'GITHUB_RUNTIME')

    def test_unhealthy_owned_container_still_has_mock_cleanup_identity(self):
        self.entries();obj=self.port.objects['container'][self.s['db_id']]
        obj['State']={'Running':False}
        self.assertEqual(self.lab.cleanup('HEALTH_FAILURE')['validation'],'PASS')

    def test_every_real_io_entry_stays_blocked_before_side_effects(self):
        from github_runtime import dispatch
        port=object.__new__(GitHubIO)
        calls=(lambda:GitHubIO(Path('must-not-be-created')),lambda:port.command(['docker','info']),
               lambda:port.inventory(),lambda:port.inspect('container','2'*64),lambda:port.measure(),
               lambda:port.verify_proof_origin({}),lambda:port.remove_temp('unused','unused'),
               lambda:dispatch('start',ROOT))
        with patch('subprocess.run',side_effect=AssertionError('Forbidden subprocess')) as process, \
             patch('shutil.which',side_effect=AssertionError('Forbidden runtime discovery')) as discovery, \
             patch('urllib.request.urlopen',side_effect=AssertionError('Forbidden network')) as network, \
             patch('pathlib.Path.mkdir',side_effect=AssertionError('Forbidden runtime mkdir')) as mkdir:
            for call in calls:
                with self.subTest(call=call),self.assertRaisesRegex(Denied,'EXECUTION_BLOCKED'):call()
            for mock in (process,discovery,network,mkdir):mock.assert_not_called()



class CompatibilityHardening(unittest.TestCase):
    """Each negative starts with passing image, pre-start and REST mock baselines."""
    def setUp(self):
        FutureGitHubPreparation.setUp(self)
        self.assertEqual(self.image_check(),self.f['container']['Id'])
        self.assertEqual(prestart_image_gate(self.s['image_profile'],self.s['image_selection'])['runtime'],'NOT_EXECUTED')
        self.assertEqual(self.rest_check()['runtime'],'NOT_EXECUTED')

    def image_check(self,obj=None,profile=None):
        return check_container(self.f['container'] if obj is None else obj,self.s['project'],self.s['network_id'],
            self.s['image_profile'] if profile is None else profile,self.s['started'])

    def rest_objects(self):
        self.port.seed(MANDATORY_ROLES);self.port.seed_executor()
        return [self.port.objects['container'][format(6,'064x')],
                self.port.objects['container'][format(8,'064x')],
                self.port.objects['container'][self.s['executor_id']]]

    def rest_check(self,**changes):
        response=copy.deepcopy(self.f['rest_response']);response.update(changes)
        return check_rest_readiness(*self.rest_objects(),self.f['network'],self.s['image_profile'],
            self.s['project'],self.s['started'],SyntheticRestTransport(response))

    def test_IMG_01_wrong_container_and_inspect_image_id(self):
        for field in ('container','inspect'):
            bad=copy.deepcopy(self.f['container'])
            if field=='container':bad['Image']='sha256:'+'f'*64
            else:bad['ImageEvidence']['Id']='sha256:'+'f'*64
            with self.subTest(field=field),self.assertRaises(ReadinessError):self.image_check(bad)

    def test_IMG_02_correct_tag_different_content_id(self):
        bad=copy.deepcopy(self.f['container']);bad['Image']=self.s['image_profile']['roles']['auth']['approved_image_id']
        self.assertEqual(bad['Config']['Image'],self.s['image_profile']['roles']['db']['create_reference'])
        with self.assertRaisesRegex(ReadinessError,'SERVICE_IMAGE_ID_MISMATCH'):self.image_check(bad)

    def test_IMG_03_correct_image_wrong_service_role(self):
        for role in MANDATORY_ROLES[1:]:
            bad=copy.deepcopy(self.f['container']);bad['Name']='/supabase_'+role+'_'+self.s['project']
            with self.subTest(role=role),self.assertRaises(ReadinessError):self.image_check(bad)
        profile=copy.deepcopy(self.s['image_profile']);profile['roles']['db']['role']='auth'
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PROFILE_INVALID'):self.image_check(profile=profile)

    def test_IMG_04_wrong_digest_and_inconsistent_manifest_graph(self):
        for field,code in (('RepoDigests','IMAGE_REPOSITORY_DIGEST_MISMATCH'),('ConfigBytes','IMAGE_CONFIG_DIGEST_MISMATCH'),
                           ('ManifestBytes','IMAGE_MANIFEST_DIGEST_MISMATCH'),('RepositoryManifestBytes','IMAGE_REPOSITORY_MANIFEST_DIGEST_MISMATCH')):
            bad=copy.deepcopy(self.f['container']);e=bad['ImageEvidence']
            if field=='RepoDigests':e[field]=['fixture.invalid/db@sha256:'+'f'*64]
            elif field=='ConfigBytes':e[field]=e[field].replace('\"synthetic_role\":\"db\"','\"synthetic_role\":\"dx\"')
            elif field=='ManifestBytes':e[field]=e[field].replace('\"offline.fixture\":\"db\"','\"offline.fixture\":\"dx\"')
            else:e[field]+=' '
            with self.subTest(field=field),self.assertRaisesRegex(ReadinessError,code):self.image_check(bad)
        profile=copy.deepcopy(self.s['image_profile']);profile['roles']['db']['approved_repository_digest']='fixture.invalid/db@sha256:'+'f'*64
        with self.assertRaises(ReadinessError):self.image_check(profile=profile)

    def test_IMG_05_wrong_os_architecture_or_platform_manifest(self):
        for field,value in (('Os','windows'),('Architecture','arm64')):
            bad=copy.deepcopy(self.f['container']);bad['ImageEvidence'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ReadinessError,'IMAGE_PLATFORM_MISMATCH'):self.image_check(bad)
        profile=copy.deepcopy(self.s['image_profile']);profile['roles']['db']['approved_platform']['os']='windows'
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PLATFORM_UNAPPROVED'):self.image_check(profile=profile)
        bad=copy.deepcopy(self.f['container']);profile=copy.deepcopy(self.s['image_profile'])
        index=json.loads(bad['ImageEvidence']['RepositoryManifestBytes']);index['manifests'][0]['digest']='sha256:'+'f'*64
        raw=json.dumps(index);digest='sha256:'+hashlib.sha256(raw.encode()).hexdigest()
        profile['roles']['db']['approved_repository_digest']='fixture.invalid/db@'+digest
        bad['ImageEvidence']['RepositoryManifestBytes']=raw;bad['ImageEvidence']['RepoDigests']=['fixture.invalid/db@'+digest]
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PLATFORM_MANIFEST_MISMATCH'):self.image_check(bad,profile)

    def test_IMG_06_unapproved_registry_fallback(self):
        for registry in ('public.ecr.aws','ghcr.io','docker.io','evil.invalid'):
            bad=copy.deepcopy(self.f['container']);bad['Config']['Image']=registry+'/db:synthetic'
            with self.subTest(registry=registry),self.assertRaisesRegex(ReadinessError,'SERVICE_IMAGE_REFERENCE_MISMATCH'):
                self.image_check(bad)

    def test_IMG_manifest_config_edge_is_not_replaced_by_equal_outer_hashes(self):
        bad=copy.deepcopy(self.f['container']);profile=copy.deepcopy(self.s['image_profile'])
        e=bad['ImageEvidence'];row=profile['roles']['db']
        manifest=json.loads(e['ManifestBytes']);manifest['config']['digest']='sha256:'+'f'*64
        e['ManifestBytes']=json.dumps(manifest);md='sha256:'+hashlib.sha256(e['ManifestBytes'].encode()).hexdigest()
        row['approved_platform_manifest_digest']=md
        index=json.loads(e['RepositoryManifestBytes']);index['manifests'][0]['digest']=md
        index['manifests'][0]['size']=len(e['ManifestBytes'].encode());e['RepositoryManifestBytes']=json.dumps(index)
        rd='fixture.invalid/db@sha256:'+hashlib.sha256(e['RepositoryManifestBytes'].encode()).hexdigest()
        row['approved_repository_digest']=rd;e['RepoDigests']=[rd]
        with self.assertRaisesRegex(ReadinessError,'IMAGE_MANIFEST_CONFIG_MISMATCH'):self.image_check(bad,profile)

    def test_IMG_single_platform_repository_manifest_has_explicit_binding(self):
        bad=copy.deepcopy(self.f['container']);profile=copy.deepcopy(self.s['image_profile']);row=profile['roles']['db']
        rd='fixture.invalid/db@'+row['approved_platform_manifest_digest']
        row['approved_repository_digest']=rd;bad['ImageEvidence']['RepoDigests']=[rd]
        bad['ImageEvidence']['RepositoryManifestBytes']=bad['ImageEvidence']['ManifestBytes']
        self.assertEqual(self.image_check(bad,profile),bad['Id'])
        self.assertNotEqual(row['approved_image_id'],row['approved_platform_manifest_digest'])

    def test_IMG_missing_malformed_and_duplicate_metadata_never_passes(self):
        for field in ('Id','Os','Architecture','RepoDigests','ConfigBytes','ManifestBytes','RepositoryManifestBytes'):
            bad=copy.deepcopy(self.f['container']);bad['ImageEvidence'].pop(field)
            with self.subTest(field=field),self.assertRaises(ReadinessError):self.image_check(bad)
        for raw in ('{}','[]','{"os":"linux","os":"windows"}','{"os":NaN}'):
            bad=copy.deepcopy(self.f['container']);bad['ImageEvidence']['ConfigBytes']=raw
            with self.subTest(raw=raw),self.assertRaises(ReadinessError):self.image_check(bad)
        for config in (None,[],True):
            bad=copy.deepcopy(self.f['container']);bad['Config']=config
            with self.subTest(config=config),self.assertRaises(ReadinessError):self.image_check(bad)

    def test_IMG_07_missing_profile_or_image_inspection(self):
        for profile in (None,{},[]):
            with self.subTest(profile=profile),self.assertRaises(ReadinessError):
                check_container(self.f['container'],self.s['project'],self.s['network_id'],profile,self.s['started'])
        bad=copy.deepcopy(self.f['container']);bad.pop('ImageEvidence')
        with self.assertRaisesRegex(ReadinessError,'IMAGE_INSPECT_ID_MISMATCH'):self.image_check(bad)

    def test_IMG_08_synthetic_profile_never_authorizes_runtime(self):
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PROFILE_UNAPPROVED'):
            image_profile(self.s['image_profile'],'GITHUB_RUNTIME')
        self.port.origin='GITHUB_RUNTIME'
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PROFILE_UNAPPROVED'):self.lab.start(self.s['local'])
        self.assertEqual(self.port.calls,[])

    def test_IMG_09_unverified_prestart_selection_blocks_before_any_command(self):
        for selection in (None,{},dict(self.s['image_selection'],phase='AFTER_START'),
                          dict(self.s['image_selection'],images={})):
            self.s['image_selection']=selection
            with self.subTest(selection=selection),self.assertRaisesRegex(ReadinessError,'IMAGE_PRESTART_TRUST_BLOCKED'):
                self.lab.start(self.s['local'])
            self.assertEqual(self.port.calls,[])
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PRESTART_TRUST_BLOCKED'):
            prestart_image_gate(self.f['state']['image_profile'],self.f['state']['image_selection'],'GITHUB_RUNTIME')

    def test_IMG_10_post_start_inspection_is_not_admission(self):
        entry=resource_entry('container',self.f['container'],self.s['project'],self.s['network_id'],
            self.s['image_profile'],self.s['started'],[])
        self.assertEqual(entry['ownership'],'VERIFIED_BY_CREATION_AND_INSPECT')
        self.s['ledger'].append(entry);self.s['image_selection']=None
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PRESTART_TRUST_BLOCKED'):self.lab.start(self.s['local'])
        self.assertEqual(self.port.calls,[])

    def test_REST_01_head_200_only_offline(self):
        result=self.rest_check()
        self.assertEqual(result,{'validation':'PASS','origin':'SYNTHETIC','runtime':'NOT_EXECUTED',
            'real_probe':'REST_RUNTIME_PROBE_UNVERIFIED'})
        policy=self.s['image_profile']['roles']['rest']['readiness']
        self.assertEqual((policy['method'],policy['path'],policy['status']),('HEAD','/rest-admin/v1/ready',200))

    def test_REST_02_rejects_every_other_status(self):
        for status in (204,301,302,401,403,404,500,True,'200'):
            with self.subTest(status=status),self.assertRaisesRegex(ReadinessError,'REST_PROBE_FAILED'):self.rest_check(status=status)

    def test_REST_03_redirect_never_passes_even_with_final_200(self):
        with self.assertRaisesRegex(ReadinessError,'REST_PROBE_FAILED'):self.rest_check(redirected=True)

    def test_REST_04_timeout_and_unbounded_duration(self):
        with self.assertRaisesRegex(ReadinessError,'REST_PROBE_FAILED'):self.rest_check(timed_out=True)
        with patch('github_runtime.readiness_now',return_value=dt.datetime.fromisoformat('2026-10-24T00:00:08+00:00')):
            with self.assertRaisesRegex(ReadinessError,'REST_PROBE_STALE'):
                self.rest_check(completed_at='2026-10-24T00:00:07Z')

    def test_REST_05_wrong_gateway_identity_or_image(self):
        for field in ('gateway_id','gateway_image_id'):
            with self.subTest(field=field),self.assertRaisesRegex(ReadinessError,'REST_SERVICE_BINDING_MISMATCH'):
                self.rest_check(**{field:'foreign'})

    def test_REST_06_wrong_rest_identity_or_image(self):
        for field in ('rest_id','rest_image_id'):
            with self.subTest(field=field),self.assertRaisesRegex(ReadinessError,'REST_SERVICE_BINDING_MISMATCH'):
                self.rest_check(**{field:'foreign'})

    def test_REST_07_wrong_project_network_executor_or_namespace(self):
        for field in ('project','network_id','executor_id','executor_image_id','executor_netns'):
            with self.subTest(field=field),self.assertRaisesRegex(ReadinessError,'REST_SERVICE_BINDING_MISMATCH'):
                self.rest_check(**{field:'foreign'})
        rest,kong,executor=self.rest_objects();executor['NamespaceEvidence']['netns']=1
        with self.assertRaisesRegex(ReadinessError,'REST_EXECUTOR_UNVERIFIED'):
            check_rest_readiness(rest,kong,executor,self.f['network'],self.s['image_profile'],self.s['project'],
                self.s['started'],SyntheticRestTransport(self.f['rest_response']))

    def test_REST_08_stale_future_and_prestart_receipts(self):
        for changes in ({'started_at':'2026-10-23T23:59:59Z'}, {'completed_at':'2026-10-24T00:00:07Z'},
                        {'completed_at':None}, {'started_at':'malformed'}):
            with self.subTest(changes=changes),self.assertRaises(ReadinessError):self.rest_check(**changes)
        with patch('github_runtime.readiness_now',return_value=dt.datetime.fromisoformat('2026-10-24T00:00:16+00:00')):
            # Isolate receipt age from the (60-second) native health evidence.
            with self.assertRaisesRegex(ReadinessError,'REST_PROBE_STALE'):self.rest_check()

    def test_REST_09_missing_receipt(self):
        with self.assertRaisesRegex(ReadinessError,'REST_PROBE_MISSING'):
            check_rest_readiness(*self.rest_objects(),self.f['network'],self.s['image_profile'],self.s['project'],
                self.s['started'],SyntheticRestTransport(None))

    def test_REST_10_healthy_kong_with_failed_rest(self):
        self.assertEqual(self.rest_objects()[1]['State']['Health']['Status'],'healthy')
        with self.assertRaisesRegex(ReadinessError,'REST_PROBE_FAILED'):self.rest_check(status=503)
        rest,kong,executor=self.rest_objects();rest['State']['Running']=False
        with self.assertRaisesRegex(ReadinessError,'REST_SERVICE_NOT_RUNNING'):
            check_rest_readiness(rest,kong,executor,self.f['network'],self.s['image_profile'],self.s['project'],
                self.s['started'],SyntheticRestTransport(self.f['rest_response']))

    def test_REST_11_generic_200_from_another_service(self):
        with self.assertRaisesRegex(ReadinessError,'REST_SERVICE_BINDING_MISMATCH'):
            self.rest_check(response_service_id=self.s['db_id'])
        for method,path in (('GET','/rest-admin/v1/ready'),('HEAD','/rest/v1'),('HEAD','/health'),('HEAD','/')):
            with self.subTest(method=method,path=path),self.assertRaisesRegex(ReadinessError,'REST_PROBE_FAILED'):
                self.rest_check(method=method,path=path)

    def test_REST_12_handcrafted_pass_is_not_a_collector_receipt(self):
        transport=SyntheticRestTransport(self.f['rest_response']);policy=self.s['image_profile']['roles']['rest']['readiness']
        for receipt in (None,{},dict(self.f['rest_response'],status='PASS'),object()):
            with self.subTest(receipt=receipt),self.assertRaisesRegex(ReadinessError,'REST_PROBE_ORIGIN_UNTRUSTED'):
                assess_rest_receipt(receipt,transport,{},policy,self.s['started'])
        with self.assertRaisesRegex(ReadinessError,'REST_PROBE_ORIGIN_UNTRUSTED'):
            self.rest_check(origin='GITHUB_RUNTIME')

    def test_REST_13_real_probe_always_unverified(self):
        with self.assertRaisesRegex(ReadinessError,'REST_RUNTIME_PROBE_UNVERIFIED'):
            check_rest_readiness(None,None,None,None,None,None,None,None,'GITHUB_RUNTIME')

    def test_REST_policy_accepts_no_url_hostname_or_arbitrary_callback(self):
        policy=self.s['image_profile']['roles']['rest']['readiness']
        for key,value in (('url','https://unreviewed.invalid'),('hostname','localhost'),('path','/health'),
                          ('method','GET'),('timeout_seconds',11),('timeout_seconds',True),('follow_redirects',True)):
            with self.subTest(key=key),self.assertRaisesRegex(ReadinessError,'REST_POLICY_UNAPPROVED'):
                rest_policy(dict(policy,**{key:value}))
        class ForeignTransport:
            def head_rest(self,*args):raise AssertionError('Untrusted callback must never run')
        with self.assertRaisesRegex(ReadinessError,'REST_PROBE_ORIGIN_UNTRUSTED'):
            check_rest_readiness(*self.rest_objects(),self.f['network'],self.s['image_profile'],self.s['project'],
                self.s['started'],ForeignTransport())

    def test_EDGE_01_template_disables_only_optional_edge(self):
        config=tomllib.loads((ROOT/'harness/contracts/c0-config.toml.in').read_text(encoding='utf-8'))
        self.assertIs(config['edge_runtime']['enabled'],False)
        self.assertTrue(config['api']['enabled']);self.assertTrue(config['auth']['enabled'])
        self.assertTrue(config['local_smtp']['enabled'])
        self.assertNotIn('edge_runtime',MANDATORY_ROLES)
        self.assertEqual(set(MANDATORY_ROLES),{'db','auth','rest','storage','kong','inbucket','realtime'})

    def test_EDGE_02_unknown_extra_runtime_container_is_rejected(self):
        original=self.port.seed
        def seed(roles):
            original(roles);bad=copy.deepcopy(self.f['container']);bad['Id']='9'*64
            bad['Name']='/supabase_edge_runtime_'+self.s['project'];self.port.objects['container'][bad['Id']]=bad
        with patch.object(self.port,'seed',side_effect=seed):
            with self.assertRaisesRegex(ReadinessError,'STARTUP_OWNERSHIP_UNVERIFIED'):self.lab.start(self.s['local'])
        bad=copy.deepcopy(self.f['container']);bad['Name']='/supabase_edge_runtime_'+self.s['project']
        with self.assertRaisesRegex(ReadinessError,'SERVICE_ROLE_UNVERIFIED'):self.image_check(bad)

    def test_EDGE_03_all_seven_roles_remain_required(self):
        for missing in MANDATORY_ROLES:
            state=copy.deepcopy(self.f['state']);port=MockPort(self.f);seed=port.seed
            def absent(roles,omit=missing):seed(tuple(x for x in roles if x!=omit))
            with self.subTest(missing=missing),patch.object(port,'seed',side_effect=absent):
                with self.assertRaisesRegex(ReadinessError,'REQUIRED_SERVICE_MISSING'):Lab(port,state).start(state['local'])

    def test_GUARD_01_authorize_has_one_unconditional_deny(self):
        import ast
        from security import authorize
        tree=ast.parse((ROOT/'harness/security.py').read_text(encoding='utf-8'))
        guard=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='authorize')
        self.assertEqual(len(guard.body),1);self.assertIsInstance(guard.body[0],ast.Raise)
        with self.assertRaisesRegex(Denied,'EXECUTION_BLOCKED'):authorize()

    def test_GUARD_02_no_real_io_from_new_paths(self):
        port=object.__new__(GitHubIO)
        with patch('subprocess.run',side_effect=AssertionError('No subprocess')) as process, \
             patch('shutil.which',side_effect=AssertionError('No discovery')) as discovery, \
             patch('socket.socket.connect',side_effect=AssertionError('No socket')) as network, \
             patch('urllib.request.urlopen',side_effect=AssertionError('No HTTP')) as http:
            for call in (port.rest_transport,port.prestart_images):
                with self.assertRaisesRegex(Denied,'EXECUTION_BLOCKED'):call()
            self.assertEqual(self.rest_check()['runtime'],'NOT_EXECUTED')
            for mock in (process,discovery,network,http):mock.assert_not_called()

    def test_GUARD_03_mock_receipt_cannot_cross_into_real_boundary(self):
        policy=self.s['image_profile']['roles']['rest']['readiness'];response=self.f['rest_response']
        fields={'origin','method','path','status','redirected','timed_out','response_service_id','started_at','completed_at'}
        binding={k:v for k,v in response.items() if k not in fields}
        transport=SyntheticRestTransport(response);receipt=SyntheticRestTransport.head_rest(transport,binding,policy)
        self.assertEqual(assess_rest_receipt(receipt,transport,binding,policy,self.s['started'])['runtime'],'NOT_EXECUTED')
        with self.assertRaisesRegex(ReadinessError,'REST_PROBE_ORIGIN_UNTRUSTED'):
            assess_rest_receipt(receipt,transport,binding,policy,self.s['started'])
        with self.assertRaisesRegex(ReadinessError,'IMAGE_PRESTART_TRUST_BLOCKED'):
            prestart_image_gate(self.s['image_profile'],self.s['image_selection'],'GITHUB_RUNTIME')


if __name__=='__main__':
    unittest.main()
