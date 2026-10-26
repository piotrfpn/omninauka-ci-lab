"""Synthetic JSON only. No process, database, Docker, network or source mutation."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from c0_results import InvalidResult, evaluate_jsonl
from security import Denied, cleanup, verify_controller_revision

FIXTURE = Path(__file__).parent / 'fixtures/c0-synthetic-pass.jsonl'


class ResultsContract(unittest.TestCase):
    def setUp(self):
        self.rows = [json.loads(x) for x in FIXTURE.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(evaluate_jsonl(self.encode())['evaluation'], 'PASS')

    def encode(self, rows=None):
        return '\n'.join(json.dumps(x) for x in (self.rows if rows is None else rows))

    def reject(self, rows=None):
        with self.assertRaises(InvalidResult):
            evaluate_jsonl(self.encode(rows))

    def test_synthetic_prerequisite_success_is_not_runtime_or_cleanup(self):
        result = evaluate_jsonl(self.encode())
        self.assertEqual(result['scope'], 'SQL_PREREQUISITES_ONLY')
        self.assertEqual(result['runtime'], 'NOT_TESTED')
        self.assertEqual(result['cleanup'], 'NOT_TESTED')
        self.assertEqual(result['egress'], 'NOT_EXECUTED')

    def test_process_exit_alone_never_passes(self):
        for value in ('', '{}', '[]', 'null', self.encode(self.rows[:7])):
            with self.subTest(value=value[:20]), self.assertRaises(InvalidResult):
                evaluate_jsonl(value)
        with self.assertRaises(InvalidResult):
            evaluate_jsonl(self.encode(), sql_exit=1)

    def test_malformed_json_and_nonfinite(self):
        lines = self.encode().splitlines()
        for bad in ('{', 'null', '[]', 'true', '{"check":"C0-09","n":NaN}'):
            with self.subTest(bad=bad), self.assertRaises(InvalidResult):
                evaluate_jsonl('\n'.join([bad, *lines[1:]]))

    def test_duplicate_json_key(self):
        payload = self.encode().replace('"check": "C0-09"', '"check": "C0-09", "check": "C0-09"', 1)
        with self.assertRaises(InvalidResult):
            evaluate_jsonl(payload)

    def test_duplicate_unknown_extra_checks(self):
        rows = copy.deepcopy(self.rows)
        rows[1] = rows[0]
        self.reject(rows)
        rows[1] = {'check':'C0-UNKNOWN'}
        self.reject(rows)
        self.reject([*self.rows, self.rows[0]])

    def test_each_top_level_required_field_is_mandatory(self):
        for index, row in enumerate(self.rows):
            for key in row:
                with self.subTest(check=row['check'], field=key):
                    rows = copy.deepcopy(self.rows)
                    del rows[index][key]
                    self.reject(rows)

    def test_each_nested_required_field_is_mandatory(self):
        for index, field in ((1,'roles'),(2,'schemas'),(3,'relations'),(4,'available'),(5,'installed'),(6,'publications'),(7,'application_relations')):
            for key in self.rows[index][field][0]:
                with self.subTest(check=index, field=key):
                    rows = copy.deepcopy(self.rows)
                    del rows[index][field][0][key]
                    self.reject(rows)

    def test_unexpected_fields_fail(self):
        for index in range(len(self.rows)):
            with self.subTest(index=index):
                rows = copy.deepcopy(self.rows)
                rows[index]['unreviewed'] = True
                self.reject(rows)
        rows = copy.deepcopy(self.rows)
        rows[1]['roles'][0]['unreviewed'] = False
        self.reject(rows)

    def test_pg17_number_and_minor_consistency(self):
        for number in (160006,180000,True,170006.0,'170006'):
            with self.subTest(number=number):
                rows = copy.deepcopy(self.rows)
                rows[0]['server_version_num'] = number
                self.reject(rows)
        self.rows[0]['version'] = '17.7'
        self.reject()

    def test_false_prerequisite_booleans_fail(self):
        for index, key in ((0,'major_17'),(0,'postgres_session'),(7,'application_tables_absent'),(7,'managed_schema_absent')):
            rows = copy.deepcopy(self.rows)
            rows[index][key] = False
            self.reject(rows)
            rows[index][key] = 1
            self.reject(rows)
        self.rows[3]['relations'][1]['rls'] = False
        self.reject()

    def test_roles_attrs_missing_unknown_and_type(self):
        rows = copy.deepcopy(self.rows)
        rows[1]['roles'].pop()
        self.reject(rows)
        rows = copy.deepcopy(self.rows)
        rows[1]['roles'][2]['bypass_rls'] = True
        self.reject(rows)
        rows = copy.deepcopy(self.rows)
        rows[1]['roles'][0]['login'] = 'true'
        self.reject(rows)
        self.rows[0]['session_user'] = 'service_role'
        self.reject()

    def test_schema_relation_owner_and_rls(self):
        for index, key, field in ((2,'schemas','owner'),(3,'relations','owner')):
            rows = copy.deepcopy(self.rows)
            rows[index][key][0][field] = 'anon'
            self.reject(rows)
        self.rows[3]['relations'].pop()
        self.reject()

    def test_extensions_preload_and_cron_fail_closed(self):
        for key,value in (('preload','pg_stat_statements'),('preload','pg_cron,evil'),('cron_database',None),('cron_database','other')):
            rows = copy.deepcopy(self.rows)
            rows[5][key] = value
            self.reject(rows)
        self.rows[5]['installed'][1]['schema'] = 'public'
        self.reject()

    def test_available_but_uninstalled_extensions(self):
        self.rows[5]['installed'] = []
        self.rows[2]['schemas'] = [x for x in self.rows[2]['schemas'] if x['name'] != 'cron']
        for item in self.rows[4]['available']:
            item['installed_version'] = None
        self.assertEqual(evaluate_jsonl(self.encode())['evaluation'], 'PASS')

    def test_c014_empty_aggregate_collector_parser_contract(self):
        # SQL text assertion only; this does not execute or validate PostgreSQL.
        sql = (Path(__file__).resolve().parents[1] / 'sql/c0-readonly.sql').read_text(encoding='utf-8')
        collector = sql.split("SELECT jsonb_build_object('check', 'C0-14',", 1)[1].split(';', 1)[0]
        expected = """'installed', coalesce(jsonb_agg(jsonb_build_object(
          'name', e.extname, 'version', e.extversion, 'schema', n.nspname,
          'owner', pg_get_userbyid(e.extowner))), '[]'::jsonb)"""
        self.assertIn(' '.join(expected.split()), ' '.join(collector.split()))

        empty = copy.deepcopy(self.rows)
        empty[5]['installed'] = []
        empty[2]['schemas'] = [x for x in empty[2]['schemas'] if x['name'] != 'cron']
        for item in empty[4]['available']:
            item['installed_version'] = None
        result = evaluate_jsonl(self.encode(empty))
        self.assertEqual(result['evaluation'], 'PASS')
        self.assertEqual(result['runtime'], 'NOT_TESTED')
        self.assertEqual(result['cleanup'], 'NOT_TESTED')
        self.assertEqual(result['egress'], 'NOT_EXECUTED')

        cases = []
        rows = copy.deepcopy(empty)
        rows[5]['installed'] = None
        cases.append(('null installed', rows, 'INSTALLED_EXTENSION_SHAPE'))
        rows = copy.deepcopy(empty)
        rows[4]['available'] = [x for x in rows[4]['available'] if x['name'] != 'pg_cron']
        cases.append(('missing required extension', rows, 'EXTENSION_AVAILABILITY'))
        rows = copy.deepcopy(empty)
        rows[5]['preload'] = 'pg_stat_statements'
        cases.append(('invalid preload', rows, 'PG_CRON_PRELOAD'))
        rows = copy.deepcopy(empty)
        rows[5]['cron_database'] = 'other'
        cases.append(('wrong cron database', rows, 'PG_CRON_DATABASE'))
        rows = copy.deepcopy(empty)
        rows[4]['available'][0]['installed_version'] = '1.3'
        cases.append(('contradictory installation metadata', rows, 'INSTALLED_EXTENSION_MISSING'))
        for name, rows, code in cases:
            with self.subTest(case=name), self.assertRaisesRegex(InvalidResult, '^' + code + '$'):
                evaluate_jsonl(self.encode(rows))

    def test_publication_contract(self):
        self.rows[6]['publications'][0]['insert'] = False
        self.reject()

    def test_complete_application_inventory(self):
        rows = copy.deepcopy(self.rows)
        rows[7]['application_relations'].pop()
        self.reject(rows)
        rows = copy.deepcopy(self.rows)
        rows[7]['application_relations'][0]['absent'] = False
        self.reject(rows)
        self.rows[7]['public_relations'] = ['unexpected_table']
        self.reject()

    def test_empty_migration_schema_allowed(self):
        self.rows[7]['migration_schema_exists'] = True
        self.assertEqual(evaluate_jsonl(self.encode())['evaluation'], 'PASS')

    def test_exact_empty_migration_table_allowed(self):
        row = self.rows[7]
        row.update(migration_schema_exists=True, migration_relation='supabase_migrations.schema_migrations',
                   migration_relation_kind='r', migration_history_relations=['schema_migrations'])
        self.assertEqual(evaluate_jsonl(self.encode())['evaluation'], 'PASS')

    def test_migration_wrong_rows_and_state_fail(self):
        for key,value in (('migration_row_count',1),('migration_row_count',False),('migration_history_relations',['seed_files']),
                          ('migration_relation','supabase_migrations.other'),('migration_schema_exists',None)):
            rows = copy.deepcopy(self.rows)
            rows[7][key] = value
            self.reject(rows)

    def test_unexecuted_cleanup_cannot_pass(self):
        with self.assertRaisesRegex(Denied, 'CLEANUP_RUNTIME_NOT_TESTED'):
            cleanup()

    def test_controller_comparison_with_synthetic_external_approval(self):
        # Synthetic fixture only: not approval of a real project revision.
        approval = {'approval_state':'INDEPENDENTLY_APPROVED','approved_revision':'a'*40,
                    'repository':'piotrfpn/omninauka-ci-lab'}
        verify_controller_revision('a'*40, approval)
        with self.assertRaisesRegex(Denied, 'CONTROLLER_REVISION_MISMATCH'):
            verify_controller_revision('b'*40, approval)
        with self.assertRaisesRegex(Denied, 'CONTROLLER_REVISION_UNAPPROVED'):
            verify_controller_revision('a'*40, {'approval_state':'UNAPPROVED','approved_revision':None})


if __name__ == '__main__':
    unittest.main()
