"""Offline, strict JSONL prerequisite evaluator. Does not execute SQL or mark C0 PASS."""
import json
from pathlib import Path
import re

CHECKS = ('C0-09', 'C0-10', 'C0-11', 'C0-12', 'C0-13', 'C0-14', 'C0-15', 'C0-17')


class InvalidResult(ValueError):
    pass


def require(value, code):
    if not value:
        raise InvalidResult(code)


def exact(value, fields, code):
    require(type(value) is dict and set(value) == set(fields), code)


def text(value):
    return type(value) is str and 0 < len(value) <= 256


def named(values, key, fields, code):
    require(type(values) is list and len(values) <= 100, code)
    out = {}
    for row in values:
        exact(row, fields, code)
        require(text(row[key]) and row[key] not in out, code)
        out[row[key]] = row
    return out


def no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out


def invalid_constant(_):
    raise InvalidResult('NONFINITE_JSON')


def evaluate_jsonl(payload, sql_exit=0, contract=None):
    require(type(sql_exit) is int and sql_exit == 0, 'SQL_PROCESS_FAILED')
    require(type(payload) is str and len(payload.encode('utf-8')) <= 262144, 'RESULT_SIZE_OR_TYPE')
    if contract is None:
        contract = json.loads((Path(__file__).parent / 'contracts/c0-assertions.json').read_bytes())
    lines = [line for line in payload.splitlines() if line.strip()]
    require(len(lines) == len(CHECKS), 'MISSING_OR_EXTRA_CHECK')
    records = {}
    try:
        for line in lines:
            obj = json.loads(line, object_pairs_hook=no_duplicate_keys, parse_constant=invalid_constant)
            require(type(obj) is dict and obj.get('check') in CHECKS, 'UNKNOWN_CHECK')
            require(obj['check'] not in records, 'DUPLICATE_CHECK')
            records[obj['check']] = obj
    except (json.JSONDecodeError, RecursionError) as error:
        raise InvalidResult('MALFORMED_JSON') from error
    require(set(records) == set(CHECKS), 'MISSING_OR_EXTRA_CHECK')

    row = records['C0-09']
    exact(row, ('check','server_version_num','major_17','version','current_user','session_user','postgres_session'), 'PG_FIELDS')
    n = row['server_version_num']
    require(type(n) is int and 170000 <= n < 180000 and row['major_17'] is True, 'PG17_REQUIRED')
    minor = re.fullmatch(r'17\.(\d+)(?:\s[^\r\n]*)?', row['version']) if text(row['version']) else None
    require(minor is not None and int(minor[1]) == n % 10000, 'PG_VERSION_INCONSISTENT')
    require(row['current_user'] == row['session_user'] == 'postgres' and row['postgres_session'] is True, 'POSTGRES_SESSION_REQUIRED')

    row = records['C0-10']
    exact(row, ('check','roles'), 'ROLE_FIELDS')
    attrs = contract['role_attributes']
    roles = named(row['roles'], 'name', ['name', *attrs], 'ROLE_SHAPE')
    require(set(roles) == set(contract['role_constraints']), 'REQUIRED_ROLES')
    for name, role in roles.items():
        require(all(type(role[x]) is bool for x in attrs), 'ROLE_ATTRIBUTE_TYPE')
        require(all(role[x] is value for x, value in contract['role_constraints'][name].items()), 'ROLE_ATTRIBUTE_CONSTRAINT')

    row = records['C0-11']
    exact(row, ('check','schemas'), 'SCHEMA_FIELDS')
    schemas = named(row['schemas'], 'name', ('name','owner'), 'SCHEMA_SHAPE')
    require(set(contract['schema_owners']) <= set(schemas) <= set(contract['schema_owners']) | set(contract['optional_schema_owners']), 'SCHEMA_INVENTORY')
    owners = {**contract['schema_owners'], **contract['optional_schema_owners']}
    require(all(x['owner'] == owners[name] for name, x in schemas.items()), 'SCHEMA_OWNER')

    row = records['C0-12']
    exact(row, ('check','relations'), 'RELATION_FIELDS')
    require(type(row['relations']) is list and len(row['relations']) == 3, 'RELATION_INVENTORY')
    relation_map = {}
    for item in row['relations']:
        exact(item, ('schema','name','owner','rls','force_rls'), 'RELATION_SHAPE')
        require(text(item['schema']) and text(item['name']), 'RELATION_NAME')
        key = (item['schema'], item['name'])
        require(key not in relation_map and type(item['rls']) is bool and type(item['force_rls']) is bool, 'RELATION_DUPLICATE_OR_TYPE')
        relation_map[key] = item
    require(relation_map == {(x['schema'], x['name']): x for x in contract['relations']}, 'RELATION_OWNER_OR_RLS')

    row = records['C0-13']
    exact(row, ('check','available'), 'EXTENSION_FIELDS')
    available = named(row['available'], 'name', ('name','default_version','installed_version'), 'EXTENSION_SHAPE')
    required, allowed = set(contract['required_extensions']), set(contract['required_extensions'] + contract['optional_extensions'])
    require(required <= set(available) <= allowed, 'EXTENSION_AVAILABILITY')
    for item in available.values():
        require(text(item['default_version']) and (item['installed_version'] is None or text(item['installed_version'])), 'EXTENSION_VERSION_TYPE')

    row = records['C0-14']
    exact(row, ('check','installed','preload','cron_database','database'), 'CRON_FIELDS')
    installed = named(row['installed'], 'name', ('name','version','schema','owner'), 'INSTALLED_EXTENSION_SHAPE')
    require(set(installed) <= set(available), 'UNEXPECTED_INSTALLED_EXTENSION')
    for name, item in installed.items():
        require(text(item['version']) and item['version'] == available[name]['installed_version'], 'INSTALLED_EXTENSION_VERSION')
        require(item['schema'] == contract['installed_extension_schemas'][name] and item['owner'] in contract['installed_extension_owners'], 'INSTALLED_EXTENSION_OWNER_OR_SCHEMA')
    require(all((v['installed_version'] is None) == (name not in installed) for name,v in available.items()), 'INSTALLED_EXTENSION_MISSING')
    require(('cron' in schemas) == ('pg_cron' in installed), 'CRON_SCHEMA_INCONSISTENT')
    require(text(row['preload']), 'PRELOAD_TYPE')
    preload = [x.strip() for x in row['preload'].split(',')]
    require(len(preload) == len(set(preload)) and set(contract['required_preload_libraries']) <= set(preload)
            <= set(contract['allowed_preload_libraries']), 'PG_CRON_PRELOAD')
    require(row['database'] == row['cron_database'] == contract['database'], 'PG_CRON_DATABASE')

    row = records['C0-15']
    exact(row, ('check','publications'), 'PUBLICATION_FIELDS')
    require(type(row['publications']) is list and len(row['publications']) == 1, 'PUBLICATION_MISSING')
    pub = row['publications'][0]
    exact(pub, contract['publication'], 'PUBLICATION_SHAPE')
    require(all(type(pub[key]) is bool for key in ('all_tables','insert','update','delete','truncate')), 'PUBLICATION_BOOL_TYPE')
    require(pub == contract['publication'], 'PUBLICATION_CONTRACT')

    row = records['C0-17']
    exact(row, ('check','application_tables_absent','application_relations','public_relations','public_routines',
                'managed_schema_absent','migration_schema_exists','migration_relation','migration_relation_kind',
                'migration_history_relations','migration_row_count'), 'APPLICATION_SCOPE_FIELDS')
    require(row['application_tables_absent'] is True and row['managed_schema_absent'] is True, 'APPLICATION_SCHEMA_PRESENT')
    relations = named(row['application_relations'], 'qualified_name', ('qualified_name','absent'), 'APPLICATION_RELATION_SHAPE')
    require(set(relations) == set(contract['application_tables']) and all(x['absent'] is True for x in relations.values()), 'APPLICATION_RELATION_INVENTORY')
    require(row['public_relations'] == [] and type(row['public_relations']) is list
            and row['public_routines'] == [] and type(row['public_routines']) is list, 'UNEXPECTED_PUBLIC_OBJECT')
    require(type(row['migration_schema_exists']) is bool and type(row['migration_row_count']) is int
            and row['migration_row_count'] == 0, 'MIGRATION_ROWS')
    if row['migration_relation'] is None:
        require(row['migration_relation_kind'] is None and row['migration_history_relations'] == [], 'MIGRATION_HISTORY_ABSENCE')
    else:
        require(row['migration_schema_exists'] is True and row['migration_relation'] == contract['migration_relation']
                and row['migration_relation_kind'] == 'r' and row['migration_history_relations'] == ['schema_migrations'], 'MIGRATION_HISTORY_STATE')
    require(type(row['migration_history_relations']) is list, 'MIGRATION_HISTORY_TYPE')
    return {'evaluation': 'PASS', 'scope': 'SQL_PREREQUISITES_ONLY', 'checks_evaluated': list(CHECKS),
            'runtime': 'NOT_TESTED', 'cleanup': 'NOT_TESTED', 'egress': 'NOT_EXECUTED'}
