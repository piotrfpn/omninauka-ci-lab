BEGIN READ ONLY;
SELECT jsonb_build_object(
  'check', 'C0-09', 'server_version_num', current_setting('server_version_num')::int,
  'major_17', current_setting('server_version_num')::int / 10000 = 17,
  'version', current_setting('server_version'),
  'current_user', current_user, 'session_user', session_user,
  'postgres_session', current_user = 'postgres' AND session_user = 'postgres'
);
SELECT jsonb_build_object('check', 'C0-10', 'roles', jsonb_agg(jsonb_build_object(
  'name', rolname, 'superuser', rolsuper, 'inherit', rolinherit,
  'create_role', rolcreaterole, 'create_db', rolcreatedb, 'login', rolcanlogin,
  'bypass_rls', rolbypassrls)))
FROM pg_roles WHERE rolname IN (
  'postgres','anon','authenticated','service_role','supabase_admin','dashboard_user',
  'pg_database_owner','supabase_auth_admin','supabase_storage_admin','authenticator'
);
SELECT jsonb_build_object('check', 'C0-11', 'schemas', jsonb_agg(jsonb_build_object(
  'name', nspname, 'owner', pg_get_userbyid(nspowner))))
FROM pg_namespace WHERE nspname IN ('auth','storage','public','extensions','cron');
SELECT jsonb_build_object('check', 'C0-12', 'relations', jsonb_agg(jsonb_build_object(
  'schema', n.nspname, 'name', c.relname, 'owner', pg_get_userbyid(c.relowner),
  'rls', c.relrowsecurity, 'force_rls', c.relforcerowsecurity)))
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE (n.nspname = 'auth' AND c.relname = 'users')
   OR (n.nspname = 'storage' AND c.relname IN ('objects','buckets'));
SELECT jsonb_build_object('check', 'C0-13', 'available', jsonb_agg(jsonb_build_object(
  'name', name, 'default_version', default_version, 'installed_version', installed_version)))
FROM pg_available_extensions WHERE name IN ('pgcrypto','pg_cron','pgtap');
SELECT jsonb_build_object('check', 'C0-14', 'installed', coalesce(jsonb_agg(jsonb_build_object(
  'name', e.extname, 'version', e.extversion, 'schema', n.nspname,
  'owner', pg_get_userbyid(e.extowner))), '[]'::jsonb),
  'preload', current_setting('shared_preload_libraries'),
  'cron_database', current_setting('cron.database_name', true), 'database', current_database())
FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
WHERE e.extname IN ('pgcrypto','pg_cron','pgtap');
SELECT jsonb_build_object('check', 'C0-15', 'publications', jsonb_agg(jsonb_build_object(
  'name', pubname, 'owner', pg_get_userbyid(pubowner), 'all_tables', puballtables,
  'insert', pubinsert, 'update', pubupdate, 'delete', pubdelete, 'truncate', pubtruncate,
  'tables', (SELECT coalesce(jsonb_agg(schemaname || '.' || tablename ORDER BY schemaname, tablename), '[]'::jsonb)
    FROM pg_publication_tables WHERE pubname = 'supabase_realtime'))))
FROM pg_publication WHERE pubname = 'supabase_realtime';
WITH application_targets(schema_name, table_name) AS (VALUES
  ('public','admin_plan_actions'), ('public','child_profiles'), ('public','folders'),
  ('public','parental_consents'), ('public','payment_events'), ('public','profiles'),
  ('public','session_images'), ('public','study_sessions'), ('public','support_tickets'),
  ('public','tutor_messages'), ('public','tutor_threads'), ('public','under13_parent_notifications'),
  ('public','usage_events'), ('managed_child_private','identities'), ('managed_child_private','operations')
)
SELECT jsonb_build_object('check', 'C0-17', 'application_tables_absent',
  (SELECT bool_and(to_regclass(format('%I.%I', schema_name, table_name)) IS NULL) FROM application_targets),
  'application_relations', (SELECT jsonb_agg(jsonb_build_object(
    'qualified_name', schema_name || '.' || table_name,
    'absent', to_regclass(format('%I.%I', schema_name, table_name)) IS NULL)
    ORDER BY schema_name, table_name) FROM application_targets),
  'public_relations', (SELECT coalesce(jsonb_agg(c.relname ORDER BY c.relname), '[]'::jsonb)
    FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','f','S')),
  'public_routines', (SELECT coalesce(jsonb_agg(p.oid::regprocedure::text ORDER BY p.oid::regprocedure::text), '[]'::jsonb)
    FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid WHERE n.nspname = 'public'
      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass
        AND d.objid = p.oid AND d.deptype = 'e')),
  'managed_schema_absent', NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'managed_child_private'),
  'migration_schema_exists', EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'supabase_migrations'),
  'migration_relation', to_regclass('supabase_migrations.schema_migrations')::text,
  'migration_relation_kind', (SELECT relkind::text FROM pg_class WHERE oid = to_regclass('supabase_migrations.schema_migrations')),
  'migration_history_relations', (SELECT coalesce(jsonb_agg(c.relname ORDER BY c.relname), '[]'::jsonb)
    FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname = 'supabase_migrations' AND c.relkind IN ('r','p','v','m','f','S')),
  'migration_row_count', CASE WHEN to_regclass('supabase_migrations.schema_migrations') IS NULL THEN 0
    WHEN (SELECT relkind FROM pg_class WHERE oid = to_regclass('supabase_migrations.schema_migrations')) = 'r'
    THEN ((xpath('/table/row/row_count/text()', query_to_xml(
      'SELECT count(*) AS row_count FROM supabase_migrations.schema_migrations', false, false, '')))[1]::text)::bigint
    ELSE NULL END
);
ROLLBACK;
