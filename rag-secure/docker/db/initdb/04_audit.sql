-- ============================================================================
-- 04_audit.sql — Configuration pgaudit par rôle (S4 — SPEC §3.1, NOTES §5)
-- ----------------------------------------------------------------------------
-- Global (postgresql.conf) : pgaudit.log = 'write, ddl',
--                            pgaudit.log_parameter = off (invariant 5 :
--                            la clé pgcrypto passe en paramètre → jamais tracée).
-- Ici : les LECTURES du pipeline de requête (rag_reader) sont tracées en plus —
-- c'est la chaîne qui manipule les contenus déchiffrés (démo S3/S4).
-- ============================================================================

ALTER ROLE rag_reader SET pgaudit.log = 'read, write, ddl';

-- Trace lisible : nom des relations dans les entrées d'audit du reader.
ALTER ROLE rag_reader SET pgaudit.log_relation = on;
