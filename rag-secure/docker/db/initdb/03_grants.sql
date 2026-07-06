-- ============================================================================
-- 03_grants.sql — Droits, moindre privilège jusqu'à la colonne
-- (S2/S3, D13 — NOTES §5, SPEC §3.1)
-- ----------------------------------------------------------------------------
-- Exécuté APRÈS 02_schema.sql : les tables existent (ordre alphanumérique
-- des hooks initdb — ne JAMAIS déplacer ces GRANT dans 01_roles.sh).
--
-- Rappel des rôles :
--   rag_admin   : propriétaire (superuser bootstrap) — DDL/migrations seulement
--   rag_ingest  : ingest.py
--   rag_reader  : query.py
--   rag_auditor : /admin (phase 2, D13)
--
-- Les colonnes IDENTITY ne demandent aucun GRANT de séquence (contrairement
-- à serial) : l'usage de la séquence interne est implicite.
-- ============================================================================

-- --- Accès à la base : uniquement les rôles du projet -----------------------
-- (nom de base résolu dynamiquement : les hooks tournent déjà dans POSTGRES_DB)
DO $$
BEGIN
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO rag_ingest, rag_reader, rag_auditor',
                   current_database());
END
$$;

-- --- Schéma rag : usage seul (aucun CREATE pour les rôles applicatifs) ------
GRANT USAGE ON SCHEMA rag TO rag_ingest, rag_reader, rag_auditor;

-- --- Schéma public : USAGE seul (utiliser, PAS créer) -----------------------
-- Les extensions vector et pgcrypto sont installées dans `public`. Comme
-- 01_roles.sh a fait `REVOKE ALL ON SCHEMA public FROM PUBLIC` (durcissement),
-- il faut re-accorder USAGE aux rôles applicatifs, sinon :
--   - pgvector.register_vector échoue (« vector type not found ») ;
--   - pgp_sym_encrypt/decrypt (pgcrypto) sont injoignables.
-- USAGE (et non CREATE) : les rôles peuvent UTILISER le type/les fonctions,
-- mais ne peuvent PAS créer d'objets dans public (le durcissement tient).
GRANT USAGE ON SCHEMA public TO rag_ingest, rag_reader, rag_auditor;

-- --- rag_ingest (ingest.py) --------------------------------------------------
-- Grille EXACTE de NOTES §5 (moindre privilège) :
--   documents, chunks : INSERT+SELECT (le SELECT sert à la déduplication
--     doc_sha256 et aux transactions d'insertion) ;
--   ingest_log        : INSERT SEUL (ingest.py n'y lit jamais) ;
--   quarantine        : INSERT SEUL (jamais de relecture des contenus suspects).
GRANT INSERT, SELECT ON rag.documents, rag.chunks TO rag_ingest;
GRANT INSERT         ON rag.ingest_log            TO rag_ingest;
GRANT INSERT         ON rag.quarantine            TO rag_ingest;

-- --- rag_reader (query.py) ----------------------------------------------------
-- Lecture seule ; RIEN sur quarantine : un contenu suspect n'est jamais
-- restituable par la chaîne de requête (NOTES §5).
GRANT SELECT ON rag.documents, rag.chunks, rag.ingest_log TO rag_reader;

-- --- rag_auditor (/admin, phase 2 — D13) --------------------------------------
-- Le moindre privilège descend jusqu'à la COLONNE : métadonnées seulement,
-- jamais content_enc, rien sur chunks.
GRANT SELECT ON rag.ingest_log TO rag_auditor;
GRANT SELECT (source_ref, reason, score, detected_at) ON rag.quarantine TO rag_auditor;
GRANT SELECT (pii_stats, source_ref, ingested_at)     ON rag.documents  TO rag_auditor;
