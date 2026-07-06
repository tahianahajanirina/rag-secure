-- ============================================================================
-- 02_schema.sql — Extensions + schéma rag.* + index HNSW (SPEC §2.3, page 5)
-- ----------------------------------------------------------------------------
-- Exécuté par l'entrypoint sous l'identité du superutilisateur bootstrap
-- rag_admin (POSTGRES_USER) → rag_admin est propriétaire du schéma et des
-- tables. Les droits des autres rôles arrivent APRÈS, dans 03_grants.sql.
--
-- Cohérence transverse : les noms de colonnes ci-dessous sont des CONTRATS
-- (db.py, ingest.py, query.py, api.py les utilisent à l'identique).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS vector;    -- pgvector (EF2)
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- chiffrement au repos (S5)
CREATE EXTENSION IF NOT EXISTS pgaudit;   -- audit (S4, préchargé via shared_preload_libraries)

CREATE SCHEMA rag AUTHORIZATION rag_admin;

-- ----------------------------------------------------------------------------
-- Documents ingérés (un document = un « context » du dataset)
-- ----------------------------------------------------------------------------
CREATE TABLE rag.documents (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_ref  text        NOT NULL,                       -- référence dataset (ex. rag12000:42)
    doc_sha256  char(64)    NOT NULL UNIQUE,                -- dédup F1 : SHA-256 du contexte brut normalisé
    ingested_at timestamptz NOT NULL DEFAULT now(),
    ingested_by text        NOT NULL DEFAULT current_user,
    pii_stats   jsonb       NOT NULL DEFAULT '{}'::jsonb    -- compteurs S6 (ex. {"EMAIL": 2})
);

-- ----------------------------------------------------------------------------
-- Chunks : texte chiffré (S5), vecteur en clair (D8), scellé par HMAC (S8/D11)
-- ----------------------------------------------------------------------------
CREATE TABLE rag.chunks (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    document_id     bigint      NOT NULL REFERENCES rag.documents(id) ON DELETE CASCADE,
    chunk_index     int         NOT NULL,
    content_enc     bytea       NOT NULL,                   -- pgp_sym_encrypt (S5), clé hors base
    embedding       vector(768) NOT NULL,                   -- en clair : contrainte d'indexation pgvector (D8) — dim = EMBED_DIM
    embedding_model text        NOT NULL,                   -- épinglage de l'espace vectoriel (D14), ex. nomic-embed-text@v1.5
    chunk_hmac      char(64)    NOT NULL,                   -- HMAC-SHA256(texte ‖ doc_sha256 ‖ chunk_index ‖ vecteur) — D11
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (document_id, chunk_index)
);

-- Index de recherche : distance cosinus (rappel invariant 8 : `<=>` renvoie
-- une DISTANCE ; la similarité exposée = 1 - distance, cf. db.py).
CREATE INDEX chunks_embedding_hnsw
    ON rag.chunks
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- ----------------------------------------------------------------------------
-- Quarantaine : documents suspects (S7) — contenu chiffré comme les chunks
-- ----------------------------------------------------------------------------
CREATE TABLE rag.quarantine (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_ref  text        NOT NULL,
    reason      text        NOT NULL,                       -- motifs détectés (S7)
    score       real        NOT NULL,
    content_enc bytea       NOT NULL,                       -- jamais en clair, même suspect
    detected_at timestamptz NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- Journal d'ingestion côté base (F12/S4) — operation ∈ ingest|quarantine|dedup|verify
-- ----------------------------------------------------------------------------
CREATE TABLE rag.ingest_log (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts         timestamptz NOT NULL DEFAULT now(),
    operation  text        NOT NULL,
    detail     text,
    ref_sha256 char(64)
);
