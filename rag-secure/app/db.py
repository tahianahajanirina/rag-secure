"""Accès PostgreSQL — connexions par rôle et requêtes paramétrées.

Contrats : SPEC §3.2. Invariants :
  - S2/S3 : une fabrique de connexion PAR RÔLE (moindre privilège) —
    ``connect_ingest`` (ingest.py), ``connect_reader`` (query.py),
    ``connect_auditor`` (/admin), ``connect_admin`` réservé au dev/outillage
    (schémas isolés du benchmark D10 — jamais utilisé par les pipelines).
  - Invariant 4 : SQL TOUJOURS paramétré (%(name)s) — jamais de f-string.
    Les identifiants dynamiques (schéma du benchmark) passent par
    ``psycopg.sql.Identifier`` (composition sûre, pas de concaténation).
  - Invariant 4/5 : la clé pgcrypto passe en PARAMÈTRE (jamais dans le texte
    SQL) et ``pgaudit.log_parameter = off`` garantit qu'elle n'atteint aucun
    journal. Aucune fonction de ce module ne journalise ses paramètres.
  - Invariant 8 : pgvector ``<=>`` renvoie une DISTANCE cosinus ; la
    similarité exposée partout est ``1 - (embedding <=> qvec)`` et l'ordre
    de tri est ``ORDER BY … <=> … ASC``.
  - DoD : ``register_vector`` est appelé sur CHAQUE connexion — sans lui,
    psycopg ne sait ni insérer ni relire une colonne ``vector``.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import psycopg
from pgvector.psycopg import register_vector
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from config import Config, read_secret

DEFAULT_SCHEMA = "rag"


# =============================================================================
# Connexions par rôle (S2/S3)
# =============================================================================

def _connect(cfg: Config, user: str, password_file, *,
             autocommit: bool = False) -> psycopg.Connection:
    """Connexion psycopg pour un rôle donné (mot de passe lu à la demande).

    ``autocommit=False`` (défaut) : les écritures se font en transaction
    explicite (« transaction par document » côté ingestion, SPEC §3.4).
    ``autocommit=True`` : réservé à l'outillage (``connect_admin``) — évite
    qu'un ``SELECT`` laisse une transaction « idle in transaction » ouverte
    pendant une longue génération ; sinon un crash du process laisserait un
    verrou bloquant le ``DROP SCHEMA`` des schémas jetables (rag_demo/bench).
    """
    password = read_secret(password_file)
    conn = psycopg.connect(
        host=cfg.pg_host,
        port=cfg.pg_port,
        dbname=cfg.pg_database,
        user=user,
        password=password,
        connect_timeout=10,
        autocommit=autocommit,
        row_factory=dict_row,
    )
    register_vector(conn)  # adaptation du type vector (lecture ET écriture)
    return conn


def connect_ingest(cfg: Config) -> psycopg.Connection:
    """Connexion du pipeline d'ingestion (rôle ``rag_ingest``)."""
    return _connect(cfg, cfg.ingest_user, cfg.ingest_password_file)


def connect_reader(cfg: Config) -> psycopg.Connection:
    """Connexion du pipeline de requête (rôle ``rag_reader``, lecture seule)."""
    return _connect(cfg, cfg.reader_user, cfg.reader_password_file)


def connect_auditor(cfg: Config) -> psycopg.Connection:
    """Connexion du tableau d'audit /admin (rôle ``rag_auditor``, phase 2)."""
    return _connect(cfg, cfg.auditor_user, cfg.auditor_password_file)


def connect_admin(cfg: Config) -> psycopg.Connection:
    """Connexion propriétaire (rôle ``rag_admin``).

    RÉSERVÉ au dev/outillage : création des schémas isolés du benchmark D10
    et des démos. Jamais utilisée par ingest.py / query.py / api.py (S3).
    ``autocommit=True`` : aucune transaction longue → aucun verrou résiduel
    si le process meurt pendant une génération (cf. _connect).
    """
    return _connect(cfg, cfg.admin_user, cfg.admin_password_file, autocommit=True)


# =============================================================================
# Aides internes
# =============================================================================

def _canon_embedding(embedding: Any) -> np.ndarray:
    """Quantifie le vecteur en float32 AVANT stockage.

    Cohérence D11 : le HMAC scelle la forme float32 (integrity._canon_vec) ;
    on stocke donc exactement ce qui a été scellé (pgvector stocke en float32).
    """
    return np.asarray(embedding, dtype=np.float32)


# =============================================================================
# Écritures (rôle rag_ingest)
# =============================================================================

def get_document_id_by_sha(
    conn: psycopg.Connection, doc_sha256: str, *, schema: str = DEFAULT_SCHEMA
) -> int | None:
    """Déduplication F1 : id du document déjà ingéré, sinon None."""
    query = sql.SQL(
        "SELECT id FROM {sch}.documents WHERE doc_sha256 = %(doc_sha256)s"
    ).format(sch=sql.Identifier(schema))
    row = conn.execute(query, {"doc_sha256": doc_sha256}).fetchone()
    return row["id"] if row else None


def insert_document(
    conn: psycopg.Connection,
    *,
    source_ref: str,
    doc_sha256: str,
    pii_stats: dict[str, int],
    schema: str = DEFAULT_SCHEMA,
) -> int:
    """Insère un document (F6) et renvoie son id (``ingested_by`` = rôle courant)."""
    query = sql.SQL(
        """
        INSERT INTO {sch}.documents (source_ref, doc_sha256, pii_stats)
        VALUES (%(source_ref)s, %(doc_sha256)s, %(pii_stats)s)
        RETURNING id
        """
    ).format(sch=sql.Identifier(schema))
    row = conn.execute(
        query,
        {
            "source_ref": source_ref,
            "doc_sha256": doc_sha256,
            "pii_stats": Jsonb(pii_stats),
        },
    ).fetchone()
    return row["id"]


def insert_chunk(
    conn: psycopg.Connection,
    *,
    document_id: int,
    chunk_index: int,
    text: str,
    embedding: Any,
    embedding_model: str,
    chunk_hmac: str,
    key: str,
    schema: str = DEFAULT_SCHEMA,
) -> None:
    """Insère un chunk : texte chiffré (S5, clé en PARAMÈTRE), vecteur float32,
    identité du modèle (D14) et sceau HMAC (S8/D11)."""
    query = sql.SQL(
        """
        INSERT INTO {sch}.chunks
            (document_id, chunk_index, content_enc, embedding, embedding_model, chunk_hmac)
        VALUES
            (%(document_id)s, %(chunk_index)s,
             pgp_sym_encrypt(%(text)s, %(key)s),
             %(embedding)s, %(embedding_model)s, %(chunk_hmac)s)
        """
    ).format(sch=sql.Identifier(schema))
    conn.execute(
        query,
        {
            "document_id": document_id,
            "chunk_index": chunk_index,
            "text": text,
            "key": key,
            "embedding": _canon_embedding(embedding),
            "embedding_model": embedding_model,
            "chunk_hmac": chunk_hmac,
        },
    )


def insert_quarantine(
    conn: psycopg.Connection,
    *,
    source_ref: str,
    reason: str,
    score: float,
    text: str,
    key: str,
    schema: str = DEFAULT_SCHEMA,
) -> None:
    """Met un document suspect en quarantaine (S7).

    Le contenu suspect est CHIFFRÉ comme les chunks (SPEC §3.2) : un document
    malveillant ou porteur de PII ne doit pas dormir en clair.
    """
    query = sql.SQL(
        """
        INSERT INTO {sch}.quarantine (source_ref, reason, score, content_enc)
        VALUES (%(source_ref)s, %(reason)s, %(score)s,
                pgp_sym_encrypt(%(text)s, %(key)s))
        """
    ).format(sch=sql.Identifier(schema))
    conn.execute(
        query,
        {"source_ref": source_ref, "reason": reason, "score": score,
         "text": text, "key": key},
    )


def log_ingest(
    conn: psycopg.Connection,
    *,
    operation: str,
    detail: str,
    ref_sha256: str | None,
    schema: str = DEFAULT_SCHEMA,
) -> None:
    """Trace côté base (F12/S4) — operation ∈ ingest|quarantine|dedup|verify."""
    query = sql.SQL(
        """
        INSERT INTO {sch}.ingest_log (operation, detail, ref_sha256)
        VALUES (%(operation)s, %(detail)s, %(ref_sha256)s)
        """
    ).format(sch=sql.Identifier(schema))
    conn.execute(
        query,
        {"operation": operation, "detail": detail, "ref_sha256": ref_sha256},
    )


# =============================================================================
# Lectures (rôle rag_reader)
# =============================================================================

def distinct_embedding_models(
    conn: psycopg.Connection, *, schema: str = DEFAULT_SCHEMA
) -> list[str]:
    """Garde D14 : identités de modèle présentes dans le stock vectoriel."""
    query = sql.SQL(
        "SELECT DISTINCT embedding_model FROM {sch}.chunks ORDER BY embedding_model"
    ).format(sch=sql.Identifier(schema))
    return [row["embedding_model"] for row in conn.execute(query).fetchall()]


def search_similar(
    conn: psycopg.Connection,
    *,
    qvec: Any,
    k: int,
    key: str,
    schema: str = DEFAULT_SCHEMA,
) -> list[dict[str, Any]]:
    """Recherche top-k par distance cosinus (F8).

    Contrat invariant 8 (à écrire tel quel) : ``<=>`` renvoie une DISTANCE ;
    la similarité exposée est ``1 - (embedding <=> qvec)`` ; on ordonne par
    distance ASC. Le SEUIL s'applique côté appelant sur ``similarity``
    (jamais sur la distance brute — logique inversée sinon).

    Renvoie par chunk : content (déchiffré), embedding (pour la revérification
    HMAC, D11), doc_sha256, source_ref, chunk_index, chunk_hmac,
    embedding_model, similarity.
    """
    query = sql.SQL(
        """
        SELECT
            c.id AS chunk_id,
            c.chunk_index,
            c.embedding,
            c.embedding_model,
            c.chunk_hmac,
            pgp_sym_decrypt(c.content_enc, %(key)s) AS content,
            d.doc_sha256,
            d.source_ref,
            1 - (c.embedding <=> %(qvec)s) AS similarity
        FROM {sch}.chunks c
        JOIN {sch}.documents d ON d.id = c.document_id
        ORDER BY c.embedding <=> %(qvec)s ASC
        LIMIT %(k)s
        """
    ).format(sch=sql.Identifier(schema))
    return conn.execute(
        query, {"qvec": _canon_embedding(qvec), "k": k, "key": key}
    ).fetchall()


# =============================================================================
# Lectures d'audit (rôle rag_auditor — phase 2, D13)
# =============================================================================
# Colonnes STRICTEMENT limitées aux GRANT par colonne de 03_grants.sql :
# jamais content_enc, rien sur chunks. count(colonne_autorisée) plutôt que
# count(*) (un count(*) échouerait avec des privilèges par colonne).

def auditor_recent_ingest_log(
    conn: psycopg.Connection, *, limit: int = 20
) -> list[dict[str, Any]]:
    """Dernières opérations d'ingestion (activité du tableau /admin)."""
    return conn.execute(
        """
        SELECT ts, operation, detail, ref_sha256
        FROM rag.ingest_log
        ORDER BY ts DESC
        LIMIT %(limit)s
        """,
        {"limit": limit},
    ).fetchall()


def auditor_quarantine_recent(
    conn: psycopg.Connection, *, limit: int = 20
) -> list[dict[str, Any]]:
    """Dernières mises en quarantaine — métadonnées seulement (jamais content_enc)."""
    return conn.execute(
        """
        SELECT source_ref, reason, score, detected_at
        FROM rag.quarantine
        ORDER BY detected_at DESC
        LIMIT %(limit)s
        """,
        {"limit": limit},
    ).fetchall()


def auditor_quarantine_count(conn: psycopg.Connection) -> int:
    """Nombre total de documents en quarantaine."""
    row = conn.execute("SELECT count(source_ref) AS n FROM rag.quarantine").fetchone()
    return row["n"]


def auditor_documents_overview(conn: psycopg.Connection) -> dict[str, Any]:
    """Agrégats du corpus pour /admin : volumétrie + somme des pii_stats (S6).

    L'agrégation JSON se fait côté Python (volumétrie ~10³ lignes) pour rester
    dans les colonnes autorisées (pii_stats, source_ref, ingested_at).
    """
    rows = conn.execute(
        "SELECT pii_stats, source_ref, ingested_at FROM rag.documents"
    ).fetchall()
    pii_totals: dict[str, int] = {}
    last_ingested = None
    for row in rows:
        for category, count in (row["pii_stats"] or {}).items():
            pii_totals[category] = pii_totals.get(category, 0) + int(count)
        if last_ingested is None or row["ingested_at"] > last_ingested:
            last_ingested = row["ingested_at"]
    return {
        "documents": len(rows),
        "pii_totals": pii_totals,
        "last_ingested_at": last_ingested,
    }


# =============================================================================
# Outillage benchmark D10 (rôle rag_admin UNIQUEMENT)
# =============================================================================

# Miroir du DDL de docker/db/initdb/02_schema.sql, paramétré par schéma —
# GARDER SYNCHRONE avec 02_schema.sql (source de vérité de la production).
# Sert exclusivement aux schémas isolés rag_bench_* du benchmark (D10) :
# chaque taille de chunk est ingérée à part (sinon collision doc_sha256
# UNIQUE et contamination croisée).
_BENCH_DDL = """
CREATE SCHEMA {sch};

CREATE TABLE {sch}.documents (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_ref  text        NOT NULL,
    doc_sha256  char(64)    NOT NULL UNIQUE,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    ingested_by text        NOT NULL DEFAULT current_user,
    pii_stats   jsonb       NOT NULL DEFAULT '{{}}'::jsonb
);

CREATE TABLE {sch}.chunks (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    document_id     bigint      NOT NULL REFERENCES {sch}.documents(id) ON DELETE CASCADE,
    chunk_index     int         NOT NULL,
    content_enc     bytea       NOT NULL,
    embedding       vector(768) NOT NULL,
    embedding_model text        NOT NULL,
    chunk_hmac      char(64)    NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (document_id, chunk_index)
);

CREATE INDEX ON {sch}.chunks USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE TABLE {sch}.quarantine (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_ref  text        NOT NULL,
    reason      text        NOT NULL,
    score       real        NOT NULL,
    content_enc bytea       NOT NULL,
    detected_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE {sch}.ingest_log (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts         timestamptz NOT NULL DEFAULT now(),
    operation  text        NOT NULL,
    detail     text,
    ref_sha256 char(64)
);
"""


def create_bench_schema(admin_conn: psycopg.Connection, schema: str) -> None:
    """(Re)crée un schéma isolé du benchmark D10 — connexion rag_admin requise.

    Le nom de schéma passe par ``sql.Identifier`` (composition sûre psycopg,
    pas de concaténation de chaîne).
    """
    ident = sql.Identifier(schema)
    admin_conn.execute(
        sql.SQL("DROP SCHEMA IF EXISTS {sch} CASCADE").format(sch=ident)
    )
    admin_conn.execute(sql.SQL(_BENCH_DDL).format(sch=ident))
    # Le benchmark tourne entièrement sous rag_admin (dev/outillage) :
    # aucun GRANT nécessaire sur les schémas jetables.
    admin_conn.commit()


def drop_bench_schema(admin_conn: psycopg.Connection, schema: str) -> None:
    """Supprime un schéma de benchmark (nettoyage)."""
    admin_conn.execute(
        sql.SQL("DROP SCHEMA IF EXISTS {sch} CASCADE").format(sch=sql.Identifier(schema))
    )
    admin_conn.commit()
