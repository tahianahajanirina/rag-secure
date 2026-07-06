"""F1–F6 — Pipeline d'ingestion sécurisée (CLI, rôle ``rag_ingest``).

Chaîne (page 3 du .drawio, SPEC §3.4) :
    F1 lecture /data (RO) + déduplication SHA-256 normalisé
    F2 pseudonymisation AVANT tout embedding/stockage (S6 — invariant 6)
    F3 garde anti-injection → quarantaine chiffrée si score ≥ seuil (S7)
    F4 chunking récursif (CHUNK_SIZE / CHUNK_OVERLAP, D10)
    F5 embeddings Ollama, préfixe ``search_document:`` (D3 — invariant 12)
    F6 HMAC (vecteur scellé, D11) + chiffrement pgcrypto + INSERT en
       transaction PAR DOCUMENT (rôle rag_ingest — S2/S3)

Contrat Ollama (SPEC §3.4) : accès via LangChain (``OllamaEmbeddings``),
préfixes nomic DANS le texte. Idempotence : ``documents.doc_sha256 UNIQUE``.

Usage (depuis l'hôte) :
    docker exec rag-app python ingest.py --n-docs 1000
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from pathlib import Path
from typing import Any

from langchain_ollama import OllamaEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

import db
from config import Config, get_config
from logutil import (
    EVT_DOC_QUARANTINED,
    EVT_PII_PSEUDONYMIZED,
    get_logger,
    log_event,
    security_event,
)
from security.anonymize import pseudonymize
from security.injection_guard import scan
from security.integrity import compute_hmac, sha256_norm

SEARCH_DOCUMENT_PREFIX = "search_document: "  # préfixe nomic OBLIGATOIRE (invariant 12)


# =============================================================================
# Fabriques (partagées avec benchmark_chunking.py — D10, pas de duplication)
# =============================================================================

def make_embedder(cfg: Config) -> OllamaEmbeddings:
    """Client d'embeddings LangChain → rag-ollama (timeout borné)."""
    return OllamaEmbeddings(
        model=cfg.embed_model,
        base_url=cfg.ollama_url,
        client_kwargs={"timeout": cfg.ollama_timeout},
    )


def make_splitter(cfg: Config, *, chunk_size: int | None = None) -> RecursiveCharacterTextSplitter:
    """Splitter récursif (D10) — ``chunk_size`` surchargable par le benchmark."""
    return RecursiveCharacterTextSplitter(
        chunk_size=chunk_size or cfg.chunk_size,
        chunk_overlap=cfg.chunk_overlap,
    )


def embed_texts(embedder: OllamaEmbeddings, texts: list[str], cfg: Config) -> list[list[float]]:
    """Embeddings de chunks, préfixe ``search_document:`` (F5).

    Vérifie la dimension (doit matcher ``vector(768)`` du schéma — EMBED_DIM).
    """
    vectors = embedder.embed_documents([SEARCH_DOCUMENT_PREFIX + t for t in texts])
    for vec in vectors:
        if len(vec) != cfg.embed_dim:
            raise RuntimeError(
                f"Dimension d'embedding inattendue : {len(vec)} ≠ EMBED_DIM={cfg.embed_dim} "
                f"(modèle {cfg.embed_model} — vérifier le schéma vector({cfg.embed_dim}))"
            )
    return vectors


# =============================================================================
# Lecture du dataset (F1)
# =============================================================================

def load_rows(
    dataset_file: Path, *, n_docs: int | None = None, seed: int | None = None
) -> list[dict[str, Any]]:
    """Lit le JSONL produit par scripts/download_dataset.py.

    Colonnes attendues : ``context`` (ingéré), ``question``/``answer``
    (vérité terrain EF7/EF8 — JAMAIS ingérées), ``source_id`` (traçabilité).
    La sélection déterministe primaire est faite AU TÉLÉCHARGEMENT
    (shuffle seedé, F1) ; ``seed`` ici re-mélange localement si fourni.
    """
    if not dataset_file.is_file():
        raise FileNotFoundError(
            f"Dataset introuvable : {dataset_file} — lancer scripts/01_provision.ps1 "
            f"(étape download_dataset) ; le fichier est monté RO sous /data."
        )
    rows: list[dict[str, Any]] = []
    with dataset_file.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if "context" not in record:
                # TODO(conception): le schéma réel du dataset devait être
                # vérifié au provisioning (SPEC §3.6) — colonne manquante ici.
                raise KeyError(
                    f"Colonne 'context' absente (ligne {line_number + 1} de {dataset_file})"
                )
            record.setdefault("source_id", f"line{line_number}")
            record["source_ref"] = f"rag12000:{record['source_id']}"
            rows.append(record)
    if seed is not None:
        random.Random(seed).shuffle(rows)
    return rows[:n_docs] if n_docs is not None else rows


# =============================================================================
# Traitement d'un document (F1→F6)
# =============================================================================

def process_document(
    conn,
    cfg: Config,
    row: dict[str, Any],
    splitter: RecursiveCharacterTextSplitter,
    embedder: OllamaEmbeddings,
    logger,
    *,
    schema: str = db.DEFAULT_SCHEMA,
) -> tuple[str, int]:
    """Ingère UN document en transaction ; renvoie ``(statut, n_chunks)``.

    Statuts : ``ingested`` | ``duplicate`` | ``quarantined`` | ``empty``.
    Les journaux ne portent JAMAIS de contenu — uniquement compteurs,
    hachés et références (invariant 5).
    """
    context: str = row["context"]
    source_ref: str = row["source_ref"]
    doc_sha = sha256_norm(context)  # F1 — sur le contexte BRUT normalisé (D11)

    # --- F1 : déduplication --------------------------------------------------
    if db.get_document_id_by_sha(conn, doc_sha, schema=schema) is not None:
        db.log_ingest(conn, operation="dedup",
                      detail=f"doublon ignoré ({source_ref})",
                      ref_sha256=doc_sha, schema=schema)
        conn.commit()
        log_event(logger, "doc_skipped_duplicate", source_ref=source_ref, doc_sha256=doc_sha)
        return "duplicate", 0

    # --- F2 : pseudonymisation AVANT tout embedding/stockage (S6) -------------
    text_pseudo, pii_stats = pseudonymize(context)
    if pii_stats:
        security_event(logger, EVT_PII_PSEUDONYMIZED,
                       source_ref=source_ref, doc_sha256=doc_sha, categories=pii_stats)

    # --- F3 : garde anti-injection (S7) ----------------------------------------
    score, reasons = scan(text_pseudo)
    if score >= cfg.injection_threshold:
        db.insert_quarantine(conn, source_ref=source_ref, reason=", ".join(reasons),
                             score=score, text=text_pseudo, key=cfg.pgcrypto_key,
                             schema=schema)
        db.log_ingest(conn, operation="quarantine",
                      detail=f"score={score:.2f} motifs={','.join(reasons)}",
                      ref_sha256=doc_sha, schema=schema)
        conn.commit()
        security_event(logger, EVT_DOC_QUARANTINED,
                       source_ref=source_ref, doc_sha256=doc_sha,
                       score=round(score, 3), reason=reasons)
        return "quarantined", 0

    # --- F4 : chunking ----------------------------------------------------------
    chunks = splitter.split_text(text_pseudo)
    if not chunks:
        log_event(logger, "doc_empty", source_ref=source_ref, doc_sha256=doc_sha)
        return "empty", 0

    # --- F5 : embeddings (préfixe search_document:) ------------------------------
    vectors = embed_texts(embedder, chunks, cfg)

    # --- F6 : sceau + chiffrement + INSERT en transaction par document -----------
    document_id = db.insert_document(conn, source_ref=source_ref,
                                     doc_sha256=doc_sha, pii_stats=pii_stats,
                                     schema=schema)
    for index, (chunk_text, vector) in enumerate(zip(chunks, vectors)):
        seal = compute_hmac(chunk_text, doc_sha, index, vector, cfg.hmac_key)  # D11 : vecteur scellé
        db.insert_chunk(conn, document_id=document_id, chunk_index=index,
                        text=chunk_text, embedding=vector,
                        embedding_model=cfg.embed_model_tag,  # D14
                        chunk_hmac=seal, key=cfg.pgcrypto_key, schema=schema)
    db.log_ingest(conn, operation="ingest",
                  detail=f"{len(chunks)} chunks ({source_ref})",
                  ref_sha256=doc_sha, schema=schema)
    conn.commit()
    log_event(logger, "doc_ingested", source_ref=source_ref, doc_sha256=doc_sha,
              chunks=len(chunks), pii=pii_stats)
    return "ingested", len(chunks)


# =============================================================================
# Boucle d'ingestion (réutilisée par benchmark_chunking.py)
# =============================================================================

def run_ingest(
    cfg: Config,
    rows: list[dict[str, Any]],
    *,
    conn=None,
    embedder: OllamaEmbeddings | None = None,
    splitter: RecursiveCharacterTextSplitter | None = None,
    schema: str = db.DEFAULT_SCHEMA,
    logger=None,
) -> dict[str, Any]:
    """Ingère une liste de documents ; renvoie le bilan (F12).

    Les dépendances injectables (conn/embedder/splitter) permettent au
    benchmark D10 de rejouer la MÊME chaîne dans un schéma isolé.
    """
    logger = logger or get_logger("ingest")
    embedder = embedder or make_embedder(cfg)
    splitter = splitter or make_splitter(cfg)
    own_conn = conn is None
    if own_conn:
        conn = db.connect_ingest(cfg)

    stats = {"ingested": 0, "duplicate": 0, "quarantined": 0, "empty": 0,
             "errors": 0, "chunks": 0}
    started = time.perf_counter()
    log_event(logger, "ingest_start", documents=len(rows), schema=schema)
    try:
        for row in rows:
            try:
                status, n_chunks = process_document(
                    conn, cfg, row, splitter, embedder, logger, schema=schema
                )
                stats[status] += 1
                stats["chunks"] += n_chunks
            except Exception as exc:  # un document en échec n'arrête pas le lot
                conn.rollback()
                stats["errors"] += 1
                log_event(logger, "doc_error", level=logging.ERROR,
                          source_ref=row.get("source_ref", "?"), error=str(exc))
    finally:
        if own_conn:
            conn.close()

    stats["duration_s"] = round(time.perf_counter() - started, 1)
    log_event(logger, "ingest_done", **stats)
    return stats


# =============================================================================
# CLI
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingestion sécurisée du corpus (F1–F6, rôle rag_ingest)."
    )
    parser.add_argument("--n-docs", type=int, default=None,
                        help="nombre de documents à ingérer (défaut : tout le fichier)")
    parser.add_argument("--seed", type=int, default=None,
                        help="re-mélange local déterministe (la sélection primaire "
                             "est déjà seedée au téléchargement)")
    parser.add_argument("--input", type=Path, default=None,
                        help="fichier JSONL (défaut : $DATASET_FILE)")
    parser.add_argument("--schema", default=db.DEFAULT_SCHEMA,
                        help="schéma cible (outillage D10 ; défaut : rag)")
    args = parser.parse_args(argv)

    cfg = get_config()
    logger = get_logger("ingest")
    rows = load_rows(args.input or cfg.dataset_file, n_docs=args.n_docs, seed=args.seed)
    stats = run_ingest(cfg, rows, schema=args.schema, logger=logger)

    print(
        f"Ingestion terminée en {stats['duration_s']} s : "
        f"{stats['ingested']} ingérés ({stats['chunks']} chunks), "
        f"{stats['duplicate']} doublons, {stats['quarantined']} en quarantaine, "
        f"{stats['empty']} vides, {stats['errors']} erreurs."
    )
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
