"""F7–F12 — Pipeline d'interrogation contextualisée (CLI, rôle ``rag_reader``).

Chaîne (page 4 du .drawio, SPEC §3.4) :
    F7  question (CLI ``--rag``/``--no-rag`` ; API web en phase 2)
    F8  embedding ``search_query:`` → garde D14 (un SEUL embedding_model)
        → top-k cosinus (similarité = 1 - distance, invariant 8) → seuil
        → vérification HMAC de CHAQUE chunk relu (texte + vecteur, D11)
    F9  prompt durci (spotlighting — S7)
    F10 génération Ollama (température 0,1 · num_ctx 8192 · graine fixe)
    F11 filtrage de sortie (S9)
    F12 journalisation JSON

``answer_question`` est RÉUTILISÉE telle quelle par l'API phase 2 (api.py)
et ``retrieve`` par le benchmark D10 — ne pas dupliquer ces chaînes.

Usage (depuis l'hôte) :
    docker exec rag-app python query.py "Ma question ?" --rag --show-sources
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from langchain_ollama import ChatOllama, OllamaEmbeddings

import db
from config import Config, get_config
from ingest import make_embedder  # même fabrique (cohérence des clients)
from logutil import (
    EVT_BELOW_THRESHOLD,
    EVT_HMAC_MISMATCH,
    EVT_OUTPUT_MASKED,
    get_logger,
    log_event,
    security_event,
)
from security.anonymize import URL_RE
from security.integrity import verify
from security.output_filter import filter_output, has_masking
from security.prompting import build_prompt

SEARCH_QUERY_PREFIX = "search_query: "  # préfixe nomic OBLIGATOIRE (invariant 12)


class EmbeddingSpaceError(RuntimeError):
    """Garde D14 : stock vectoriel incohérent avec le modèle configuré."""


# =============================================================================
# Fabriques
# =============================================================================

def make_chat(cfg: Config) -> ChatOllama:
    """Client de génération (F10) — options EXPLICITES (invariant 12) :
    ``num_ctx`` forcé (le défaut 2048 tronque silencieusement le contexte),
    graine fixe, température basse."""
    return ChatOllama(
        model=cfg.llm_model,
        temperature=0.1,
        num_ctx=cfg.num_ctx,
        seed=cfg.seed,
        base_url=cfg.ollama_url,
        client_kwargs={"timeout": cfg.ollama_timeout},
    )


def embed_question(embedder: OllamaEmbeddings, question: str, cfg: Config) -> list[float]:
    """Embedding de la question, préfixe ``search_query:`` (F8)."""
    vector = embedder.embed_query(SEARCH_QUERY_PREFIX + question)
    if len(vector) != cfg.embed_dim:
        raise RuntimeError(
            f"Dimension d'embedding inattendue : {len(vector)} ≠ EMBED_DIM={cfg.embed_dim}"
        )
    return vector


# =============================================================================
# F8 — retrieval sécurisé (garde D14 + seuil + vérification HMAC)
# =============================================================================

def check_embedding_space(cfg: Config, conn, *, schema: str = db.DEFAULT_SCHEMA,
                          logger=None) -> bool:
    """Garde D14 : refuse un stock mêlant plusieurs modèles d'embedding.

    Renvoie False si le stock est VIDE (aucun chunk) ; lève
    ``EmbeddingSpaceError`` si le stock est incomparable avec
    ``EMBED_MODEL_TAG`` (espaces vectoriels différents → recherche
    silencieusement corrompue sinon).
    """
    models = db.distinct_embedding_models(conn, schema=schema)
    if not models:
        return False
    if len(models) > 1:
        if logger:
            security_event(logger, "model_mismatch", models=models)
        raise EmbeddingSpaceError(
            f"Stock vectoriel MÊLÉ ({models}) : espaces incomparables — "
            f"ré-indexation complète requise (D14)."
        )
    if models[0] != cfg.embed_model_tag:
        if logger:
            security_event(logger, "model_mismatch",
                           stored=models[0], configured=cfg.embed_model_tag)
        raise EmbeddingSpaceError(
            f"Stock indexé avec '{models[0]}' ≠ EMBED_MODEL_TAG='{cfg.embed_model_tag}' : "
            f"vecteurs incomparables — ré-indexer ou corriger la configuration (D14)."
        )
    return True


def retrieve(
    cfg: Config,
    conn,
    question_vector: list[float],
    *,
    k: int | None = None,
    schema: str = db.DEFAULT_SCHEMA,
    logger=None,
    request_id: str | None = None,
) -> list[dict[str, Any]]:
    """Top-k → seuil de similarité → vérification HMAC (F8, S8/D11).

    Renvoie les chunks VALIDES au-dessus du seuil (peut être vide : aucun
    contexte ne sera injecté et la réponse le signalera).
    """
    k = k or cfg.top_k
    if not check_embedding_space(cfg, conn, schema=schema, logger=logger):
        if logger:
            log_event(logger, "empty_store", request_id=request_id, schema=schema)
        return []

    rows = db.search_similar(conn, qvec=question_vector, k=k,
                             key=cfg.pgcrypto_key, schema=schema)

    # Seuil sur la SIMILARITÉ (déjà convertie 1 - distance par db.py —
    # jamais la distance brute, invariant 8).
    kept = [row for row in rows if row["similarity"] >= cfg.sim_threshold]
    if rows and not kept:
        best = max(row["similarity"] for row in rows)
        if logger:
            security_event(logger, EVT_BELOW_THRESHOLD, request_id=request_id,
                           best_similarity=round(float(best), 4),
                           threshold=cfg.sim_threshold)
        return []

    # Vérification d'intégrité à CHAQUE lecture (invariant 8) : texte
    # déchiffré ET vecteur relu, position et document liés (D11).
    valid: list[dict[str, Any]] = []
    for row in kept:
        if verify(row["content"], row["doc_sha256"], row["chunk_index"],
                  row["embedding"], cfg.hmac_key, row["chunk_hmac"]):
            valid.append(row)
        elif logger:
            security_event(logger, EVT_HMAC_MISMATCH, request_id=request_id,
                           chunk_id=row["chunk_id"], source_ref=row["source_ref"],
                           chunk_index=row["chunk_index"],
                           doc_sha256=row["doc_sha256"])
    return valid


# =============================================================================
# F7→F12 — chaîne complète (réutilisée par api.py)
# =============================================================================

def answer_question(
    cfg: Config,
    question: str,
    *,
    mode: str = "rag",
    k: int | None = None,
    schema: str = db.DEFAULT_SCHEMA,
    conn=None,
    embedder: OllamaEmbeddings | None = None,
    chat: ChatOllama | None = None,
    logger=None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Répond à une question (mode ``rag`` ou ``no-rag``) — contrat §2.5.

    Retour : ``{answer, sources: [{source_ref, similarity}], mode,
    context_used, flags, request_id}``.
    """
    if mode not in ("rag", "no-rag"):
        raise ValueError(f"mode invalide : {mode!r} (attendu 'rag' ou 'no-rag')")

    logger = logger or get_logger("query")
    started = time.perf_counter()
    log_event(logger, "query_start", request_id=request_id, mode=mode, k=k or cfg.top_k)

    chunks: list[dict[str, Any]] = []
    if mode == "rag":
        embedder = embedder or make_embedder(cfg)
        own_conn = conn is None
        if own_conn:
            conn = db.connect_reader(cfg)
        try:
            vector = embed_question(embedder, question, cfg)
            chunks = retrieve(cfg, conn, vector, k=k, schema=schema,
                              logger=logger, request_id=request_id)
        finally:
            if own_conn:
                conn.close()

    # F9 — prompt durci (spotlighting) ; liste vide = « aucun contexte ».
    messages = build_prompt(question, chunks)

    # F10 — génération (options explicites, invariant 12).
    chat = chat or make_chat(cfg)
    answer_raw = chat.invoke(messages).content

    # F11 — filtrage de sortie : sources autorisées = refs des chunks + URLs
    # PRÉSENTES dans leur contenu (toute autre URL est neutralisée).
    allowed_sources: set[str] = set()
    for chunk in chunks:
        allowed_sources.add(str(chunk["source_ref"]))
        allowed_sources.update(URL_RE.findall(chunk["content"]))
    answer, flags = filter_output(answer_raw, allowed_sources)
    if has_masking(flags):
        security_event(logger, EVT_OUTPUT_MASKED, request_id=request_id, **flags)

    # F12 — journalisation du bilan (jamais de contenu, invariant 5).
    log_event(logger, "query_done", request_id=request_id, mode=mode,
              context_used=bool(chunks), n_chunks=len(chunks),
              duration_s=round(time.perf_counter() - started, 2))

    return {
        "answer": answer,
        "sources": [
            {"source_ref": chunk["source_ref"],
             "similarity": round(float(chunk["similarity"]), 4)}
            for chunk in chunks
        ],
        "mode": mode,
        "context_used": bool(chunks),
        "flags": flags,
        "request_id": request_id,
    }


# =============================================================================
# CLI
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Interrogation contextualisée du corpus (F7–F12, rôle rag_reader)."
    )
    parser.add_argument("question", help="question posée au système")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--rag", action="store_true", default=True,
                       help="mode RAG (défaut) : contexte récupéré dans le corpus")
    group.add_argument("--no-rag", dest="no_rag", action="store_true",
                       help="mode comparatif EF8 : AUCUN contexte injecté")
    parser.add_argument("-k", type=int, default=None,
                        help="nombre de chunks récupérés (défaut : $TOP_K)")
    parser.add_argument("--show-sources", action="store_true",
                        help="affiche les sources (source_ref, similarité)")
    parser.add_argument("--schema", default=db.DEFAULT_SCHEMA,
                        help="schéma interrogé (outillage D10 ; défaut : rag)")
    args = parser.parse_args(argv)

    cfg = get_config()
    mode = "no-rag" if args.no_rag else "rag"
    try:
        result = answer_question(cfg, args.question, mode=mode, k=args.k,
                                 schema=args.schema)
    except EmbeddingSpaceError as exc:
        print(f"REFUS (garde D14) : {exc}", file=sys.stderr)
        return 2

    if mode == "rag" and not result["context_used"]:
        print("[!] Aucun contexte injecté (stock vide ou similarité sous le "
              "seuil) — réponse SANS appui documentaire.\n", file=sys.stderr)

    print(result["answer"])
    if args.show_sources:
        print("\n--- Sources ---")
        if result["sources"]:
            for source in result["sources"]:
                print(f"  {source['source_ref']}  (similarité {source['similarity']:.4f})")
        else:
            print("  (aucune : pas de contexte injecté)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
