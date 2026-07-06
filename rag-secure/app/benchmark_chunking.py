"""D10 — Mini-benchmark empirique du chunking (hit-rate@k).

Justifie CHUNK_SIZE par la MESURE, pas par défaut (NOTES §3 D10) : la
littérature ne donne pas d'optimum universel — on mesure sur NOS données.

Protocole :
  - pour chaque taille (défaut 500 / 1000 / 2000), ingestion du MÊME
    sous-ensemble dans un SCHÉMA ISOLÉ ``rag_bench_<taille>`` (sinon
    collision ``doc_sha256 UNIQUE`` et contamination croisée) ;
  - ~100 questions de la colonne ``question`` (vérité terrain du dataset) ;
  - hit = le document d'origine (par ``doc_sha256``) apparaît dans le top-k
    BRUT (avant seuil : on isole l'effet de la taille, pas du seuil) ;
  - recouvrement maintenu CONSTANT (CHUNK_OVERLAP) : une seule variable.

Réutilise les chaînes de production (run_ingest, make_splitter,
embed_question, db.search_similar) — pas de duplication (SPEC §3.4).

Rôle : ``rag_admin`` UNIQUEMENT (outillage — création de schémas jetables).
HORS du chemin de production. Lancé par l'étudiant (Docker + modèles requis) :
    docker exec rag-app python benchmark_chunking.py --n-docs 200
Écrit ``/logs/benchmark_chunking.md`` (/app est monté RO) ; copier ensuite
vers ``resultats/benchmark_chunking.md`` (README §Benchmark).
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import db
from config import Config, get_config
from ingest import load_rows, make_embedder, make_splitter, run_ingest
from logutil import get_logger, log_event
from query import embed_question
from security.integrity import sha256_norm

DEFAULT_SIZES = (500, 1000, 2000)


def benchmark_size(
    cfg: Config,
    admin_conn,
    embedder,
    rows: list[dict[str, Any]],
    *,
    size: int,
    k: int,
    n_questions: int,
    logger,
) -> dict[str, Any]:
    """Ingestion + mesure du hit-rate@k pour UNE taille de chunk."""
    schema = f"rag_bench_{size}"
    log_event(logger, "bench_size_start", schema=schema, chunk_size=size)
    db.create_bench_schema(admin_conn, schema)

    splitter = make_splitter(cfg, chunk_size=size)
    started = time.perf_counter()
    ingest_stats = run_ingest(cfg, rows, conn=admin_conn, embedder=embedder,
                              splitter=splitter, schema=schema, logger=logger)
    ingest_seconds = time.perf_counter() - started

    # Questions des documents réellement ingérés (les quarantainés/doublons
    # sortent du périmètre — identiques pour toutes les tailles : la garde
    # S7 intervient AVANT le chunking).
    candidates = [row for row in rows if str(row.get("question", "")).strip()]
    questions: list[dict[str, Any]] = []
    for row in candidates:
        doc_sha = sha256_norm(row["context"])
        if db.get_document_id_by_sha(admin_conn, doc_sha, schema=schema) is not None:
            questions.append({"question": row["question"], "doc_sha256": doc_sha})
        if len(questions) >= n_questions:
            break

    hits = 0
    hit_similarities: list[float] = []
    query_ms: list[float] = []
    for item in questions:
        vector = embed_question(embedder, item["question"], cfg)
        t0 = time.perf_counter()
        found = db.search_similar(admin_conn, qvec=vector, k=k,
                                  key=cfg.pgcrypto_key, schema=schema)
        query_ms.append((time.perf_counter() - t0) * 1000)
        matching = [row for row in found
                    if row["doc_sha256"].strip() == item["doc_sha256"]]
        if matching:
            hits += 1
            hit_similarities.append(max(float(r["similarity"]) for r in matching))

    result = {
        "chunk_size": size,
        "schema": schema,
        "chunks": ingest_stats["chunks"],
        "documents": ingest_stats["ingested"],
        "questions": len(questions),
        "hits": hits,
        "hit_rate": round(hits / len(questions), 3) if questions else 0.0,
        "mean_hit_similarity": round(statistics.mean(hit_similarities), 4)
        if hit_similarities else None,
        "ingest_seconds": round(ingest_seconds, 1),
        "mean_query_ms": round(statistics.mean(query_ms), 1) if query_ms else None,
    }
    log_event(logger, "bench_size_done", **result)
    return result


def render_markdown(cfg: Config, results: list[dict[str, Any]],
                    *, k: int, n_docs: int) -> str:
    """Tableau comparatif → resultats/benchmark_chunking.md (gabarit D10)."""
    lines = [
        "# Benchmark chunking (D10) — hit-rate@k mesuré",
        "",
        f"- Modèle d'embedding : `{cfg.embed_model_tag}` (préfixes nomic)",
        f"- k = {k} · recouvrement constant = {cfg.chunk_overlap} · "
        f"documents = {n_docs} · graine = {cfg.seed}",
        "- Hit = le document d'origine (doc_sha256) apparaît dans le top-k "
        "brut (avant seuil).",
        "",
        "| Taille (car.) | Chunks | Questions | Hit-rate@k | Similarité moy. des hits "
        "| Ingestion (s) | Requête moy. (ms) |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        lines.append(
            f"| {r['chunk_size']} | {r['chunks']} | {r['questions']} "
            f"| **{r['hit_rate']:.3f}** | {r['mean_hit_similarity'] or '—'} "
            f"| {r['ingest_seconds']} | {r['mean_query_ms'] or '—'} |"
        )
    best = max(results, key=lambda r: r["hit_rate"]) if results else None
    if best:
        lines += [
            "",
            f"**Lecture** : meilleur hit-rate@{k} pour une taille de "
            f"{best['chunk_size']} caractères ({best['hit_rate']:.3f}). "
            f"La baseline retenue dans `.env` est CHUNK_SIZE={cfg.chunk_size} — "
            "à confirmer/ajuster d'après ce tableau (D10).",
        ]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark D10 : hit-rate@k selon la taille de chunk "
                    "(schémas isolés rag_bench_*, rôle rag_admin)."
    )
    parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)),
                        help="tailles à comparer, séparées par des virgules")
    parser.add_argument("--n-docs", type=int, default=200,
                        help="documents ingérés par taille (défaut 200)")
    parser.add_argument("--n-questions", type=int, default=100,
                        help="questions de vérité terrain (défaut 100)")
    parser.add_argument("-k", type=int, default=None, help="top-k (défaut $TOP_K)")
    parser.add_argument("--out", type=Path, default=Path("/logs/benchmark_chunking.md"),
                        help="fichier markdown produit (défaut /logs/… ; "
                             "copier ensuite vers resultats/)")
    parser.add_argument("--keep-schemas", action="store_true",
                        help="conserve les schémas rag_bench_* (défaut : supprimés)")
    args = parser.parse_args(argv)

    cfg = get_config()
    logger = get_logger("ingest")  # composant ingest : le bench est de l'outillage
    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    k = args.k or cfg.top_k

    rows = load_rows(cfg.dataset_file, n_docs=args.n_docs, seed=cfg.seed)
    embedder = make_embedder(cfg)
    admin_conn = db.connect_admin(cfg)  # outillage uniquement (SPEC §3.2)

    results: list[dict[str, Any]] = []
    try:
        for size in sizes:
            if cfg.chunk_overlap >= size:
                print(f"[!] taille {size} ignorée : CHUNK_OVERLAP="
                      f"{cfg.chunk_overlap} doit être < taille", file=sys.stderr)
                continue
            results.append(
                benchmark_size(cfg, admin_conn, embedder, rows,
                               size=size, k=k, n_questions=args.n_questions,
                               logger=logger)
            )
        markdown = render_markdown(cfg, results, k=k, n_docs=args.n_docs)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(markdown, encoding="utf-8")
        print(markdown)
        print(f"[i] Écrit : {args.out} — copier vers resultats/benchmark_chunking.md "
              f"(cf. README).", file=sys.stderr)
    finally:
        if not args.keep_schemas:
            for size in sizes:
                db.drop_bench_schema(admin_conn, f"rag_bench_{size}")
        admin_conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
