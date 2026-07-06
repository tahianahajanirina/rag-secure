"""P1 — Téléchargement du dataset sur l'HÔTE (hors conteneur, SPEC §3.6).

Télécharge ``neural-bridge/rag-dataset-12000`` (3 colonnes : ``context`` =
connaissance ingérée ; ``question``/``answer`` = vérité terrain EF7/EF8,
JAMAIS ingérée) et écrit un JSONL déterministe dans ``./data/``.

Sélection DÉTERMINISTE (F1) : ``ds.shuffle(seed=SEED).select(range(n))``.

Ce script ne fait QUE ça (séparation des responsabilités — la génération
des secrets est dans 01_provision.ps1, étape gen_secrets). Il touche
UNIQUEMENT ``./data``.

Prérequis hôte : Python + ``pip install datasets`` (README §Prérequis).
Point UNIQUE, avec le pull des modèles, où le projet accède à Internet.

Usage :
    python scripts/download_dataset.py --n 1000 --seed 42 --out ./data/rag_subset.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DATASET_NAME = "neural-bridge/rag-dataset-12000"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Téléchargement déterministe du dataset (P1).")
    parser.add_argument("--n", type=int, default=1000, help="nombre de contextes (défaut 1000, D5)")
    parser.add_argument("--seed", type=int, default=42, help="graine de sélection (F1)")
    parser.add_argument("--out", type=Path, default=Path("./data/rag_subset.jsonl"),
                        help="fichier JSONL de sortie (monté RO dans rag-app)")
    parser.add_argument("--split", default="train", help="split HF (défaut train)")
    args = parser.parse_args(argv)

    try:
        from datasets import load_dataset
    except ImportError:
        print("ERREUR : le paquet 'datasets' est requis sur l'hôte "
              "(pip install datasets). Cf. README §Prérequis.", file=sys.stderr)
        return 1

    print(f"[i] Chargement de {DATASET_NAME} (split={args.split})…", file=sys.stderr)
    dataset = load_dataset(DATASET_NAME, split=args.split)

    # Vérification du schéma réel (SPEC §3.6 : si les colonnes diffèrent,
    # échouer clairement plutôt que produire un fichier inutilisable).
    colonnes = set(dataset.column_names)
    attendues = {"context", "question", "answer"}
    if not attendues.issubset(colonnes):
        print(f"ERREUR : colonnes {sorted(colonnes)} — attendu au moins "
              f"{sorted(attendues)}. Schéma du dataset modifié ? "
              f"# TODO(conception): ajuster les noms de colonnes.", file=sys.stderr)
        return 2

    n = min(args.n, len(dataset))
    selection = dataset.shuffle(seed=args.seed).select(range(n))  # déterministe (F1)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for index, record in enumerate(selection):
            # source_id stable = position dans la sélection seedée (traçabilité).
            handle.write(json.dumps({
                "source_id": str(index),
                "context": record["context"],
                "question": record["question"],
                "answer": record["answer"],
            }, ensure_ascii=False) + "\n")

    print(f"[✓] {n} contextes écrits dans {args.out} "
          f"(seed={args.seed}). Colonnes question/answer = vérité terrain "
          f"EF7/EF8, jamais ingérées.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
