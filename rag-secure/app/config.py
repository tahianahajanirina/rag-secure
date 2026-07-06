"""Configuration centralisée — lecture unique des variables d'env + secrets.

Contrats : SPEC §2.1 (variables d'environnement) et §2.2 (fichiers secrets).
Invariant 2 : les secrets sont lus depuis des FICHIERS montés
(`/run/secrets_rag/…`), jamais depuis des valeurs en dur ni des variables
d'environnement en clair. Aucune valeur sensible par défaut.

Usage : ``cfg = get_config()`` (chargé une seule fois, mis en cache).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


class ConfigError(RuntimeError):
    """Erreur de configuration : variable ou secret manquant/invalide."""


def read_secret(path: Path) -> str:
    """Lit un secret depuis son fichier (strip des blancs de fin).

    Cohérent avec ``$(cat …)`` côté shell (01_roles.sh) : les fins de ligne
    finales ne font jamais partie du secret.
    """
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise ConfigError(
            f"Secret manquant : {path} — lancer scripts/01_provision.ps1 "
            f"(étape gen_secrets) et vérifier le montage /run/secrets_rag."
        ) from exc
    if not value:
        raise ConfigError(f"Secret vide : {path}")
    return value


def _env(name: str, default: str | None = None) -> str:
    """Variable d'environnement obligatoire (sauf si un défaut est fourni)."""
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise ConfigError(f"Variable d'environnement manquante : {name} (cf. .env.example)")
    return value


@dataclass(frozen=True)
class Config:
    """Configuration typée du projet (SPEC §2.1). Secrets en ``repr=False``."""

    # --- PostgreSQL -----------------------------------------------------------
    pg_host: str
    pg_port: int
    pg_database: str
    admin_user: str
    ingest_user: str
    reader_user: str
    auditor_user: str
    # Mots de passe : on ne garde que les CHEMINS ; db.py lit le fichier au
    # moment de la connexion (minimise l'exposition en mémoire / repr / logs).
    admin_password_file: Path
    ingest_password_file: Path
    reader_password_file: Path
    auditor_password_file: Path

    # --- Clés applicatives (distinctes — invariant 8) ---------------------------
    pgcrypto_key: str = field(repr=False)   # S5 — passée en PARAMÈTRE SQL, jamais dans le texte
    hmac_key: bytes = field(repr=False)     # S8 — clé d'intégrité dédiée (≠ pgcrypto)

    # --- Ollama / modèles --------------------------------------------------------
    ollama_url: str
    llm_model: str
    embed_model: str
    embed_model_tag: str                    # identité versionnée D14 (chunks.embedding_model)
    embed_dim: int
    ollama_timeout: float

    # --- Paramètres RAG -----------------------------------------------------------
    chunk_size: int
    chunk_overlap: int
    top_k: int
    sim_threshold: float                    # seuil de SIMILARITÉ (= 1 - distance, invariant 8)
    num_ctx: int                            # invariant 12 : jamais le défaut 2048
    seed: int

    # --- Sécurité ingestion ---------------------------------------------------------
    injection_threshold: float              # S7 — score de mise en quarantaine

    # --- Chemins ----------------------------------------------------------------------
    dataset_file: Path
    log_dir: Path

    # --- Phase 2 (jetons distincts, D12) — None si les fichiers n'existent pas
    # encore ; api.py exige leur présence à SON démarrage.
    api_token: str | None = field(repr=False, default=None)
    admin_token: str | None = field(repr=False, default=None)

    def __post_init__(self) -> None:
        if self.embed_dim <= 0:
            raise ConfigError("EMBED_DIM doit être > 0")
        if not (0 < self.chunk_overlap < self.chunk_size):
            raise ConfigError("CHUNK_OVERLAP doit être dans ]0, CHUNK_SIZE[")
        if not (-1.0 <= self.sim_threshold <= 1.0):
            raise ConfigError("SIM_THRESHOLD est une similarité cosinus ∈ [-1, 1]")
        if self.top_k < 1:
            raise ConfigError("TOP_K doit être ≥ 1")
        if not (0.0 <= self.injection_threshold <= 1.0):
            raise ConfigError("INJECTION_THRESHOLD doit être ∈ [0, 1]")


def _optional_secret(path: Path) -> str | None:
    """Secret facultatif (jetons phase 2) : None si le fichier n'existe pas."""
    return read_secret(path) if path.is_file() else None


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Charge la configuration une seule fois (variables §2.1 + secrets §2.2)."""
    return Config(
        pg_host=_env("PG_HOST", "rag-db"),
        pg_port=int(_env("PG_PORT", "5432")),
        pg_database=_env("PG_DATABASE", "ragdb"),
        admin_user=_env("PG_ADMIN_USER", "rag_admin"),
        ingest_user=_env("PG_INGEST_USER", "rag_ingest"),
        reader_user=_env("PG_READER_USER", "rag_reader"),
        auditor_user=_env("PG_AUDITOR_USER", "rag_auditor"),
        admin_password_file=Path(_env("PG_ADMIN_PASSWORD_FILE")),
        ingest_password_file=Path(_env("PG_INGEST_PASSWORD_FILE")),
        reader_password_file=Path(_env("PG_READER_PASSWORD_FILE")),
        auditor_password_file=Path(_env("PG_AUDITOR_PASSWORD_FILE")),
        pgcrypto_key=read_secret(Path(_env("PGCRYPTO_KEY_FILE"))),
        # La clé HMAC sert telle quelle en octets (integrity.py) ; encodage
        # UTF-8 du contenu texte du fichier (hex généré par 01_provision.ps1).
        hmac_key=read_secret(Path(_env("HMAC_KEY_FILE"))).encode("utf-8"),
        ollama_url=_env("OLLAMA_URL", "http://rag-ollama:11434"),
        llm_model=_env("LLM_MODEL", "llama3.1:8b"),
        embed_model=_env("EMBED_MODEL", "nomic-embed-text"),
        embed_model_tag=_env("EMBED_MODEL_TAG", "nomic-embed-text@v1.5"),
        embed_dim=int(_env("EMBED_DIM", "768")),
        ollama_timeout=float(_env("OLLAMA_TIMEOUT", "120")),
        chunk_size=int(_env("CHUNK_SIZE", "1000")),
        chunk_overlap=int(_env("CHUNK_OVERLAP", "150")),
        top_k=int(_env("TOP_K", "4")),
        sim_threshold=float(_env("SIM_THRESHOLD", "0.35")),
        num_ctx=int(_env("NUM_CTX", "8192")),
        seed=int(_env("SEED", "42")),
        injection_threshold=float(_env("INJECTION_THRESHOLD", "0.5")),
        dataset_file=Path(_env("DATASET_FILE", "/data/rag_subset.jsonl")),
        log_dir=Path(_env("LOG_DIR", "/logs")),
        api_token=_optional_secret(Path(_env("API_TOKEN_FILE", "/run/secrets_rag/api_token"))),
        admin_token=_optional_secret(Path(_env("ADMIN_TOKEN_FILE", "/run/secrets_rag/admin_token"))),
    )
