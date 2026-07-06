"""F12/S4 — Journal applicatif JSON structuré (une ligne JSON par événement).

Schéma des lignes (contrat SPEC §2.4) :
    ts (ISO 8601 UTC) · level · event · component (ingest|query|api) ·
    request_id (phase 2, optionnel) · detail (objet)

Événements de sécurité obligatoires (constantes ci-dessous, à utiliser
partout — jamais de chaîne libre) : pii_pseudonymized, doc_quarantined,
hmac_mismatch, output_masked, below_threshold, auth_failed.

Invariant 5 : JAMAIS de clé (pgcrypto/HMAC) ni de contenu déchiffré dans les
logs — ne journaliser que des métadonnées (compteurs, hachés, références).

Module autonome : ne dépend PAS de config.py (utilisable par pytest sans
secrets). Destination : $LOG_DIR/app.jsonl (défaut /logs, cf. compose.yaml) ;
repli sur stderr seul si le répertoire n'est pas inscriptible.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# --- Événements de sécurité (contrat §2.4 — noms EXACTS, transverses) --------
EVT_PII_PSEUDONYMIZED = "pii_pseudonymized"
EVT_DOC_QUARANTINED = "doc_quarantined"
EVT_HMAC_MISMATCH = "hmac_mismatch"
EVT_OUTPUT_MASKED = "output_masked"
EVT_BELOW_THRESHOLD = "below_threshold"
EVT_AUTH_FAILED = "auth_failed"          # phase 2

_LOG_FILENAME = "app.jsonl"


class _JsonLineFormatter(logging.Formatter):
    """Formate chaque enregistrement en une ligne JSON (schéma §2.4)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
            "component": getattr(record, "component", record.name),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id
        payload["detail"] = getattr(record, "detail", {})
        return json.dumps(payload, ensure_ascii=False, default=str)


def _log_dir() -> Path:
    return Path(os.environ.get("LOG_DIR", "/logs"))


def get_logger(component: str) -> logging.Logger:
    """Logger JSON pour un composant (``ingest`` | ``query`` | ``api``).

    Écrit dans ``$LOG_DIR/app.jsonl`` (F12) et sur stderr (visible via
    ``docker logs rag-app``). Idempotent : les handlers ne sont posés qu'une
    fois par composant.
    """
    logger = logging.getLogger(f"rag.{component}")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = _JsonLineFormatter()

    stream = logging.StreamHandler(stream=sys.stderr)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    log_dir = _log_dir()
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / _LOG_FILENAME, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # Repli (hôte sans /logs) : stderr seul, mais on le signale.
        logger.warning(
            "log_dir_indisponible",
            extra={"event": "log_dir_indisponible", "component": component,
                   "detail": {"log_dir": str(log_dir)}},
        )
    return logger


def _component_of(logger: logging.Logger) -> str:
    return logger.name.split(".", 1)[1] if "." in logger.name else logger.name


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    request_id: str | None = None,
    **detail: Any,
) -> None:
    """Journalise un événement opérationnel (une ligne JSON, schéma §2.4)."""
    logger.log(
        level,
        event,
        extra={
            "event": event,
            "component": _component_of(logger),
            "request_id": request_id,
            "detail": detail,
        },
    )


def security_event(
    logger: logging.Logger,
    event: str,
    *,
    request_id: str | None = None,
    **detail: Any,
) -> None:
    """Journalise un événement de SÉCURITÉ (niveau WARNING — helper SPEC §3.2)."""
    log_event(logger, event, level=logging.WARNING, request_id=request_id, **detail)
