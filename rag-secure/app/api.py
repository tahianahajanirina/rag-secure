"""Phase 2 — API web FastAPI : /query, /admin, /health (F7 web, F13 — D12/D13).

Durcissement (SPEC §2.5, invariant 11) :
  - aucun middleware CORS permissif (aucune origine générique autorisée) —
    l'UI est servie en same-origin ;
  - ``TrustedHostMiddleware`` limité à 127.0.0.1 / localhost ;
  - validation Pydantic STRICTE (longueur de question plafonnée, k borné,
    champs inconnus refusés) ;
  - jetons requête et admin DISTINCTS, comparés à temps constant
    (``secrets.compare_digest``) ; échec → 401 + événement ``auth_failed`` ;
  - ``request_id`` par requête, propagé au journal applicatif (corrélation
    access log ↔ app.jsonl) ;
  - surface minimale : /docs, /redoc et /openapi.json désactivés ;
  - en-têtes de sécurité (CSP sans AUCUNE origine externe, nosniff,
    frame-ancestors none) — zéro JS externe (D13) ;
  - timeouts : Ollama (client_kwargs), DB (connect_timeout) ;
  - /admin : rendu CÔTÉ SERVEUR, texte systématiquement échappé
    (``html.escape``), lectures via le rôle ``rag_auditor`` uniquement.

Exposition réseau (S1/D12) : la SEULE publication est ``127.0.0.1:8000``
côté hôte (compose.phase2.yaml). Dans le conteneur, uvicorn écoute sur les
interfaces internes (cf. note compose) — jamais publié ailleurs.

Démarrage (compose.phase2.yaml) :
    uvicorn api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import html
import json
import secrets
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

import db
from config import get_config
from logutil import EVT_AUTH_FAILED, get_logger, log_event, security_event
from query import EmbeddingSpaceError, answer_question, make_chat
from ingest import make_embedder

STATIC_DIR = Path(__file__).resolve().parent / "static"

cfg = get_config()
logger = get_logger("api")

# Jetons OBLIGATOIRES et DISTINCTS en phase 2 (fail fast au démarrage).
if not cfg.api_token or not cfg.admin_token:
    raise RuntimeError(
        "Phase 2 : API_TOKEN_FILE et ADMIN_TOKEN_FILE requis "
        "(générés par scripts/01_provision.ps1, montés sous /run/secrets_rag)."
    )
if cfg.api_token == cfg.admin_token:
    raise RuntimeError("Les jetons requête et admin doivent être DISTINCTS (D12).")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

# Clients partagés (initialisés paresseusement au premier appel).
_embedder = None
_chat = None


def _clients():
    global _embedder, _chat
    if _embedder is None:
        _embedder = make_embedder(cfg)
        _chat = make_chat(cfg)
    return _embedder, _chat


@app.middleware("http")
async def security_headers(request, call_next):
    """En-têtes de sécurité sur TOUTES les réponses (D13, anti-XSS).

    CSP : aucune origine externe autorisée ; les styles/scripts INLINE de nos
    deux pages statiques sont permis ('unsafe-inline') — zéro JS externe.
    """
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _check_token(provided: str | None, expected: str, *, request_id: str, path: str) -> None:
    """Comparaison à temps constant ; 401 + ``auth_failed`` sinon (T9)."""
    if provided is None or not secrets.compare_digest(
        provided.encode("utf-8"), expected.encode("utf-8")
    ):
        security_event(logger, EVT_AUTH_FAILED, request_id=request_id, path=path)
        raise HTTPException(status_code=401, detail="Jeton invalide ou absent.")


# =============================================================================
# Modèles Pydantic (validation stricte — §2.5)
# =============================================================================

class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # champs inconnus refusés

    question: str = Field(min_length=1, max_length=2000)
    mode: Literal["rag", "no-rag"] = "rag"
    k: int | None = Field(default=None, ge=1, le=10)


# =============================================================================
# Endpoints
# =============================================================================

@app.get("/health")
def health() -> dict[str, str]:
    """Sonde de vivacité — publique, sans jeton (contrat §2.5)."""
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """Page « poser une question » (statique, JS inline uniquement — D13)."""
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.post("/query")
def query(
    body: QueryRequest,
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> JSONResponse:
    """Interrogation du RAG — réutilise le pipeline de query.py (contrat §2.5)."""
    request_id = uuid.uuid4().hex[:12]
    _check_token(x_api_token, cfg.api_token, request_id=request_id, path="/query")

    embedder, chat = _clients()
    try:
        result = answer_question(
            cfg, body.question, mode=body.mode, k=body.k,
            embedder=embedder, chat=chat, logger=logger, request_id=request_id,
        )
    except EmbeddingSpaceError as exc:
        # Garde D14 : stock incomparable — indisponibilité assumée, message sûr.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception:
        # Jamais de détail interne vers le client ; trace côté serveur.
        log_event(logger, "api_error", request_id=request_id, path="/query")
        raise HTTPException(status_code=500, detail="Erreur interne.") from None

    return JSONResponse(
        {
            "answer": result["answer"],
            "sources": result["sources"],
            "mode": result["mode"],
            "request_id": request_id,
            # Champ additionnel (UI) : contexte réellement injecté ou non.
            "context_used": result["context_used"],
        }
    )


# =============================================================================
# /admin — tableau d'audit (F13, D13) : rendu serveur, tout échappé
# =============================================================================

def _esc(value: Any) -> str:
    """Échappement systématique — TOUTE valeur insérée dans le HTML y passe."""
    return html.escape(str(value), quote=True)


def _row(cells: list[Any]) -> str:
    return "<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in cells) + "</tr>"


def _tail_app_log(max_lines: int = 5000) -> list[dict[str, Any]]:
    """Dernières lignes du journal applicatif JSON (alertes F13)."""
    log_file = cfg.log_dir / "app.jsonl"
    if not log_file.is_file():
        return []
    entries: list[dict[str, Any]] = []
    for line in log_file.read_text(encoding="utf-8").splitlines()[-max_lines:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # ligne corrompue : ignorée (le fichier reste la preuve)
    return entries


def _ollama_reachable() -> bool:
    try:
        with urllib.request.urlopen(f"{cfg.ollama_url}/api/tags", timeout=3):
            return True
    except Exception:
        return False


@app.get("/admin", response_class=HTMLResponse)
def admin(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> str:
    """Tableau d'audit en LECTURE SEULE (rôle rag_auditor, jeton admin distinct).

    Sources : base (ingest_log, métadonnées quarantine, pii_stats — GRANT par
    colonne) + journal applicatif JSON. Les fichiers restent la source de
    vérité probante (D13) ; cette page est la vue « facteur humain ».
    """
    request_id = uuid.uuid4().hex[:12]
    _check_token(x_admin_token, cfg.admin_token, request_id=request_id, path="/admin")

    # --- Santé -----------------------------------------------------------------
    db_ok = False
    overview: dict[str, Any] = {}
    quarantine_count = 0
    quarantine_rows: list[dict[str, Any]] = []
    activity_rows: list[dict[str, Any]] = []
    try:
        with db.connect_auditor(cfg) as conn:
            db_ok = True
            overview = db.auditor_documents_overview(conn)
            quarantine_count = db.auditor_quarantine_count(conn)
            quarantine_rows = db.auditor_quarantine_recent(conn, limit=10)
            activity_rows = db.auditor_recent_ingest_log(conn, limit=20)
    except Exception:
        log_event(logger, "api_error", request_id=request_id, path="/admin",
                  step="db_auditor")
    ollama_ok = _ollama_reachable()

    health_rows = "".join([
        _row(["Base PostgreSQL (rag-db)", "OK" if db_ok else "INACCESSIBLE"]),
        _row(["Ollama (rag-ollama)", "OK" if ollama_ok else "INACCESSIBLE"]),
        _row(["Documents ingérés", overview.get("documents", "—")]),
        _row(["Dernière ingestion", overview.get("last_ingested_at", "—")]),
    ])

    # --- Alertes (journal applicatif + base) --------------------------------------
    entries = _tail_app_log()
    counters = {"hmac_mismatch": 0, "doc_quarantined": 0, "output_masked": 0,
                "auth_failed": 0, "below_threshold": 0, "model_mismatch": 0}
    for entry in entries:
        event = entry.get("event")
        if event in counters:
            counters[event] += 1
    alert_rows = "".join([
        _row(["Chunks à HMAC invalide", counters["hmac_mismatch"]]),
        _row(["Documents mis en quarantaine — journal", counters["doc_quarantined"]]),
        _row(["Quarantaine — total en base", quarantine_count]),
        _row(["Réponses masquées/neutralisées", counters["output_masked"]]),
        _row(["Requêtes sous le seuil de similarité", counters["below_threshold"]]),
        _row(["Jetons invalides", counters["auth_failed"]]),
        _row(["Incohérences d'espace vectoriel", counters["model_mismatch"]]),
    ])

    quarantine_html = "".join(
        _row([r["detected_at"], r["source_ref"], f"{float(r['score']):.2f}", r["reason"]])
        for r in quarantine_rows
    ) or _row(["—", "aucune entrée", "—", "—"])

    # --- Activité --------------------------------------------------------------------
    activity_html = "".join(
        _row([r["ts"], r["operation"], r["detail"] or "", r["ref_sha256"] or ""])
        for r in activity_rows
    ) or _row(["—", "aucune entrée", "—", "—"])

    recent_queries = [e for e in entries if e.get("event") == "query_done"][-10:]
    queries_html = "".join(
        _row([e.get("ts", ""), e.get("request_id") or "—",
              e.get("detail", {}).get("mode", ""),
              e.get("detail", {}).get("n_chunks", ""),
              e.get("detail", {}).get("duration_s", "")])
        for e in reversed(recent_queries)
    ) or _row(["—", "aucune requête", "—", "—", "—"])

    # --- Agrégats pii_stats (S6) --------------------------------------------------------
    pii_html = "".join(
        _row([category, count])
        for category, count in sorted(overview.get("pii_totals", {}).items())
    ) or _row(["—", 0])

    template = (STATIC_DIR / "admin.html").read_text(encoding="utf-8")
    page = (
        template
        .replace("%%GENERATED_AT%%", _esc(datetime.now(timezone.utc).isoformat(timespec="seconds")))
        .replace("%%HEALTH_ROWS%%", health_rows)
        .replace("%%ALERT_ROWS%%", alert_rows)
        .replace("%%QUARANTINE_ROWS%%", quarantine_html)
        .replace("%%ACTIVITY_ROWS%%", activity_html)
        .replace("%%QUERY_ROWS%%", queries_html)
        .replace("%%PII_ROWS%%", pii_html)
    )
    log_event(logger, "admin_viewed", request_id=request_id)
    return page
