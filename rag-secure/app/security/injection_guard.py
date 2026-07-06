# S7 — heuristiques anti-injection à l'ingestion, cf. NOTES §3 (OWASP LLM01/LLM04)
"""Détection heuristique de tentatives d'injection dans les documents (S7).

Gardes STRICTEMENT déterministes (invariant 7) : normalisation Unicode,
détection de caractères invisibles, motifs pondérés. AUCUN LLM ici — un
détecteur instructible exposé à du contenu non fiable serait lui-même une
surface d'injection (D9, alternative écartée).

Un score ≥ seuil (défaut ``DEFAULT_THRESHOLD``, configurable via
``INJECTION_THRESHOLD``) envoie le document en quarantaine (F3) — chiffré,
motifs et score journalisés (``doc_quarantined``).

Défense en profondeur (NOTES §6 T4) : ces heuristiques sont contournables ;
elles se combinent au spotlighting (F9) et au filtrage de sortie (F11).
"""

from __future__ import annotations

import re
import unicodedata

# Seuil de quarantaine par défaut (SPEC §3.3) — surchargé par la variable
# d'environnement INJECTION_THRESHOLD (config.py).
DEFAULT_THRESHOLD = 0.5

# Caractères invisibles / de contrôle bidi : vecteurs classiques de
# dissimulation d'instructions (zero-width, BOM, soft hyphen, overrides).
# Séquences \u ÉCHAPPÉES (jamais de littéraux invisibles dans le source).
_INVISIBLE_RE = re.compile(
    "[\\u200b-\\u200f"   # zero-width space/joiner/non-joiner, marques directionnelles
    "\\u2060"            # word joiner
    "\\ufeff"            # BOM / zero-width no-break space
    "\\u00ad"            # soft hyphen
    "\\u202a-\\u202e"    # bidi embeddings/overrides
    "\\u2066-\\u2069"    # bidi isolates
    "]"
)

# Motifs pondérés (appliqués au texte NORMALISÉ NFKC, casse ignorée).
# Chaque motif ne compte qu'UNE fois ; score final plafonné à 1.0.
_PATTERNS: tuple[tuple[float, str, re.Pattern[str]], ...] = (
    (
        0.7,
        "template_tokens",  # balises de gabarit de chat (LLM01)
        re.compile(
            r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[/INST\]"
            r"|<<SYS>>|<</SYS>>|<\|start_header_id\|>",
            re.IGNORECASE,
        ),
    ),
    (
        0.6,
        "ignore_instructions",  # « ignore/disregard previous instructions… »
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,40}?"
            r"\b(?:previous|prior|above|earlier|preceding|all|any|your)\b.{0,40}?"
            r"\b(?:instructions?|rules?|context|prompts?|directives?|guidelines?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        0.6,
        "reveal_prompt",  # exfiltration du prompt système
        re.compile(
            r"\b(?:reveal|show|print|repeat|output|display|leak)\b.{0,40}?"
            r"\b(?:system\s+prompt|initial\s+prompt|your\s+(?:instructions|prompt|rules))\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        0.5,
        "role_reassignment",  # ligne débutant par un tour de dialogue
        re.compile(r"^\s*(?:system|assistant|user)\s*:", re.IGNORECASE | re.MULTILINE),
    ),
    (
        0.5,
        "new_identity",  # réassignation d'identité du modèle
        re.compile(
            r"\byou\s+are\s+now\b|\bact\s+as\b|\bpretend\s+(?:to\s+be|you\s+are)\b"
            r"|\bfrom\s+now\s+on\b|\bnew\s+persona\b",
            re.IGNORECASE,
        ),
    ),
    (
        0.5,
        "jailbreak_known",  # jailbreaks connus
        re.compile(r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bdeveloper\s+mode\b", re.IGNORECASE),
    ),
    (
        0.4,
        "exfiltration_hint",  # incitation à l'exfiltration
        re.compile(
            r"\b(?:send|post|upload|exfiltrate|transmit)\b.{0,30}?"
            r"\b(?:data|secrets?|keys?|passwords?|credentials?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        0.3,
        "dangerous_scheme",  # schémas exécutables dans du markdown/HTML
        re.compile(r"javascript:|data:text/html", re.IGNORECASE),
    ),
)

_INVISIBLE_WEIGHT = 0.4


def scan(text: str) -> tuple[float, list[str]]:
    """Analyse un document : ``(score ∈ [0,1], motifs détectés)`` (F3/S7).

    Étapes (SPEC §3.3) :
      1. détection des caractères invisibles (comptés, poids dédié) ;
      2. normalisation NFKC + suppression des invisibles — les regex
         s'appliquent au texte NETTOYÉ (déjoue « ｉｇｎｏｒｅ » pleine
         largeur ou « ig<U+200B>nore » troué de zero-width) ;
      3. somme des poids des motifs distincts, plafonnée à 1.0.
    """
    reasons: list[str] = []
    score = 0.0

    invisible_count = len(_INVISIBLE_RE.findall(text))
    if invisible_count:
        score += _INVISIBLE_WEIGHT
        reasons.append(f"invisible_chars:{invisible_count}")

    # Normalisation APRÈS détection : NFKC replie les homoglyphes de
    # compatibilité, la suppression des invisibles recolle les mots troués.
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _INVISIBLE_RE.sub("", normalized)

    for weight, label, pattern in _PATTERNS:
        if pattern.search(normalized):
            score += weight
            reasons.append(label)

    return min(score, 1.0), reasons
