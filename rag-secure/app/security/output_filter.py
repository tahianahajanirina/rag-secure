# S9 — filtrage des réponses (F11), cf. NOTES §2 ES9 (OWASP LLM02)
"""Filtrage de la réponse du LLM avant restitution (S9, F11).

Trois politiques (SPEC §3.3) :
  1. PII BRUTES masquées — mêmes regex qu'``anonymize`` (S6) : si une donnée
     personnelle réelle traverse la génération, elle n'atteint pas l'usager ;
  2. URLs absentes des sources NEUTRALISÉES — anti-exfiltration par lien
     forgé (OWASP LLM02) : seules les URLs présentes dans le contexte fourni
     (ou les références de sources) survivent ;
  3. les JETONS de pseudonymisation (``[EMAIL_1]``…) passent, en étant
     comptés : ils sont la preuve visible que S6 a fait son travail.

Fonction pure ; les ``flags`` retournés sont journalisés par l'appelant
(événement ``output_masked`` si au moins un masquage a eu lieu).
"""

from __future__ import annotations

from security.anonymize import TOKEN_RE, URL_RE, find_regex_pii

MASK_TMPL = "[{category}_MASQUE]"
URL_NEUTRALIZED = "[URL_NEUTRALISEE]"

# Ponctuation de fin de phrase souvent collée aux URLs par le modèle.
_TRAILING_PUNCT = ".,;:!?"


def _canon_url(url: str) -> str:
    """Forme canonique d'une URL pour la comparaison aux sources autorisées."""
    return url.strip().rstrip(_TRAILING_PUNCT).rstrip("/")


def filter_output(
    answer: str, allowed_sources: set[str] | frozenset[str]
) -> tuple[str, dict[str, object]]:
    """Filtre la réponse du LLM (F11) → ``(réponse_filtrée, flags)``.

    ``allowed_sources`` : URLs apparaissant dans les chunks du contexte +
    références ``source_ref`` (constitué par query.py). Les URLs de la réponse
    absentes de cet ensemble sont neutralisées.

    ``flags`` : ``{"masked": {cat: n}, "urls_neutralized": n,
    "tokens_passed": {cat: n}}`` — à journaliser côté appelant
    (``output_masked`` si masked/urls_neutralized non vides).
    """
    allowed = {_canon_url(str(source)) for source in allowed_sources}

    # 1. Jetons de pseudonymisation : comptés, jamais altérés (les regex PII
    #    ne peuvent pas les matcher : « [EMAIL_1] » n'a pas la forme d'un
    #    email — aucune substitution ne les touche).
    tokens_passed: dict[str, int] = {}
    for match in TOKEN_RE.finditer(answer):
        category = match.group(1)
        tokens_passed[category] = tokens_passed.get(category, 0) + 1

    replacements: list[tuple[int, int, str]] = []

    # 2. PII brutes (EMAIL/PHONE/IP/IBAN — mêmes regex que S6). Les URLs
    #    sont traitées à part (politique « sources autorisées », pas
    #    « nominative »).
    masked: dict[str, int] = {}
    for start, end, category, _value in find_regex_pii(answer, include_urls=False):
        replacements.append((start, end, MASK_TMPL.format(category=category)))
        masked[category] = masked.get(category, 0) + 1

    # 3. URLs hors sources : neutralisées.
    urls_neutralized = 0
    for match in URL_RE.finditer(answer):
        span = (match.start(), match.end())
        if any(s < span[1] and span[0] < e for s, e, _ in replacements):
            continue  # déjà couverte par un masquage PII
        if _canon_url(match.group(0)) not in allowed:
            replacements.append((span[0], span[1], URL_NEUTRALIZED))
            urls_neutralized += 1

    # Application de droite à gauche (offsets stables).
    filtered = answer
    for start, end, replacement in sorted(replacements, reverse=True):
        filtered = filtered[:start] + replacement + filtered[end:]

    flags: dict[str, object] = {
        "masked": masked,
        "urls_neutralized": urls_neutralized,
        "tokens_passed": tokens_passed,
    }
    return filtered, flags


def has_masking(flags: dict[str, object]) -> bool:
    """Vrai si le filtre a réellement modifié la réponse (→ ``output_masked``)."""
    return bool(flags.get("masked")) or bool(flags.get("urls_neutralized"))
