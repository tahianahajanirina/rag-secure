# S6 — pseudonymisation, cf. NOTES §3 D9
"""Pseudonymisation des PII AVANT embedding et stockage (S6, D9).

Approche HYBRIDE et DÉTERMINISTE (invariant 7 — jamais de LLM détecteur) :
  - regex pour les PII « à forme » : EMAIL, PHONE, IP, IBAN, URL nominative ;
  - NER spaCy ``en_core_web_sm`` pour PERSON / GPE / ORG.

Remplacement par jetons catégoriels numérotés, COHÉRENTS par document :
la même valeur reçoit le même jeton (``[EMAIL_1]`` partout). Pseudonymisation
NON réversible : aucune table de correspondance n'est conservée.

Invariant 6 : ``pseudonymize`` s'applique avant F5 (embedding) et F6
(stockage) — rien de personnel n'entre dans un vecteur.

Le module s'importe SANS spaCy (chargement paresseux) pour rester testable
côté regex ; l'absence du modèle NER à l'usage lève une erreur EXPLICITE —
jamais de dégradation silencieuse (ce serait un contournement de S6).
"""

from __future__ import annotations

import re
from typing import Any

# =============================================================================
# Regex des PII « à forme » — RÉUTILISÉES par output_filter (S9, mêmes regex)
# =============================================================================

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# IBAN : CC + 2 chiffres de contrôle + 11 à 30 caractères (espaces tolérés).
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b")

# IPv4 : la forme seulement ; les octets sont validés dans _valid_ip
# (limite les faux positifs type numéros de version).
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Téléphone : trois formes explicites — (1) internationale (+/00, groupes
# librement espacés : « +33 6 12 34 56 78 »), (2) indicatif parenthésé
# (« (555) 123-4567 »), (3) groupes séparés par POINT ou TIRET uniquement
# (« 06.12.34.56.78 ») : l'espace y est exclu à dessein, sinon les grands
# nombres encyclopédiques (« 1 380 000 000 ») deviendraient des faux
# positifs. Post-validation dans _valid_phone (9-15 chiffres, jamais une
# date ISO). Le lookbehind (?<![\w.]) écarte les segments de versions.
PHONE_RE = re.compile(
    r"(?<![\w.])(?:"
    r"(?:\+|00)\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d(?:[\s.-]?\d){6,12}"
    r"|\(\d{2,4}\)[\s.-]?\d{3}[\s.-]?\d{4}"
    r"|\d{2,4}(?:[.-]\d{2,4}){2,4}"
    r")(?!\w)"
)

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

# URL « nominative » (D9) : porte un identifiant personnel apparent —
# segment de profil/compte ou paramètre nominatif. Les autres URLs restent
# intactes à l'ingestion (l'information documentaire est conservée) ;
# c'est la SORTIE qui neutralise les URLs hors sources (S9).
_URL_NOMINATIVE_RE = re.compile(
    r"(?:/(?:users?|profiles?|accounts?|members?|people|author)s?/[^/\s?]+"
    r"|/~[^/\s?]+"
    r"|[?&](?:name|user|username|email|login)=)",
    re.IGNORECASE,
)

# Jetons de pseudonymisation — contrat transverse (output_filter les laisse
# passer en les comptant, S9/F11).
PII_CATEGORIES = ("EMAIL", "PHONE", "IP", "IBAN", "URL", "PERSON", "GPE", "ORG")
TOKEN_RE = re.compile(r"\[(EMAIL|PHONE|IP|IBAN|URL|PERSON|GPE|ORG)_\d+\]")

_ISO_DATE_RE = re.compile(r"^\d{4}[\s.-]\d{2}[\s.-]\d{2}$")

# Ordre d'examen = priorité en cas de chevauchement (le plus englobant /
# le plus spécifique d'abord) : URL ⊃ EMAIL ; IBAN et IP avant PHONE
# (une séquence de chiffres pointés matcherait PHONE sinon).
_REGEX_ORDER: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("URL", URL_RE),
    ("EMAIL", EMAIL_RE),
    ("IBAN", IBAN_RE),
    ("IP", IP_RE),
    ("PHONE", PHONE_RE),
)


def _valid_ip(value: str) -> bool:
    """Chaque octet ≤ 255 (limite les faux positifs de IP_RE)."""
    return all(0 <= int(part) <= 255 for part in value.split("."))


def _valid_phone(value: str) -> bool:
    """Garde anti-faux-positifs : 9 à 15 chiffres, jamais une date ISO."""
    if _ISO_DATE_RE.match(value.strip()):
        return False
    digits = sum(ch.isdigit() for ch in value)
    return 9 <= digits <= 15


def find_regex_pii(
    text: str, *, include_urls: bool = True
) -> list[tuple[int, int, str, str]]:
    """Détections regex : liste de spans ``(début, fin, catégorie, valeur)``.

    Sans chevauchement (priorité = ordre de ``_REGEX_ORDER``). ``include_urls``
    à False permet à output_filter de gérer les URLs séparément (politique
    « sources autorisées » plutôt que « nominative »).
    """
    spans: list[tuple[int, int, str, str]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < e and end > s for s, e, _, _ in spans)

    for category, pattern in _REGEX_ORDER:
        if category == "URL" and not include_urls:
            continue
        for match in pattern.finditer(text):
            value = match.group(0)
            if category == "URL" and not _URL_NOMINATIVE_RE.search(value):
                continue
            if category == "IP" and not _valid_ip(value):
                continue
            if category == "PHONE" and not _valid_phone(value):
                continue
            if not overlaps(match.start(), match.end()):
                spans.append((match.start(), match.end(), category, value))
    return spans


# =============================================================================
# NER spaCy (PERSON / GPE / ORG) — chargement paresseux
# =============================================================================

_NER_LABELS = {"PERSON": "PERSON", "GPE": "GPE", "ORG": "ORG"}
_NLP: Any = None


def _get_nlp() -> Any:
    """Charge ``en_core_web_sm`` une seule fois.

    Échec BRUYANT si le modèle manque (jamais de repli silencieux — S6) :
    dans l'image rag-app il est cuit au build (Dockerfile) ; sur l'hôte,
    voir README (venv de test).
    """
    global _NLP
    if _NLP is None:
        try:
            import spacy

            # Seuls tok2vec + ner sont nécessaires ici.
            _NLP = spacy.load(
                "en_core_web_sm",
                disable=["tagger", "parser", "attribute_ruler", "lemmatizer"],
            )
        except Exception as exc:  # ImportError ou OSError (modèle absent)
            raise RuntimeError(
                "S6 — spaCy/en_core_web_sm indisponible : la pseudonymisation "
                "NER est OBLIGATOIRE avant embedding (D9). Dans le conteneur, "
                "le modèle est installé au build ; sur l'hôte : "
                "pip install spacy && python -m spacy download en_core_web_sm."
            ) from exc
    return _NLP


def _find_ner_spans(text: str) -> list[tuple[int, int, str, str]]:
    """Entités PERSON/GPE/ORG détectées par spaCy."""
    doc = _get_nlp()(text)
    return [
        (ent.start_char, ent.end_char, _NER_LABELS[ent.label_], ent.text)
        for ent in doc.ents
        if ent.label_ in _NER_LABELS
    ]


# =============================================================================
# Pseudonymisation (F2)
# =============================================================================

def pseudonymize(text: str) -> tuple[str, dict[str, int]]:
    """Remplace les PII par des jetons catégoriels numérotés (S6, D9).

    Renvoie ``(texte_pseudonymisé, pii_stats)`` où ``pii_stats`` compte les
    OCCURRENCES remplacées par catégorie (stocké dans ``documents.pii_stats``).

    Cohérence intra-document : une même valeur reçoit toujours le même jeton
    (``jean@ex.com`` → ``[EMAIL_1]`` à chaque occurrence). Non réversible.
    """
    # 1. Détections : regex (prioritaires) puis NER hors des spans déjà pris.
    spans = find_regex_pii(text, include_urls=True)

    def overlaps(start: int, end: int) -> bool:
        return any(start < e and end > s for s, e, _, _ in spans)

    for start, end, category, value in _find_ner_spans(text):
        if not overlaps(start, end):
            spans.append((start, end, category, value))

    if not spans:
        return text, {}

    # 2. Numérotation stable : ordre de PREMIÈRE apparition, par catégorie ;
    #    même valeur → même numéro (emails insensibles à la casse).
    spans.sort(key=lambda s: s[0])
    numbering: dict[str, dict[str, int]] = {}
    pii_stats: dict[str, int] = {}
    replacements: list[tuple[int, int, str]] = []
    for start, end, category, value in spans:
        key = value.strip().lower() if category == "EMAIL" else value.strip()
        per_cat = numbering.setdefault(category, {})
        if key not in per_cat:
            per_cat[key] = len(per_cat) + 1
        replacements.append((start, end, f"[{category}_{per_cat[key]}]"))
        pii_stats[category] = pii_stats.get(category, 0) + 1

    # 3. Remplacement de droite à gauche (les offsets restent valides).
    result = text
    for start, end, token in reversed(replacements):
        result = result[:start] + token + result[end:]
    return result, pii_stats
