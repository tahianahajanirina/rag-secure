"""Modules de sécurité du RAG (S6–S9) — fonctions PURES et testables.

Règle d'architecture (invariant 7) : gardes DÉTERMINISTES uniquement
(regex, NER, heuristiques). JAMAIS d'appel à un LLM dans ce package —
un composant instructible exposé à du contenu non fiable est une surface
d'injection. Le LLM ne sert qu'à la génération finale (F10).

Modules :
    anonymize        S6 — pseudonymisation (regex + NER), cf. NOTES §3 D9
    injection_guard  S7 — heuristiques anti-injection (ingestion)
    integrity        S8 — HMAC-SHA256 à clé dédiée, cf. NOTES §3 D11
    prompting        S7 — prompt durci (spotlighting, F9)
    output_filter    S9 — filtrage des réponses (F11)
"""
