# ============================================================================
# rag-app — Python 3.12 slim, utilisateur non-root, code monté en RO
# (SPEC §3.1 — le code n'est PAS copié : bind mount ./app:/app:ro pour rester
#  immuable et modifiable côté hôte sans rebuild)
# ============================================================================
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Résilience réseau (connexions instables) : timeout long + retries.
    # Respecté par TOUS les appels pip du build, y compris le pip interne
    # de `spacy download`.
    PIP_TIMEOUT=120 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10

# Dépendances Python (versions épinglées — voir requirements.txt)
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --timeout 120 --retries 10 -r /tmp/requirements.txt

# Modèle NER spaCy CUIT DANS L'IMAGE au build (D9, SPEC §3.1) :
# P2 est hors-ligne et les conteneurs sont éphémères — un téléchargement au
# runtime échouerait (pas d'Internet) et ne persisterait pas.
RUN python -m spacy download en_core_web_sm

# Utilisateur non-root (invariant : moindre privilège aussi côté conteneur)
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin raguser

# /logs doit appartenir au non-root, sinon logutil.py ne peut pas écrire
# (échec runtime invisible en génération seule — SPEC §3.1)
RUN mkdir -p /logs && chown raguser:raguser /logs

WORKDIR /app
USER raguser

# Vivacité par défaut (phase 1) : conteneur idle, piloté par docker exec.
# La `command:` de compose.yaml prime (uvicorn en phase 2 via l'override).
CMD ["tail", "-f", "/dev/null"]
