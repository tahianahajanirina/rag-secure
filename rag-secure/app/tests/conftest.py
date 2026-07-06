"""Configuration pytest — rend le paquet ``security`` importable.

Permet de lancer les tests depuis n'importe quelle racine :
    pytest app/tests/          (depuis rag-secure/, cf. README)
    pytest tests/              (depuis app/, ex. dans le conteneur)

Les tests des modules security/ sont PURS : aucun Docker, aucune base,
aucun réseau requis (lançables sur l'hôte comme dans le conteneur).
"""

from __future__ import annotations

import sys
from pathlib import Path

# app/ (parent de tests/) en tête de sys.path → `import security.*`, comme
# lorsque les pipelines tournent avec WORKDIR /app dans le conteneur.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
