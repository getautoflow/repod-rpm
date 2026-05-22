import os
from pathlib import Path

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))


def list_packages():
    """
    Retourne la liste des fichiers `.rpm` dans POOL_DIR.
    Le répertoire est configuré via la variable d'environnement POOL_DIR.
    """
    if not POOL_DIR.exists():
        return {"error": f"Dossier {POOL_DIR} introuvable"}
    packages = [f for f in os.listdir(POOL_DIR) if f.endswith(".rpm")]
    return {"packages": packages}
