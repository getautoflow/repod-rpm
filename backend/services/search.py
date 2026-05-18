import os

def list_packages():
    """
    📌 Retourne la liste des fichiers `.rpm` dans /usr/share/repos/pool.
    """
    repo_path = "/usr/share/repos/pool"
    if not os.path.exists(repo_path):
        return {"error": "Dossier /usr/share/repos/pool introuvable"}
    packages = [f for f in os.listdir(repo_path) if f.endswith(".rpm")]
    return {"packages": packages}
