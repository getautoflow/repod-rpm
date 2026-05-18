import subprocess
import os

SCRIPT_PATH = "~/repodata/download-package-dep.sh"
SSH_HOST = os.getenv("SSH_HOST", "192.168.1.123")  # Récupère l'IP de l'hôte

def download_package(package_name: str):
    """
    📌 Exécute `download-package-dep.sh` sur la machine hôte via SSH.
    """
    try:
        result = subprocess.run(
            [
                "ssh", "-i", "/root/.ssh/id_rsa",
                "-o", "StrictHostKeyChecking=no",
                f"vagrant@{SSH_HOST}", f"sh {SCRIPT_PATH} {package_name}"
            ],
            capture_output=True,
            text=True,
            check=True
        )
        return {
            "message": f"✅ {package_name} installé avec succès",
            "output": result.stdout
        }
    except subprocess.CalledProcessError as e:
        return {
            "error": f"❌ Échec de l'installation de {package_name}",
            "details": e.stderr
        }
