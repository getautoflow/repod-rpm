from fastapi import APIRouter, HTTPException, Depends
from services.download import download_package
from services.search import list_packages
from auth.dependencies import get_current_user
from pydantic import BaseModel


router = APIRouter(prefix="/packages", tags=["Packages"])


class PackageRequest(BaseModel):
    name: str


@router.get("/")
def get_packages(current_user: str = Depends(get_current_user)):
    """Retourne la liste des paquets disponibles."""
    try:
        return list_packages()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur : {str(e)}")


@router.post("/install/")
def install_package(request: PackageRequest, current_user: str = Depends(get_current_user)):
    """Installe un paquet APT en exécutant download-package-dep.sh."""
    try:
        result = download_package(request.name)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur : {str(e)}")
