"""
Gestion des tokens d'API pour les pipelines CI/CD.
Les tokens sont stockés dans /repos/security/api_tokens.json (hashés SHA-256).
"""
import json
import hashlib
import secrets
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

TOKENS_FILE = Path(os.getenv("SECURITY_DIR", "/repos/security")) / "api_tokens.json"
_lock = Lock()

PREFIX = "repod_"  # préfixe lisible pour identifier les tokens


def _load() -> dict:
    if not TOKENS_FILE.exists():
        return {}
    try:
        with open(TOKENS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict):
    TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(TOKENS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(name: str, role: str, created_by: str, expires_days: int = None) -> str:
    """Crée un nouveau token, le stocke hashé et retourne le token en clair (une seule fois)."""
    raw = PREFIX + secrets.token_urlsafe(32)
    token_hash = _hash(raw)
    token_id = secrets.token_hex(8)

    entry = {
        "id": token_id,
        "name": name,
        "role": role,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_used": None,
        "expires_at": None,
    }
    if expires_days:
        from datetime import timedelta
        entry["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

    with _lock:
        data = _load()
        data[token_hash] = entry
        _save(data)

    return raw  # retourné UNE SEULE FOIS, jamais stocké en clair


def list_tokens() -> list[dict]:
    """Liste les tokens sans exposer les hashes."""
    data = _load()
    return [v for v in data.values()]


def revoke_token(token_id: str) -> bool:
    """Révoque un token par son ID."""
    with _lock:
        data = _load()
        to_delete = [h for h, v in data.items() if v["id"] == token_id]
        if not to_delete:
            return False
        for h in to_delete:
            del data[h]
        _save(data)
    return True


def verify_api_token(raw_token: str) -> dict | None:
    """
    Vérifie un token en clair, met à jour last_used, retourne {username, role} ou None.
    """
    if not raw_token.startswith(PREFIX):
        return None

    token_hash = _hash(raw_token)
    with _lock:
        data = _load()
        entry = data.get(token_hash)
        if not entry:
            return None

        # Vérifier expiration
        if entry.get("expires_at"):
            exp = datetime.fromisoformat(entry["expires_at"])
            if datetime.now(timezone.utc) > exp:
                return None

        # Mettre à jour last_used
        entry["last_used"] = datetime.now(timezone.utc).isoformat()
        data[token_hash] = entry
        _save(data)

    return {
        "username": f"token:{entry['name']}",
        "role": entry["role"],
        "full_name": entry["name"],
        "token_id": entry["id"],
    }
