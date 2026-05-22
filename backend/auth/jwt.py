from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

MFA_TOKEN_EXPIRE_MINUTES = 5  # token temporaire, courte durée de vie


def create_access_token(data: dict) -> str:
    """Crée un JWT avec sub, role et expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_mfa_token(username: str, role: str) -> str:
    """
    Crée un JWT temporaire (5 min) indiquant que la première étape du login
    a réussi mais que le MFA reste à valider.

    Le payload contient :
      - sub   : username
      - role  : role
      - scope : "mfa_required"  ← distingue ce token d'un access token normal
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=MFA_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub":   username,
        "role":  role,
        "scope": "mfa_required",
        "exp":   expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    """
    Décode un JWT et retourne {username, role} ou None si invalide.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        return {
            "username": username,
            "role": payload.get("role", "reader"),
            "full_name": payload.get("full_name", ""),
        }
    except JWTError:
        return None
