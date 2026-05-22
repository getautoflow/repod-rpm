"""
Routes d'authentification et de gestion des utilisateurs.

Publique :
  POST /auth/token           → connexion, retourne JWT

Authentifié (tout rôle) :
  GET  /auth/me              → info du compte courant
  POST /auth/change-password → changer son propre mot de passe

Admin uniquement :
  GET    /auth/users                        → liste tous les utilisateurs
  POST   /auth/users                        → créer un utilisateur
  PATCH  /auth/users/{username}             → modifier rôle/infos
  DELETE /auth/users/{username}             → supprimer un utilisateur
  POST   /auth/users/{username}/reset-password → réinitialiser le mdp
"""
import re
import secrets

from fastapi import APIRouter, HTTPException, Request, status, Depends
from pydantic import BaseModel
from typing import Optional

from .models import Token, UserLogin, UserCreate, UserUpdate, PasswordChange, PasswordReset
from .api_tokens import create_token, list_tokens, revoke_token, PREFIX as API_TOKEN_PREFIX
from .users import (
    get_user, get_user_any, list_users, create_user,
    update_user, delete_user, change_password, verify_password, update_last_login,
    get_mfa_info, set_totp_pending, enable_mfa, disable_mfa,
    VALID_ROLES, ROLE_DESCRIPTIONS,
)
from .jwt import create_access_token, create_mfa_token
from .mfa import generate_totp_secret, get_totp_uri, generate_qr_code_base64, verify_totp
from .dependencies import get_current_user, get_current_user_full, get_admin_user
from .reset_tokens import create_reset_token, consume_reset_token
from limiter import limiter, auth_limit
from services.audit import log as audit_log

router = APIRouter(prefix="/auth", tags=["Auth"])


# ─── Validation de la politique mot de passe ─────────────────────────────────

def _validate_password(password: str, field: str = "Le mot de passe") -> None:
    """
    Vérifie que le mot de passe respecte la politique de sécurité :
    - 8 caractères minimum
    - Au moins une majuscule
    - Au moins un chiffre ou un caractère spécial
    Lève HTTPException 400 si la politique n'est pas respectée.
    """
    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail=f"{field} doit contenir au moins 8 caractères.",
        )
    if not re.search(r"[A-Z]", password):
        raise HTTPException(
            status_code=400,
            detail=f"{field} doit contenir au moins une lettre majuscule.",
        )
    if not re.search(r"[0-9!@#$%^&*()_+\-=\[\]{{}}|;':\",./<>?]", password):
        raise HTTPException(
            status_code=400,
            detail=f"{field} doit contenir au moins un chiffre ou un caractère spécial.",
        )


# ─── Connexion ────────────────────────────────────────────────────────────────

@router.post("/token", response_model=Token)
@limiter.limit(auth_limit)
def login(request: Request, credentials: UserLogin):
    """
    Authentifie un utilisateur.
    Ordre : auth locale → auth LDAP (si activée et utilisateur non trouvé localement).
    """
    import logging as _log
    _logger = _log.getLogger("auth.login")

    # ── 1. Auth locale ────────────────────────────────────────────────────────
    client_ip = request.client.host if request.client else "unknown"
    local_user = get_user(credentials.username)
    if local_user and local_user.get("auth_source") != "ldap":
        # Compte local standard
        if not verify_password(credentials.password, local_user["hashed_password"]):
            audit_log("LOGIN", credentials.username, "FAILURE",
                      detail="Mot de passe incorrect", extra={"ip": client_ip})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Identifiants incorrects")
        if not local_user.get("active", True):
            audit_log("LOGIN", credentials.username, "FAILURE",
                      detail="Compte désactivé", extra={"ip": client_ip})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Compte désactivé")
        user = local_user

    else:
        # ── 2. Auth LDAP ──────────────────────────────────────────────────────
        from services.settings import get_settings
        ldap_cfg = get_settings().get("ldap", {})

        if not ldap_cfg.get("enabled", False):
            audit_log("LOGIN", credentials.username, "FAILURE",
                      detail="Utilisateur inconnu (LDAP désactivé)", extra={"ip": client_ip})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Identifiants incorrects")

        try:
            from services.ldap_auth import authenticate as ldap_auth
            ldap_user = ldap_auth(credentials.username, credentials.password)
        except Exception as e:
            _logger.error(f"[login] Erreur LDAP : {e}")
            audit_log("LOGIN", credentials.username, "FAILURE",
                      detail="Serveur LDAP indisponible", extra={"ip": client_ip})
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="Serveur LDAP indisponible. Réessayez plus tard.")

        if not ldap_user:
            audit_log("LOGIN", credentials.username, "FAILURE",
                      detail="Identifiants LDAP incorrects", extra={"ip": client_ip})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Identifiants incorrects")

        # ── Auto-provisioning : créer/mettre à jour le compte local ───────────
        if ldap_cfg.get("auto_provision", True):
            existing = get_user_any(ldap_user["username"])
            if not existing:
                try:
                    create_user(
                        username=ldap_user["username"],
                        password=secrets.token_hex(32),  # mot de passe aléatoire inutilisable
                        role=ldap_user["role"],
                        full_name=ldap_user.get("full_name", ""),
                        email=ldap_user.get("email", ""),
                        auth_source="ldap",  # marque le compte comme LDAP → login local impossible
                    )
                    _logger.info(f"[ldap] Compte '{ldap_user['username']}' auto-provisionné")
                    audit_log("USER_CREATE", "ldap_provision", "SUCCESS",
                              detail=f"Auto-provision LDAP : {ldap_user['username']} rôle={ldap_user['role']}")
                except Exception as ex:
                    _logger.warning(f"[ldap] Auto-provision échoué : {ex}")
            else:
                # Mettre à jour le rôle si changement de groupe AD
                # Toujours corriger auth_source si le compte était marqué 'local' par erreur
                updates = {}
                if existing.get("role") != ldap_user["role"]:
                    updates["role"] = ldap_user["role"]
                    old_role = existing.get("role")
                    audit_log("USER_ROLE_CHANGE", "ldap_sync", "SUCCESS",
                              detail=f"{ldap_user['username']} : {old_role} → {ldap_user['role']}")
                if existing.get("auth_source") != "ldap":
                    updates["auth_source"] = "ldap"
                    _logger.info(f"[ldap] Correction auth_source pour '{ldap_user['username']}' : local → ldap")
                if updates:
                    update_user(ldap_user["username"], **updates)

        # Marquer la source d'auth pour éviter les tentatives de login local
        user = get_user_any(ldap_user["username"]) or {
            "username": ldap_user["username"],
            "role":     ldap_user["role"],
            "full_name": ldap_user.get("full_name", ""),
        }

    update_last_login(user["username"])

    # ── MFA : si activé, retourner un token temporaire ───────────────────────
    mfa = get_mfa_info(user["username"])
    if mfa and mfa.get("mfa_enabled"):
        mfa_token = create_mfa_token(user["username"], user["role"])
        audit_log("LOGIN", user["username"], "MFA_REQUIRED",
                  extra={"ip": client_ip, "role": user["role"]})
        # On retourne mfa_required=True — le frontend redirige vers l'écran TOTP
        return {
            "access_token": "",
            "token_type":   "bearer",
            "mfa_required": True,
            "mfa_token":    mfa_token,
        }

    audit_log("LOGIN", user["username"], "SUCCESS",
              extra={"ip": client_ip, "role": user["role"]})
    token = create_access_token({
        "sub":       user["username"],
        "role":      user["role"],
        "full_name": user.get("full_name", ""),
    })
    return {"access_token": token, "token_type": "bearer"}


# ─── Compte courant ───────────────────────────────────────────────────────────

@router.get("/me")
def me(current_user: dict = Depends(get_current_user_full)):
    """Retourne les informations du compte connecté."""
    user = get_user_any(current_user["username"])
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return {
        "username":    user["username"],
        "role":        user["role"],
        "full_name":   user.get("full_name", ""),
        "email":       user.get("email", ""),
        "active":      bool(user["active"]),
        "last_login":  user.get("last_login"),
        "mfa_enabled": bool(user.get("mfa_enabled", False)),
    }


@router.post("/change-password")
def change_own_password(
    payload: PasswordChange,
    current_user: dict = Depends(get_current_user_full),
):
    """Permet à l'utilisateur connecté de changer son propre mot de passe."""
    username = current_user["username"]
    user = get_user_any(username)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    if not verify_password(payload.current_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")

    _validate_password(payload.new_password, "Le nouveau mot de passe")
    change_password(username, payload.new_password)
    audit_log("PASSWORD_CHANGE", username, "SUCCESS", detail="Changement de mot de passe par l'utilisateur")
    return {"status": "ok", "message": "Mot de passe modifié avec succès"}


# ─── Gestion des utilisateurs (admin) ────────────────────────────────────────

@router.get("/roles")
def list_roles():
    """Retourne la liste des rôles disponibles avec leur description (public)."""
    return {"roles": ROLE_DESCRIPTIONS}


@router.get("/users")
def list_all_users(admin: str = Depends(get_admin_user)):
    """Liste tous les utilisateurs (admin uniquement)."""
    users = list_users()
    # Ne jamais exposer les hashes
    return {"users": [
        {k: v for k, v in u.items() if k != "hashed_password"}
        for u in users
    ]}


@router.post("/users", status_code=201)
def create_new_user(payload: UserCreate, admin: str = Depends(get_admin_user)):
    """Crée un nouvel utilisateur (admin uniquement)."""
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Rôle invalide. Valeurs acceptées : {', '.join(VALID_ROLES)}")

    _validate_password(payload.password)

    existing = get_user_any(payload.username)
    if existing:
        raise HTTPException(status_code=409, detail=f"L'utilisateur '{payload.username}' existe déjà")

    user = create_user(
        username=payload.username,
        password=payload.password,
        role=payload.role,
        full_name=payload.full_name,
        email=payload.email,
    )
    audit_log("USER_CREATE", admin, "SUCCESS",
              detail=f"Utilisateur créé : {payload.username} (rôle={payload.role})")
    return {k: v for k, v in user.items() if k != "hashed_password"}


@router.patch("/users/{username}")
def update_existing_user(
    username: str,
    payload: UserUpdate,
    admin: str = Depends(get_admin_user),
):
    """Met à jour le rôle et/ou les infos d'un utilisateur (admin uniquement)."""
    # L'admin ne peut pas changer son propre rôle (sécurité)
    if username == admin and payload.role is not None and payload.role != "admin":
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas changer votre propre rôle")

    if payload.role is not None and payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Rôle invalide. Valeurs acceptées : {', '.join(VALID_ROLES)}")

    before = get_user_any(username)
    user = update_user(
        username=username,
        role=payload.role,
        full_name=payload.full_name,
        email=payload.email,
        active=payload.active,
    )
    if not user:
        raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' introuvable")

    # Tracer les changements significatifs dans l'audit trail
    changes = []
    if payload.role is not None and before and before.get("role") != payload.role:
        changes.append(f"rôle : {before.get('role')} → {payload.role}")
    if payload.active is not None and before and bool(before.get("active")) != payload.active:
        changes.append(f"actif : {bool(before.get('active'))} → {payload.active}")
    if changes:
        audit_log("USER_UPDATE", admin, "SUCCESS",
                  detail=f"{username} — {', '.join(changes)}")

    return {k: v for k, v in user.items() if k != "hashed_password"}


@router.delete("/users/{username}")
def delete_existing_user(username: str, admin: str = Depends(get_admin_user)):
    """Supprime un utilisateur (admin uniquement, ne peut pas se supprimer soi-même)."""
    if username == admin:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas supprimer votre propre compte")

    ok = delete_user(username)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' introuvable")

    audit_log("USER_DELETE", admin, "SUCCESS", detail=f"Utilisateur supprimé : {username}")
    return {"status": "deleted", "username": username}


@router.post("/users/{username}/reset-password")
def reset_user_password(
    username: str,
    payload: PasswordReset,
    admin: str = Depends(get_admin_user),
):
    """Réinitialise le mot de passe d'un utilisateur (admin uniquement)."""
    _validate_password(payload.new_password)

    user = get_user_any(username)
    if not user:
        raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' introuvable")

    change_password(username, payload.new_password)
    audit_log("PASSWORD_RESET", admin, "SUCCESS",
              detail=f"Réinitialisation mot de passe de '{username}' par l'admin")
    return {"status": "ok", "message": f"Mot de passe de '{username}' réinitialisé"}


# ─── Réinitialisation de mot de passe (publique) ─────────────────────────────

import logging as _logging
_logger = _logging.getLogger("auth.reset")

class ForgotPasswordPayload(BaseModel):
    username: str

class ResetPasswordPayload(BaseModel):
    token: str
    new_password: str


@router.post("/forgot-password")
@limiter.limit(auth_limit)
def forgot_password(request: Request, payload: ForgotPasswordPayload):
    """
    Envoie un email de réinitialisation si l'utilisateur existe et a un email.
    Toujours 200 pour ne pas divulguer l'existence du compte.
    """
    user = get_user_any(payload.username)
    if not user or not user.get("email"):
        # Réponse générique — on ne révèle pas si l'utilisateur existe
        return {"status": "ok", "message": "Si ce compte existe et a un email, un lien a été envoyé."}

    token = create_reset_token(payload.username)

    try:
        from services.email_notifications import _send_email
        from services.settings import get_settings
        settings = get_settings()
        base_url = settings.get("app_url", "http://localhost:3003")

        reset_url = f"{base_url}/reset-password?token={token}"
        subject = "Réinitialisation de mot de passe — APT Repo Manager"
        body_html = f"""
<p>Bonjour <strong>{user.get('full_name') or payload.username}</strong>,</p>
<p>Une demande de réinitialisation de mot de passe a été effectuée pour votre compte.</p>
<p>
  <a href="{reset_url}" style="
    background:#2563eb;color:#fff;padding:10px 20px;
    border-radius:6px;text-decoration:none;font-weight:600
  ">Réinitialiser mon mot de passe</a>
</p>
<p>Ce lien est valable <strong>30 minutes</strong>. Si vous n'avez pas fait cette demande, ignorez cet email.</p>
<hr/>
<p style="color:#888;font-size:12px">APT Repo Manager</p>
"""
        body_text = (
            f"Réinitialisez votre mot de passe via ce lien (valable 30 min) :\n{reset_url}\n"
            "Si vous n'avez pas fait cette demande, ignorez cet email."
        )
        _send_email(subject, body_html, body_text, to_override=user["email"])
        _logger.info(f"[reset] Email de reset envoyé à {user['email']} pour {payload.username}")
    except Exception as e:
        _logger.error(f"[reset] Erreur envoi email reset : {e}")
        # On continue — le token est créé, l'admin peut le lire en CLI si besoin

    return {"status": "ok", "message": "Si ce compte existe et a un email, un lien a été envoyé."}


@router.post("/reset-password")
@limiter.limit(auth_limit)
def reset_password_with_token(request: Request, payload: ResetPasswordPayload):
    """Réinitialise le mot de passe via un token one-time envoyé par email."""
    _validate_password(payload.new_password)

    username = consume_reset_token(payload.token)
    if not username:
        raise HTTPException(status_code=400, detail="Lien invalide ou expiré. Faites une nouvelle demande.")

    change_password(username, payload.new_password)
    audit_log("PASSWORD_RESET", username, "SUCCESS", detail="Reset via token email")
    _logger.info(f"[reset] Mot de passe réinitialisé pour {username}")
    return {"status": "ok", "message": "Mot de passe modifié. Vous pouvez vous connecter."}


# ─── MFA TOTP ─────────────────────────────────────────────────────────────────

class MfaConfirmPayload(BaseModel):
    totp_code: str

class MfaAuthPayload(BaseModel):
    mfa_token: str
    totp_code: str

class MfaDisablePayload(BaseModel):
    totp_code: str


@router.post("/mfa/setup")
def mfa_setup(current_user: dict = Depends(get_current_user_full)):
    """
    Étape 1 — Génère un secret TOTP et retourne le QR code.
    Le secret est stocké temporairement (totp_pending_secret).
    L'activation n'est effective qu'après /mfa/confirm.
    """
    username = current_user["username"]
    secret   = generate_totp_secret()
    uri      = get_totp_uri(secret, username)
    qr_b64   = generate_qr_code_base64(uri)
    set_totp_pending(username, secret)
    return {
        "qr_code":    f"data:image/png;base64,{qr_b64}",
        "secret":     secret,
        "uri":        uri,
        "issuer":     "repod-rpm",
        "username":   username,
    }


@router.post("/mfa/confirm")
def mfa_confirm(
    payload: MfaConfirmPayload,
    current_user: dict = Depends(get_current_user_full),
):
    """
    Étape 2 — L'utilisateur soumet un code TOTP depuis son authenticator.
    Si correct → active le MFA définitivement.
    """
    username = current_user["username"]
    mfa_info = get_mfa_info(username)
    if not mfa_info or not mfa_info.get("totp_pending_secret"):
        raise HTTPException(status_code=400, detail="Aucun secret TOTP en attente. Lancez /mfa/setup d'abord.")

    if not verify_totp(mfa_info["totp_pending_secret"], payload.totp_code):
        raise HTTPException(status_code=400, detail="Code TOTP invalide.")

    enable_mfa(username)
    audit_log("MFA_ENABLE", username, "SUCCESS", detail="MFA TOTP activé")
    return {"status": "ok", "message": "MFA activé avec succès."}


@router.post("/mfa/authenticate")
@limiter.limit(auth_limit)
def mfa_authenticate(request: Request, payload: MfaAuthPayload):
    """
    Étape 2 du login avec MFA.
    Reçoit le token temporaire (mfa_token) et le code TOTP.
    Retourne le vrai access_token si le code est correct.
    """
    from jose import JWTError, jwt as jose_jwt
    from .config import SECRET_KEY, ALGORITHM

    # Vérifier le token MFA temporaire
    try:
        data = jose_jwt.decode(payload.mfa_token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token MFA invalide ou expiré.")

    if data.get("scope") != "mfa_required":
        raise HTTPException(status_code=401, detail="Token invalide (scope incorrect).")

    username = data.get("sub")
    role     = data.get("role", "reader")

    user = get_user_any(username)
    if not user or not user.get("active", True):
        raise HTTPException(status_code=401, detail="Utilisateur introuvable ou inactif.")

    mfa_info = get_mfa_info(username)
    if not mfa_info or not mfa_info.get("totp_secret"):
        raise HTTPException(status_code=400, detail="MFA non configuré pour cet utilisateur.")

    if not verify_totp(mfa_info["totp_secret"], payload.totp_code):
        audit_log("LOGIN", username, "FAILURE", detail="Code TOTP invalide")
        raise HTTPException(status_code=401, detail="Code TOTP invalide.")

    audit_log("LOGIN", username, "SUCCESS", extra={"method": "mfa_totp", "role": role})
    token = create_access_token({
        "sub":       username,
        "role":      role,
        "full_name": user.get("full_name", ""),
    })
    return {"access_token": token, "token_type": "bearer"}


@router.post("/mfa/disable")
def mfa_disable(
    payload: MfaDisablePayload,
    current_user: dict = Depends(get_current_user_full),
):
    """
    Désactive le MFA après vérification d'un code TOTP courant
    (évite la désactivation accidentelle ou non autorisée).
    """
    username = current_user["username"]
    mfa_info = get_mfa_info(username)
    if not mfa_info or not mfa_info.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="Le MFA n'est pas activé.")

    if not verify_totp(mfa_info["totp_secret"], payload.totp_code):
        raise HTTPException(status_code=400, detail="Code TOTP invalide.")

    disable_mfa(username)
    audit_log("MFA_DISABLE", username, "SUCCESS", detail="MFA TOTP désactivé")
    return {"status": "ok", "message": "MFA désactivé."}


# ─── Tokens d'API (CI/CD) ─────────────────────────────────────────────────────

class TokenCreate(BaseModel):
    name: str
    role: str = "uploader"
    expires_days: Optional[int] = None


@router.get("/api-tokens")
def get_api_tokens(admin: str = Depends(get_admin_user)):
    """Liste tous les tokens d'API."""
    return {"tokens": list_tokens()}


@router.post("/api-tokens", status_code=201)
def create_api_token(payload: TokenCreate, admin: str = Depends(get_admin_user)):
    """Crée un nouveau token d'API. Le token en clair n'est retourné qu'une seule fois."""
    valid_roles = ("admin", "maintainer", "uploader", "reader", "auditor")
    if payload.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Rôle invalide. Valeurs possibles : {', '.join(valid_roles)}")
    raw = create_token(
        name=payload.name,
        role=payload.role,
        created_by=admin,
        expires_days=payload.expires_days,
    )
    return {
        "token": raw,
        "message": "Copiez ce token maintenant — il ne sera plus affiché.",
        "prefix": API_TOKEN_PREFIX,
    }


@router.delete("/api-tokens/{token_id}")
def delete_api_token(token_id: str, admin: str = Depends(get_admin_user)):
    """Révoque un token d'API."""
    ok = revoke_token(token_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Token introuvable")
    return {"status": "revoked", "token_id": token_id}
