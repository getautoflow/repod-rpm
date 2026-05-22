"""
Service de persistance des paramètres de l'application.
Stockage : /repos/settings.json (volume Docker partagé → survit aux restarts).

Structure complète avec valeurs par défaut :
{
  "sync": { "enabled": true, "hour": 3, "minute": 0 },
  "sources": { "almalinux8-baseos": true, ... },
  "notifications": { "webhook_url": "", "webhook_enabled": false, "webhook_min_packages": 1 },
  "retention": { "audit_days": 90, "import_cleanup_days": 30 },
  "validation": { "sha256_check": true, "clamav_scan": true, "max_upload_size_mb": 500 }
}
"""

import copy
import json
import os
from pathlib import Path
from threading import RLock

SETTINGS_PATH = Path(os.getenv("SETTINGS_PATH", "/repos/settings.json"))

_lock = RLock()

DEFAULT_SETTINGS: dict = {
    "app_url": "http://localhost:3003",
    "sync": {
        "enabled": True,
        "hour": 3,
        "minute": 0,
    },
    "sources": {
        # ── AlmaLinux ──────────────────────────────────────────────────────────
        "almalinux8-baseos":          True,
        "almalinux8-appstream":       True,
        "almalinux8-extras":          True,
        "almalinux9-baseos":          True,
        "almalinux9-appstream":       True,
        # ── Rocky Linux ────────────────────────────────────────────────────────
        "rocky8-baseos":              True,
        "rocky8-appstream":           True,
        "rocky9-baseos":              True,
        "rocky9-appstream":           True,
        # ── CentOS Stream ──────────────────────────────────────────────────────
        "centos-stream9-baseos":      True,
        "centos-stream9-appstream":   True,
        # ── Oracle Linux ───────────────────────────────────────────────────────
        "oraclelinux8-baseos":        True,
        "oraclelinux8-appstream":     True,
        "oraclelinux9-baseos":        True,
        # ── Fedora ─────────────────────────────────────────────────────────────
        "fedora42":                   True,
        "fedora42-updates":           True,
        # ── EPEL (désactivé par défaut — volumineuse) ──────────────────────────
        "epel8":                      False,
        "epel9":                      False,
        # ── openSUSE ───────────────────────────────────────────────────────────
        "opensuse-leap-15.6-oss":     True,
        "opensuse-leap-15.6-updates": True,
        "opensuse-tumbleweed-oss":    True,
    },
    "notifications": {
        "webhook_url": "",
        "webhook_enabled": False,
        "webhook_min_packages": 1,
    },
    "email": {
        "enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "from_address": "",
        "to_addresses": "",
        "use_tls": True,
    },
    "ldap": {
        "enabled":          False,
        "host":             "",
        "port":             389,
        "use_ssl":          False,
        "use_starttls":     False,
        "bind_dn":          "",
        "bind_password":    "",
        "base_dn":          "",
        # {username} sera remplacé par la valeur saisie au login
        "user_filter":      "(sAMAccountName={username})",
        # Attributs à lire depuis l'entrée LDAP
        "attr_username":    "sAMAccountName",
        "attr_email":       "mail",
        "attr_fullname":    "displayName",
        "attr_groups":      "memberOf",
        # Mapping groupes → rôles repod (DN complet ou CN partiel)
        "group_admin":      "",
        "group_maintainer": "",
        "group_uploader":   "",
        "group_auditor":    "",
        "group_reader":     "",
        # Rôle par défaut si aucun groupe ne correspond
        "default_role":     "reader",
        # Auto-créer l'utilisateur dans la DB locale après 1ère auth LDAP réussie
        "auto_provision":   True,
        # Sécurité TLS : valider le certificat du serveur LDAP (recommandé : True)
        # Mettre False uniquement si CA interne auto-signée sans bundle disponible
        "verify_cert":      True,
        # Chemin vers le bundle CA si certificat auto-signé (ex: /repos/certs/internal-ca.crt)
        "ca_bundle_path":   "",
    },
    "retention": {
        "audit_days": 90,
        "import_cleanup_days": 30,
    },
    "validation": {
        "sha256_check": True,
        "clamav_scan": True,
        "grype_scan": True,
        "grype_fail_on": "critical",  # conservé pour compat — remplacé par cve_policy
        "max_upload_size_mb": 500,
    },
    # ── SSO / OIDC (Authorization Code + PKCE) ────────────────────────────────
    # Compatible : Keycloak, Authentik, Zitadel, Azure AD (Entra ID), Okta, ADFS…
    "oidc": {
        "enabled":          False,
        "provider_name":    "SSO",          # Libellé du bouton sur la page de login
        "discovery_url":    "",             # ex. https://sso.example.com/realms/myorg/.well-known/openid-configuration
        "client_id":        "",
        "client_secret":    "",
        "scopes":           "openid email profile",
        "redirect_uri":     "",             # vide = calculé depuis app_url
        # Provisioning
        "auto_provision":   True,           # Créer l'utilisateur repod-rpm au 1er login SSO
        "default_role":     "reader",       # Rôle par défaut si aucun mapping ne correspond
        # Mapping des claims IdP → champs repod-rpm
        "claim_username":   "preferred_username",  # Keycloak / Authentik / Okta
        "claim_email":      "email",
        "claim_fullname":   "name",
        "claim_role":       "",             # Claim portant les groupes/rôles IdP (ex. "groups")
        "role_map":         {},             # { "idp-group": "repod-role", ... }
    },
    "cve_policy": {
        # Action par sévérité : "block" | "review" | "warn" | "allow"
        #   block  → rejet immédiat, quarantaine
        #   review → en attente d'approbation RSSI (pas publié dans APT)
        #   warn   → import autorisé, avertissement visible
        #   allow  → transparent, aucune action
        "critical":   "block",
        "high":       "review",
        "medium":     "warn",
        "low":        "allow",
        "negligible": "allow",
        # SLA de remédiation (jours) — 0 = immédiat/bloqué
        "sla_critical_days": 0,
        "sla_high_days":     30,
        "sla_medium_days":   90,
        # Enrichissement automatique EPSS + KEV à l'import
        "auto_enrich": True,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Fusion profonde : override écrase base, les clés absentes de override restent intactes."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def get_settings() -> dict:
    """
    Charge les paramètres depuis settings.json.
    Si le fichier est absent ou corrompu, retourne les valeurs par défaut.
    Fusionne toujours avec DEFAULT_SETTINGS pour garantir les nouvelles clés.
    """
    with _lock:
        if not SETTINGS_PATH.exists():
            return copy.deepcopy(DEFAULT_SETTINGS)
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                stored = json.load(f)
            return _deep_merge(DEFAULT_SETTINGS, stored)
        except Exception:
            return copy.deepcopy(DEFAULT_SETTINGS)


def update_settings(partial: dict) -> dict:
    """
    Met à jour les paramètres en fusionnant avec les valeurs existantes.
    Écrit immédiatement sur disque.
    Retourne les paramètres complets mis à jour.
    """
    with _lock:
        current = get_settings()
        merged = _deep_merge(current, partial)
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2, ensure_ascii=False)
        return merged


def is_source_enabled(source_id: str) -> bool:
    """Retourne True si la source APT est activée dans les paramètres."""
    settings = get_settings()
    return settings["sources"].get(source_id, True)
