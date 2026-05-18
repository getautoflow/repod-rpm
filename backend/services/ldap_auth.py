"""
Authentification LDAP / Active Directory.

Flux :
  1. Connexion au serveur LDAP avec le compte de service (bind_dn / bind_password)
  2. Recherche de l'utilisateur dans base_dn via user_filter
  3. Rebind avec le DN de l'utilisateur + mot de passe fourni (vérifie les credentials)
  4. Lecture des groupes pour mapper vers un rôle repod
  5. Retourne un dict user { username, email, full_name, role }

Compatible Active Directory (sAMAccountName) et OpenLDAP (uid).
"""

import logging
from typing import Optional

logger = logging.getLogger("ldap_auth")

# Ordre de priorité des rôles (du plus fort au plus faible)
ROLE_PRIORITY = ["admin", "maintainer", "uploader", "auditor", "reader"]


def _get_ldap_config() -> dict:
    from services.settings import get_settings
    return get_settings().get("ldap", {})


def _build_server(cfg: dict):
    from ldap3 import Server, Tls
    import ssl

    host        = cfg.get("host", "")
    port        = int(cfg.get("port", 389))
    use_ssl     = cfg.get("use_ssl", False)
    use_tls     = use_ssl or cfg.get("use_starttls", False)
    verify_cert = cfg.get("verify_cert", True)

    tls = None
    if use_tls:
        if verify_cert:
            ca_bundle = cfg.get("ca_bundle_path", "").strip() or None
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_bundle)
        else:
            # Sous-classe Tls (passe le isinstance de ldap3) avec wrap_socket
            # personnalisé : TLS 1.2 forcé + CERT_NONE + pas de SNI.
            # Nécessaire pour les certs auto-signés Windows AD / Schannel.
            class _LenientTls(Tls):
                def wrap_socket(inner_self, connection, do_handshake=False):
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    try:
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                    except AttributeError:
                        pass
                    wrapped = ctx.wrap_socket(
                        connection.socket,
                        server_side=False,
                        do_handshake_on_connect=do_handshake,
                        server_hostname=None,
                    )
                    connection.socket = wrapped
                    return wrapped

            tls = _LenientTls(validate=ssl.CERT_NONE)
            logger.warning(
                "[ldap] verify_cert=False : validation TLS désactivée, TLS 1.2 forcé. "
                "Risque MITM. Configurez ca_bundle_path pour une validation complète."
            )

    return Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info="ALL")


def _resolve_role(groups: list[str], cfg: dict) -> str:
    """
    Détermine le rôle repod en fonction des groupes LDAP de l'utilisateur.
    Parcourt les rôles par ordre de priorité et retourne le plus élevé trouvé.
    """
    group_map = {
        "admin":      cfg.get("group_admin", ""),
        "maintainer": cfg.get("group_maintainer", ""),
        "uploader":   cfg.get("group_uploader", ""),
        "auditor":    cfg.get("group_auditor", ""),
        "reader":     cfg.get("group_reader", ""),
    }
    # Normaliser les DNs/noms de groupes en minuscules pour la comparaison
    groups_lower = [g.lower() for g in groups]

    for role in ROLE_PRIORITY:
        mapped_group = group_map.get(role, "").strip()
        if not mapped_group:
            continue
        # Correspondance flexible : DN complet ou CN seulement
        mapped_lower = mapped_group.lower()
        for g in groups_lower:
            if mapped_lower == g or mapped_lower in g:
                return role

    return cfg.get("default_role", "reader")


def _make_connection(server, user: str, password: str, use_starttls: bool):
    """
    Crée et ouvre une connexion LDAP en respectant l'ordre correct :
    - STARTTLS actif  → AUTO_BIND_TLS_BEFORE_BIND (TLS *avant* le bind)
    - STARTTLS inactif → AUTO_BIND_NO_TLS (comportement standard)
    Active Directory exige que TLS soit établi AVANT l'envoi des credentials.
    """
    from ldap3 import Connection, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, SIMPLE
    auto_bind = AUTO_BIND_TLS_BEFORE_BIND if use_starttls else AUTO_BIND_NO_TLS
    return Connection(
        server,
        user=user,
        password=password,
        authentication=SIMPLE,
        auto_bind=auto_bind,
        raise_exceptions=True,
    )


def authenticate(username: str, password: str) -> Optional[dict]:
    """
    Tente une authentification LDAP.
    Retourne un dict { username, email, full_name, role } en cas de succès, None sinon.
    Lève une exception si le serveur LDAP est injoignable (pour distinguer
    « mauvais mot de passe » de « serveur HS »).
    """
    from ldap3 import SUBTREE
    from ldap3.core.exceptions import LDAPBindError, LDAPException

    cfg = _get_ldap_config()
    if not cfg.get("enabled", False):
        return None

    host = cfg.get("host", "").strip()
    if not host:
        logger.warning("[ldap] Hôte LDAP non configuré")
        return None

    bind_dn       = cfg.get("bind_dn", "").strip()
    bind_password = cfg.get("bind_password", "").strip()
    base_dn       = cfg.get("base_dn", "").strip()
    user_filter   = cfg.get("user_filter", "(sAMAccountName={username})").replace("{username}", username)
    attr_username = cfg.get("attr_username", "sAMAccountName")
    attr_email    = cfg.get("attr_email", "mail")
    attr_fullname = cfg.get("attr_fullname", "displayName")
    attr_groups   = cfg.get("attr_groups", "memberOf")
    use_starttls  = cfg.get("use_starttls", False)

    try:
        server = _build_server(cfg)

        # ── Bind de service (TLS établi avant le bind si STARTTLS) ────────────
        svc_conn = _make_connection(server, bind_dn, bind_password, use_starttls)

        # ── Recherche de l'utilisateur ─────────────────────────────────────────
        svc_conn.search(
            search_base=base_dn,
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=[attr_username, attr_email, attr_fullname, attr_groups],
        )

        if not svc_conn.entries:
            logger.info(f"[ldap] Utilisateur '{username}' introuvable dans {base_dn}")
            svc_conn.unbind()
            return None

        entry    = svc_conn.entries[0]
        user_dn  = entry.entry_dn
        svc_conn.unbind()

        # ── Bind utilisateur (vérifie le mot de passe) ────────────────────────
        try:
            user_conn = _make_connection(server, user_dn, password, use_starttls)
            user_conn.unbind()
        except LDAPBindError:
            logger.info(f"[ldap] Mauvais mot de passe pour '{username}'")
            return None

        # ── Extraction des attributs ──────────────────────────────────────────
        def _attr(e, key):
            try:
                v = getattr(e, key, None)
                if v is None:
                    return ""
                vals = v.values if hasattr(v, "values") else [str(v)]
                return vals[0] if vals else ""
            except Exception:
                return ""

        raw_username = _attr(entry, attr_username) or username
        email        = _attr(entry, attr_email)
        full_name    = _attr(entry, attr_fullname)

        # Groupes (memberOf est une liste de DNs dans AD)
        try:
            groups_raw = getattr(entry, attr_groups, None)
            groups = list(groups_raw.values) if groups_raw and hasattr(groups_raw, "values") else []
        except Exception:
            groups = []

        role = _resolve_role(groups, cfg)

        logger.info(f"[ldap] Authentification réussie : {username} → rôle={role}")
        return {
            "username":  str(raw_username),
            "email":     str(email),
            "full_name": str(full_name),
            "role":      role,
        }

    except LDAPException as e:
        logger.error(f"[ldap] Erreur connexion LDAP : {e}")
        raise  # Remonter → le router affichera "serveur indisponible"
    except Exception as e:
        logger.error(f"[ldap] Erreur inattendue : {e}")
        raise


def test_connection() -> dict:
    """
    Teste la connexion et le bind de service.
    Retourne { ok, message, server_info }.
    """
    from ldap3.core.exceptions import LDAPException

    cfg = _get_ldap_config()
    # On autorise le test même si LDAP n'est pas encore activé (pour valider la config avant d'activer)
    host = cfg.get("host", "").strip()
    if not host:
        return {"ok": False, "message": "Hôte LDAP non configuré."}

    use_starttls = cfg.get("use_starttls", False)

    try:
        server = _build_server(cfg)
        conn   = _make_connection(
            server,
            cfg.get("bind_dn", ""),
            cfg.get("bind_password", ""),
            use_starttls,
        )
        info = str(server.info)[:500] if server.info else "Serveur connecté."
        conn.unbind()
        tls_note = " (STARTTLS actif)" if use_starttls else ""
        return {"ok": True, "message": f"Connexion établie sur {host}{tls_note}.", "server_info": info}

    except LDAPException as e:
        return {"ok": False, "message": str(e)}
    except Exception as e:
        return {"ok": False, "message": str(e)}
