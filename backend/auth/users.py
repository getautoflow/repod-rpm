"""
Gestion des utilisateurs via SQLite.
Initialise automatiquement l'admin depuis les variables d'environnement si la DB est vide.
"""
import os
import sqlite3
import secrets
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

AUTH_DB_PATH = Path(os.getenv("AUTH_DB_PATH", "/repos/auth/users.db"))
_lock = Lock()

VALID_ROLES = {"admin", "maintainer", "uploader", "auditor", "reader"}

# Description des rôles — utilisée par l'API et le frontend
ROLE_DESCRIPTIONS = {
    "admin": {
        "label": "Administrateur",
        "description": "Accès total : gestion des utilisateurs, paramètres système, toutes opérations.",
        "color": "red",
    },
    "maintainer": {
        "label": "Mainteneur",
        "description": "Cycle de vie des paquets : upload, import, promotion entre distributions, suppression, synchronisation et lecture des logs d'audit.",
        "color": "purple",
    },
    "uploader": {
        "label": "Packager / CI-CD",
        "description": "Dépôt de paquets uniquement : upload et import. Ne peut pas supprimer, promouvoir ou accéder aux logs d'audit.",
        "color": "blue",
    },
    "auditor": {
        "label": "Auditeur",
        "description": "Lecture de l'ensemble du dépôt + accès aux logs d'audit. Aucune modification autorisée. Idéal pour les équipes conformité / RSSI.",
        "color": "yellow",
    },
    "reader": {
        "label": "Lecteur",
        "description": "Lecture seule : recherche et liste des paquets. Compte de service pour les machines clientes APT.",
        "color": "gray",
    },
}


def _get_db() -> sqlite3.Connection:
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(AUTH_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crée le schéma et initialise l'admin depuis l'environnement si nécessaire."""
    with _lock:
        with _get_db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    username     TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    role         TEXT NOT NULL DEFAULT 'reader',
                    full_name    TEXT NOT NULL DEFAULT '',
                    email        TEXT NOT NULL DEFAULT '',
                    active       INTEGER NOT NULL DEFAULT 1,
                    created_at   TEXT NOT NULL,
                    last_login   TEXT,
                    auth_source  TEXT NOT NULL DEFAULT 'local'
                );
            """)
            # Migration : ajouter auth_source si absente (DB existante)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "auth_source" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local'")

            # Insérer l'admin depuis l'env si la table est vide
            # IMPORTANT : le INSERT doit rester dans le bloc "with conn:" pour être commité
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count == 0:
                admin_username = os.getenv("ADMIN_USERNAME", "admin")
                admin_hash = os.getenv("ADMIN_PASSWORD_HASH", "")
                # Docker Compose double les $ dans env_file → les restaurer si nécessaire
                admin_hash = admin_hash.replace("$$", "$")
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO users (username, hashed_password, role, created_at) VALUES (?, ?, 'admin', ?)",
                    (admin_username, admin_hash, now),
                )


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_user(username: str) -> dict | None:
    init_db()
    with _lock:
        with _get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND active = 1",
                (username,)
            ).fetchone()
    return dict(row) if row else None


def get_user_any(username: str) -> dict | None:
    """Retourne un user même inactif (pour admin)."""
    init_db()
    with _lock:
        with _get_db() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    init_db()
    with _lock:
        with _get_db() as conn:
            rows = conn.execute(
                "SELECT id, username, role, full_name, email, active, created_at, last_login, auth_source "
                "FROM users ORDER BY role DESC, username ASC"
            ).fetchall()
    return [dict(r) for r in rows]


def create_user(username: str, password: str, role: str = "reader",
                full_name: str = "", email: str = "",
                auth_source: str = "local") -> dict:
    init_db()
    if role not in VALID_ROLES:
        raise ValueError(f"Rôle invalide : {role}")
    hashed = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, hashed_password, role, full_name, email, created_at, auth_source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, hashed, role, full_name, email, now, auth_source),
            )
    return get_user_any(username)


def update_user(username: str, role: str | None = None, full_name: str | None = None,
                email: str | None = None, active: bool | None = None,
                auth_source: str | None = None) -> dict | None:
    init_db()
    user = get_user_any(username)
    if not user:
        return None
    if role is not None and role not in VALID_ROLES:
        raise ValueError(f"Rôle invalide : {role}")
    with _lock:
        with _get_db() as conn:
            if role is not None:
                conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
            if full_name is not None:
                conn.execute("UPDATE users SET full_name = ? WHERE username = ?", (full_name, username))
            if email is not None:
                conn.execute("UPDATE users SET email = ? WHERE username = ?", (email, username))
            if active is not None:
                conn.execute("UPDATE users SET active = ? WHERE username = ?", (int(active), username))
            if auth_source is not None:
                conn.execute("UPDATE users SET auth_source = ? WHERE username = ?", (auth_source, username))
    return get_user_any(username)


def delete_user(username: str) -> bool:
    init_db()
    with _lock:
        with _get_db() as conn:
            result = conn.execute("DELETE FROM users WHERE username = ?", (username,))
    return result.rowcount > 0


def change_password(username: str, new_password: str) -> bool:
    init_db()
    hashed = hash_password(new_password)
    with _lock:
        with _get_db() as conn:
            result = conn.execute(
                "UPDATE users SET hashed_password = ? WHERE username = ?",
                (hashed, username)
            )
    return result.rowcount > 0


def update_last_login(username: str):
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        with _get_db() as conn:
            conn.execute("UPDATE users SET last_login = ? WHERE username = ?", (now, username))
