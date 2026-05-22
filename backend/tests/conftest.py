"""
Module : conftest.py
Rôle   : Fixtures pytest partagées — configuration email, mocks SMTP
Expose : email_settings, email_settings_ssl, email_settings_disabled,
         mock_smtp, mock_smtp_ssl
Dépend : pytest, unittest.mock
"""
import pytest
from unittest.mock import patch, MagicMock


# ── Données de test ───────────────────────────────────────────────────────────

_EMAIL_CFG_BASE = {
    "enabled":       True,
    "smtp_host":     "smtp.test.local",
    "smtp_port":     587,
    "smtp_user":     "repod@test.local",
    "smtp_password": "s3cr3t",
    "from_address":  "repod@test.local",
    "to_addresses":  "admin@test.local",
    "use_tls":       True,
}


@pytest.fixture
def email_settings():
    """Settings complets avec email activé — port 587 (STARTTLS)."""
    return {
        "email":         _EMAIL_CFG_BASE.copy(),
        "notifications": {"webhook_enabled": False, "webhook_url": ""},
        "app_url":       "http://localhost:3003",
    }


@pytest.fixture
def email_settings_ssl():
    """Settings email avec port 465 — SMTP_SSL direct."""
    cfg = {**_EMAIL_CFG_BASE, "smtp_port": 465}
    return {
        "email":         cfg,
        "notifications": {"webhook_enabled": False, "webhook_url": ""},
        "app_url":       "http://localhost:3003",
    }


@pytest.fixture
def email_settings_disabled():
    """Settings avec email désactivé."""
    return {"email": {"enabled": False}}


# ── Mocks SMTP ────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_smtp():
    """
    Mock smtplib.SMTP pour port 587 (STARTTLS).
    Yields (mock_class, mock_server).
    """
    with patch("smtplib.SMTP") as mock_class:
        mock_server = mock_class.return_value.__enter__.return_value
        yield mock_class, mock_server


@pytest.fixture
def mock_smtp_ssl():
    """Mock smtplib.SMTP_SSL pour port 465."""
    with patch("smtplib.SMTP_SSL") as mock_class:
        mock_server = mock_class.return_value.__enter__.return_value
        yield mock_class, mock_server
