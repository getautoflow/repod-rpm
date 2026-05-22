"""
Module : test_email_notifications.py
Rôle   : Tests unitaires pour services/email_notifications.py
Expose : TestGetEmailCfg · TestSendEmail · TestSendTestEmail
         TestNotifyPendingReviewEmail · TestNotifyDecisionEmail
         TestNotifySlaExpiringEmail

Adapté depuis repod-apt → RPM (règle R5) :
  amd64 → x86_64 | jammy/bookworm/noble → almalinux8/rocky9/centos-stream9

Dépend : pytest, unittest.mock, services.email_notifications
"""
import email as _email_lib
import email.header
from pathlib import Path

import pytest
import smtplib
from unittest.mock import patch, MagicMock

from services.email_notifications import (
    _send_email,
    _send_email_to,
    _get_email_cfg,
    send_test_email,
    notify_pending_review_email,
    notify_decision_email,
    notify_sla_expiring_email,
)


# ── Helpers MIME ──────────────────────────────────────────────────────────────

def _decode_mime_body(raw_msg: str) -> str:
    """Décode un message MIME brut en texte lisible (sujet + corps)."""
    msg = _email_lib.message_from_string(raw_msg)
    parts: list[str] = []

    raw_subject = msg.get("Subject", "")
    for encoded_bytes, charset in _email_lib.header.decode_header(raw_subject):
        if isinstance(encoded_bytes, bytes):
            parts.append(encoded_bytes.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(encoded_bytes)

    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True)
            if payload:
                cs = part.get_content_charset() or "utf-8"
                parts.append(payload.decode(cs, errors="replace"))

    return " ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════════
# _get_email_cfg
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetEmailCfg:

    def test_returns_none_when_disabled(self, email_settings_disabled):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            assert _get_email_cfg() is None

    def test_returns_none_when_smtp_host_missing(self, email_settings):
        email_settings["email"]["smtp_host"] = ""
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            assert _get_email_cfg() is None

    def test_returns_none_when_to_addresses_missing(self, email_settings):
        email_settings["email"]["to_addresses"] = ""
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            assert _get_email_cfg() is None

    def test_returns_cfg_when_valid(self, email_settings):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _get_email_cfg()
        assert result is not None
        assert result["smtp_host"] == "smtp.test.local"


# ═══════════════════════════════════════════════════════════════════════════════
# _send_email — to_override et comportements SMTP
# ═══════════════════════════════════════════════════════════════════════════════

class TestSendEmail:

    def test_returns_false_when_email_disabled(self, email_settings_disabled):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            assert _send_email("Sujet", "<p>html</p>", "texte") is False

    def test_returns_false_when_no_recipients_configured(self, email_settings):
        email_settings["email"]["to_addresses"] = "  ,  ,  "
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            assert _send_email("Sujet", "<p>html</p>", "texte") is False

    def test_to_override_routes_email_to_specified_address(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email(
                "Reset password — RPM Repo Manager",
                "<p>Lien de réinitialisation</p>",
                "Lien de réinitialisation",
                to_override="user.specifique@company.com",
            )

        assert result is True
        _, recipients, _ = mock_server.sendmail.call_args.args
        assert recipients == ["user.specifique@company.com"]

    def test_to_override_ignores_configured_to_addresses(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Sujet", "<p>html</p>", "texte",
                        to_override="override@test.com")

        _, recipients, _ = mock_server.sendmail.call_args.args
        assert "admin@test.local" not in recipients
        assert recipients == ["override@test.com"]

    def test_to_override_empty_string_returns_false(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email("Sujet", "<p>html</p>", "texte",
                                 to_override="   ")

        assert result is False
        mock_server.sendmail.assert_not_called()

    def test_to_override_none_falls_back_to_to_addresses(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email("Sujet", "<p>html</p>", "texte",
                                 to_override=None)

        assert result is True
        _, recipients, _ = mock_server.sendmail.call_args.args
        assert recipients == ["admin@test.local"]

    def test_uses_configured_recipients_without_override(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        email_settings["email"]["to_addresses"] = "a@x.com, b@x.com , c@x.com"
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email("Sujet", "<p>html</p>", "texte")

        assert result is True
        _, recipients, _ = mock_server.sendmail.call_args.args
        assert set(recipients) == {"a@x.com", "b@x.com", "c@x.com"}

    def test_starttls_called_on_port_587(self, email_settings, mock_smtp):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Sujet", "<p>html</p>", "texte")
        mock_server.starttls.assert_called_once()

    def test_no_starttls_when_use_tls_false(self, email_settings, mock_smtp):
        mock_class, mock_server = mock_smtp
        email_settings["email"]["use_tls"] = False
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Sujet", "<p>html</p>", "texte")
        mock_server.starttls.assert_not_called()

    def test_smtp_ssl_used_on_port_465(self, email_settings_ssl, mock_smtp_ssl):
        mock_class, mock_server = mock_smtp_ssl
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_ssl):
            result = _send_email("Sujet", "<p>html</p>", "texte")
        assert result is True
        mock_class.assert_called_once()

    def test_login_called_with_credentials(self, email_settings, mock_smtp):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Sujet", "<p>html</p>", "texte")
        mock_server.login.assert_called_once_with("repod@test.local", "s3cr3t")

    def test_auth_error_returns_false(self, email_settings, mock_smtp):
        mock_class, mock_server = mock_smtp
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(
            535, b"Incorrect authentication data"
        )
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email("Sujet", "<p>html</p>", "texte")
        assert result is False

    def test_connect_error_returns_false(self, email_settings):
        with patch("smtplib.SMTP",
                   side_effect=smtplib.SMTPConnectError(421, b"no route")):
            with patch("services.email_notifications.get_settings",
                       return_value=email_settings):
                result = _send_email("Sujet", "<p>html</p>", "texte")
        assert result is False

    def test_subject_prefixed_with_repod(self, email_settings, mock_smtp):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Mon sujet", "<p>html</p>", "texte")
        _, _, raw_msg = mock_server.sendmail.call_args.args
        assert "[repod]" in raw_msg
        assert "Mon sujet" in raw_msg


# ═══════════════════════════════════════════════════════════════════════════════
# send_test_email
# ═══════════════════════════════════════════════════════════════════════════════

class TestSendTestEmail:

    def test_returns_error_when_disabled(self, email_settings_disabled):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            result = send_test_email()
        assert result["ok"] is False
        assert "désactivées" in result["error"]

    def test_returns_error_when_no_smtp_host(self):
        with patch("services.email_notifications.get_settings",
                   return_value={"email": {"enabled": True, "smtp_host": ""}}):
            result = send_test_email()
        assert result["ok"] is False
        assert "smtp_host" in result["error"]

    def test_returns_error_when_no_recipients(self, email_settings):
        email_settings["email"]["to_addresses"] = ""
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = send_test_email()
        assert result["ok"] is False
        assert "destinataire" in result["error"].lower()

    def test_success_with_configured_recipients(self, email_settings, mock_smtp):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = send_test_email()
        assert result["ok"] is True
        assert result["error"] is None

    def test_to_override_used_as_sole_recipient(self, email_settings, mock_smtp):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = send_test_email(to_override="test-override@company.com")

        assert result["ok"] is True
        _, recipients, _ = mock_server.sendmail.call_args.args
        assert recipients == ["test-override@company.com"]

    def test_smtp_failure_returns_error_dict(self, email_settings, mock_smtp):
        mock_class, mock_server = mock_smtp
        mock_server.sendmail.side_effect = Exception("network error")
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = send_test_email()
        assert result["ok"] is False
        assert result["error"] is not None


# ═══════════════════════════════════════════════════════════════════════════════
# notify_pending_review_email — paquet RPM en attente de revue
# ═══════════════════════════════════════════════════════════════════════════════

class TestNotifyPendingReviewEmail:

    def test_returns_false_when_email_disabled(self, email_settings_disabled):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            result = notify_pending_review_email(
                package="nginx", version="1.24.0", arch="x86_64",
                distribution="almalinux8", cve_counts={}, worst_severity=None,
            )
        assert result is False

    def test_sends_email_with_package_name_and_version(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = notify_pending_review_email(
                package="nginx",
                version="1.24.0",
                arch="x86_64",
                distribution="almalinux8",
                cve_counts={"Critical": 2, "High": 5},
                worst_severity="Critical",
                kev_count=1,
            )
        assert result is True
        _, _, raw_msg = mock_server.sendmail.call_args.args
        decoded = _decode_mime_body(raw_msg)
        assert "nginx" in decoded
        assert "1.24.0" in decoded

    def test_kev_block_present_when_kev_count_nonzero(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            notify_pending_review_email(
                package="openssl", version="3.0.2", arch="x86_64",
                distribution="rocky9",
                cve_counts={"Critical": 1}, worst_severity="Critical",
                kev_count=2,
            )
        _, _, raw_msg = mock_server.sendmail.call_args.args
        assert "KEV" in _decode_mime_body(raw_msg)

    def test_kev_block_absent_when_kev_count_zero(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            notify_pending_review_email(
                package="vim", version="9.0", arch="x86_64",
                distribution="centos-stream9",
                cve_counts={"Medium": 2}, worst_severity="Medium",
            )
        _, _, raw_msg = mock_server.sendmail.call_args.args
        assert "KEV CISA" not in _decode_mime_body(raw_msg)

    def test_upload_module_imports_notify_pending_review_email(self):
        """routers/upload.py doit importer notify_pending_review_email."""
        upload_src = Path(__file__).parent.parent / "routers" / "upload.py"
        assert upload_src.exists(), "routers/upload.py introuvable"
        assert "notify_pending_review_email" in upload_src.read_text(), (
            "notify_pending_review_email doit être importée dans upload.py"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# notify_decision_email
# ═══════════════════════════════════════════════════════════════════════════════

class TestNotifyDecisionEmail:

    def test_returns_false_when_email_disabled(self, email_settings_disabled):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            result = notify_decision_email(
                package="curl", version="7.88.1",
                action="reject", decided_by="admin",
                justification="CVE critique non corrigée.",
            )
        assert result is False

    @pytest.mark.parametrize("action,expected_label", [
        ("accept_risk",      "Risque accepté"),
        ("exception",        "Exception"),
        ("reject",           "Rejeté"),
        ("upgrade_required", "Upgrade"),
    ])
    def test_all_actions_send_email_with_correct_label(
        self, action, expected_label, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = notify_decision_email(
                package="libssl", version="3.0.2",
                action=action, decided_by="rssi@company.com",
                justification="Justification de test.",
            )
        assert result is True
        _, _, raw_msg = mock_server.sendmail.call_args.args
        assert expected_label in _decode_mime_body(raw_msg)

    def test_package_and_version_in_email_body(self, email_settings, mock_smtp):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            notify_decision_email(
                package="openssl", version="3.1.0",
                action="accept_risk", decided_by="admin",
                justification="Pas de fix disponible.",
                expires_in_days=30,
            )
        _, _, raw_msg = mock_server.sendmail.call_args.args
        decoded = _decode_mime_body(raw_msg)
        assert "openssl" in decoded
        assert "3.1.0" in decoded

    def test_expiration_row_present_when_expires_in_days_set(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            notify_decision_email(
                package="curl", version="7.88.1",
                action="exception", decided_by="rssi",
                justification="Exception 30 jours.",
                expires_in_days=30,
            )
        _, _, raw_msg = mock_server.sendmail.call_args.args
        assert "30" in _decode_mime_body(raw_msg)

    def test_expiration_absent_when_expires_in_days_none(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            notify_decision_email(
                package="vim", version="9.0",
                action="reject", decided_by="admin",
                justification="Rejet définitif.",
                expires_in_days=None,
            )
        _, _, raw_msg = mock_server.sendmail.call_args.args
        assert "Expiration SLA" not in _decode_mime_body(raw_msg)

    def test_security_router_imports_notify_decision_email(self):
        """routers/security_router.py doit importer notify_decision_email."""
        sec_src = Path(__file__).parent.parent / "routers" / "security_router.py"
        assert sec_src.exists(), "routers/security_router.py introuvable"
        assert "notify_decision_email" in sec_src.read_text(), (
            "notify_decision_email doit être importée dans security_router.py"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# notify_sla_expiring_email
# ═══════════════════════════════════════════════════════════════════════════════

class TestNotifySlaExpiringEmail:

    def test_returns_false_on_empty_list(self, email_settings):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            assert notify_sla_expiring_email([]) is False

    def test_sends_email_listing_expiring_decisions(
        self, email_settings, mock_smtp
    ):
        mock_class, mock_server = mock_smtp
        decisions = [
            {
                "package":        "nginx",
                "version":        "1.24.0",
                "action":         "accept_risk",
                "decided_by":     "rssi",
                "remaining_days": 3,
            }
        ]
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = notify_sla_expiring_email(decisions)
        assert result is True
        _, _, raw_msg = mock_server.sendmail.call_args.args
        assert "nginx" in _decode_mime_body(raw_msg)

    def test_returns_false_when_email_disabled(self, email_settings_disabled):
        decisions = [{"package": "curl", "version": "7.0",
                      "action": "accept_risk", "decided_by": "admin",
                      "remaining_days": 2}]
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            assert notify_sla_expiring_email(decisions) is False
