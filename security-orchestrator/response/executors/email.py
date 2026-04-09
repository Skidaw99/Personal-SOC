"""
Email executor — verstuurt alert emails via SMTP.

Gebruikt aiosmtplib voor async SMTP. Genereert een gestructureerde
HTML alert email met alle relevante event en threat intel data.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from ..config import response_settings
from ..schemas import ActionResult, ResponseEvent
from .base import BaseExecutor

logger = logging.getLogger(__name__)


class EmailExecutor(BaseExecutor):
    """Verstuurt alert emails via SMTP."""

    @property
    def action_type(self) -> str:
        return "email_alert"

    async def execute(self, event: ResponseEvent) -> ActionResult:
        recipients = [
            e.strip()
            for e in response_settings.alert_to_emails.split(",")
            if e.strip()
        ]
        if not recipients:
            return ActionResult(
                action_type=self.action_type,
                status="skipped",
                error="No alert_to_emails configured",
            )

        start = time.monotonic()
        subject = self._build_subject(event)
        body_html = self._build_body(event)

        msg = MIMEMultipart("alternative")
        msg["From"] = response_settings.alert_from_email
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg["X-SOC-Event-ID"] = str(event.soc_event_id)
        msg["X-SOC-Risk-Score"] = str(event.risk_score)
        msg.attach(MIMEText(body_html, "html"))

        try:
            await aiosmtplib.send(
                msg,
                hostname=response_settings.smtp_host,
                port=response_settings.smtp_port,
                username=response_settings.smtp_user or None,
                password=response_settings.smtp_password or None,
                start_tls=response_settings.smtp_use_tls,
            )

            elapsed = (time.monotonic() - start) * 1000

            logger.info(
                "email_alert_sent",
                recipients=recipients,
                subject=subject,
                soc_event_id=str(event.soc_event_id),
            )

            return ActionResult(
                action_type=self.action_type,
                status="success",
                target=", ".join(recipients),
                payload={
                    "subject": subject,
                    "recipients": recipients,
                    "from": response_settings.alert_from_email,
                },
                duration_ms=elapsed,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            error = f"SMTP send failed: {exc}"
            logger.error("email_send_failed", error=error)
            return ActionResult(
                action_type=self.action_type,
                status="failed",
                target=", ".join(recipients),
                payload={"subject": subject, "recipients": recipients},
                error=error,
                duration_ms=elapsed,
            )

    async def is_available(self) -> bool:
        return bool(
            response_settings.alert_to_emails
            and response_settings.smtp_host
        )

    @staticmethod
    def _build_subject(event: ResponseEvent) -> str:
        severity = event.severity.upper()
        return (
            f"[SOC ALERT — {severity}] {event.event_type} "
            f"| Risk {event.risk_score:.0f}/100"
            f"{' | ' + event.source_ip if event.source_ip else ''}"
        )

    @staticmethod
    def _build_body(event: ResponseEvent) -> str:
        actor_info = ""
        if event.actor_display_name:
            actor_info = f"""
            <tr><td><strong>Threat Actor</strong></td>
                <td>{event.actor_display_name} (level: {event.actor_threat_level or 'unknown'})</td></tr>
            """

        return f"""
        <html>
        <body style="font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px;">
            <h2 style="color: #e74c3c;">SOC Security Alert</h2>
            <table style="border-collapse: collapse; width: 100%;">
                <tr><td><strong>Event Type</strong></td><td>{event.event_type}</td></tr>
                <tr><td><strong>Severity</strong></td><td>{event.severity.upper()}</td></tr>
                <tr><td><strong>Risk Score</strong></td><td>{event.risk_score:.1f} / 100</td></tr>
                <tr><td><strong>Source IP</strong></td><td>{event.source_ip or 'N/A'}</td></tr>
                <tr><td><strong>Country</strong></td><td>{event.source_country or 'N/A'}</td></tr>
                <tr><td><strong>Platform</strong></td><td>{event.platform or 'N/A'}</td></tr>
                <tr><td><strong>Target User</strong></td><td>{event.target_user_id or 'N/A'}</td></tr>
                {actor_info}
                <tr><td><strong>Event ID</strong></td><td>{event.soc_event_id}</td></tr>
                <tr><td><strong>Occurred At</strong></td><td>{event.occurred_at.isoformat()} UTC</td></tr>
            </table>
            {f'<h3>Description</h3><p>{event.description}</p>' if event.description else ''}
            <hr>
            <p style="color: #888;">Automated alert from SOC Security Orchestrator</p>
        </body>
        </html>
        """
