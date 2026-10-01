"""Durable SMTP notification delivery for approval workflow events."""

import logging
import os
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from firewall_manager.config import Settings
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import EmailNotification

logger = logging.getLogger(__name__)


class SmtpNotConfiguredError(RuntimeError):
    """Raised when an outbound email is queued but SMTP is not configured."""


class SmtpEmailSender:
    """Provider-neutral SMTP adapter using the Python standard library."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def send(self, recipient: str, subject: str, body: str) -> None:
        settings = self._settings
        if not settings.smtp_host or not settings.smtp_from:
            raise SmtpNotConfiguredError("SMTP_HOST and SMTP_FROM are required")
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(body)
        context = ssl.create_default_context()
        client: smtplib.SMTP | smtplib.SMTP_SSL
        if settings.smtp_use_ssl:
            client = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds
            )
        else:
            client = smtplib.SMTP(
                settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds
            )
        with client:
            client.ehlo()
            if settings.smtp_use_starttls:
                client.starttls(context=context)
                client.ehlo()
            if settings.smtp_username:
                if settings.smtp_password is None:
                    raise SmtpNotConfiguredError("SMTP_PASSWORD is required with SMTP_USERNAME")
                client.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            client.send_message(message)


def claim_email_notifications(
    session: Session, owner: str, now: datetime, limit: int = 25
) -> list[EmailNotification]:
    """Claim due work with a short lease so multiple workers cannot send the same row."""
    rows = list(
        session.scalars(
            select(EmailNotification)
            .where(
                EmailNotification.next_attempt_at <= now,
                or_(
                    EmailNotification.status.in_(("PENDING", "FAILED")),
                    EmailNotification.lease_until < now,
                ),
            )
            .order_by(EmailNotification.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    for row in rows:
        row.status = "SENDING"
        row.attempts += 1
        row.lease_owner = owner
        row.lease_until = now + timedelta(minutes=2)
    session.commit()
    return rows


def mark_email_sent(notification_id: UUID, owner: str) -> None:
    with new_session() as session:
        row = session.get(EmailNotification, notification_id)
        if row is None or row.lease_owner != owner:
            return
        row.status = "SENT"
        row.sent_at = datetime.now(UTC)
        row.lease_owner = None
        row.lease_until = None
        row.last_error = None
        session.commit()


def mark_email_failed(notification_id: UUID, owner: str, error: str) -> None:
    with new_session() as session:
        row = session.get(EmailNotification, notification_id)
        if row is None or row.lease_owner != owner:
            return
        delay = min(3600, 30 * (2 ** min(row.attempts - 1, 6)))
        row.status = "FAILED"
        row.next_attempt_at = datetime.now(UTC) + timedelta(seconds=delay)
        row.last_error = error[:500]
        row.lease_owner = None
        row.lease_until = None
        session.commit()


def deliver_queued_email_notifications(settings: Settings, session: Session) -> int:
    """Send one bounded batch; failures stay durable for a later retry."""
    owner = f"{os.uname().nodename}:{os.getpid()}"
    rows = claim_email_notifications(session, owner, datetime.now(UTC))
    sender = SmtpEmailSender(settings)
    for row in rows:
        try:
            sender.send(row.recipient_email, row.subject, row.body)
        except SmtpNotConfiguredError as exc:
            logger.warning("Approval email delivery is not configured: %s", exc)
            mark_email_failed(row.id, owner, "SMTP_NOT_CONFIGURED")
        except (OSError, smtplib.SMTPException) as exc:
            logger.warning("SMTP delivery failed for notification %s: %s", row.id, exc)
            mark_email_failed(row.id, owner, "SMTP_DELIVERY_FAILED")
        else:
            mark_email_sent(row.id, owner)
    return len(rows)
