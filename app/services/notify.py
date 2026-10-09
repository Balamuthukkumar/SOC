"""Alert notifications: Slack, generic webhook, Mailgun email. Failures never propagate to the caller."""
import logging

import httpx

from app.config import settings
from app.services.integrations import validate_outbound_url

log = logging.getLogger(__name__)
NOTIFY_SEVERITIES = {"critical", "high"}


def summarize(user_email: str, alerts: list) -> str:
    lines = [f"[{a.severity.upper()}] {a.title}" + (" (known exploited)" if a.known_exploited else "") for a in alerts[:10]]
    more = f"\n...and {len(alerts) - 10} more" if len(alerts) > 10 else ""
    return f"{len(alerts)} new vulnerability alert(s) for {user_email}:\n" + "\n".join(lines) + more


async def _post(url: str, **kw) -> None:
    try:
        url = await validate_outbound_url(url)
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as http:
            (await http.post(url, **kw)).raise_for_status()
    except Exception as exc:
        log.warning("notification delivery failed: %s", type(exc).__name__)


async def notify_user(user, alerts: list) -> None:
    urgent = [a for a in alerts if a.severity in NOTIFY_SEVERITIES or a.known_exploited]
    if not urgent:
        return
    text = summarize(user.email, urgent)
    if slack := (user.slack_webhook_url or settings.slack_webhook_url):
        await _post(slack, json={"text": text})
    if hook := (user.webhook_url or settings.generic_webhook_url):
        await _post(hook, json={"text": text, "alerts": [{"id": a.id, "cve_id": a.cve_id, "severity": a.severity} for a in urgent]})
    if settings.mailgun_api_key and settings.mailgun_domain:
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                (await http.post(f"https://api.mailgun.net/v3/{settings.mailgun_domain}/messages",
                                 auth=("api", settings.mailgun_api_key),
                                 data={"from": settings.from_email, "to": user.email,
                                       "subject": f"{len(urgent)} new security alert(s)", "text": text})).raise_for_status()
        except Exception as exc:
            log.warning("email delivery failed: %s", type(exc).__name__)
