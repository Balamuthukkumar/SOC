"""Outbound SIEM/SOAR integrations. Every outbound URL is HTTPS-only and must resolve to public addresses."""
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)
FAILED = {"success": False, "error": "Integration request failed"}

TYPES = [
    {"type": "splunk", "name": "Splunk", "description": "Splunk HTTP Event Collector"},
    {"type": "sentinel", "name": "Microsoft Sentinel", "description": "Azure Log Analytics Data Collector"},
    {"type": "servicenow", "name": "ServiceNow", "description": "ServiceNow incident creation"},
    {"type": "pagerduty", "name": "PagerDuty", "description": "PagerDuty incident triggering"},
]
SECRET_FIELDS = {"hec_token", "shared_key", "password", "routing_key"}
URL_FIELDS = {"splunk": "hec_url", "servicenow": "instance_url"}
REQUIRED = {"splunk": ("hec_url", "hec_token"), "sentinel": ("workspace_id", "shared_key"),
            "servicenow": ("instance_url", "username", "password"), "pagerduty": ("routing_key",)}


async def validate_outbound_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        port = parts.port or 443
    except ValueError as exc:
        raise ValueError("Invalid URL") from exc
    if parts.scheme.lower() != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("URL must be a plain HTTPS URL")
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, parts.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Hostname could not be resolved") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ValueError("Hostname must resolve only to public addresses")
    return url


def mask(config: dict) -> dict:
    return {k: ("********" if k in SECRET_FIELDS and v else v) for k, v in config.items()}


def merge_masked(old: dict, new: dict) -> dict:
    """A PATCH that echoes back '********' keeps the stored secret."""
    return {k: (old.get(k) if v == "********" else v) for k, v in new.items()}


def missing_fields(kind: str, config: dict) -> list[str]:
    return [f for f in REQUIRED[kind] if not config.get(f)]


async def _request(method: str, url: str, **kw) -> httpx.Response:
    url = await validate_outbound_url(url)
    async with httpx.AsyncClient(timeout=10, verify=True, follow_redirects=False) as http:
        return await http.request(method, url, **kw)


def sentinel_signature(workspace_id: str, shared_key: str, date: str, length: int) -> str:
    to_sign = f"POST\n{length}\napplication/json\nx-ms-date:{date}\n/api/logs".encode()
    digest = hmac.new(base64.b64decode(shared_key), to_sign, hashlib.sha256).digest()
    return f"SharedKey {workspace_id}:{base64.b64encode(digest).decode()}"


async def send_alert(kind: str, cfg: dict, alert: dict) -> dict:
    if missing_fields(kind, cfg):
        return {"success": False, "error": f"{kind} is not fully configured"}
    try:
        if kind == "splunk":
            r = await _request("POST", cfg["hec_url"].rstrip("/") + "/services/collector/event",
                               headers={"Authorization": f"Splunk {cfg['hec_token']}"},
                               json={"event": alert, "sourcetype": cfg.get("source_type", "soc:alert"),
                                     "index": cfg.get("index", "main"), "source": "soc-platform"})
            return {"success": r.status_code == 200, "status_code": r.status_code}
        if kind == "servicenow":
            sev = alert.get("severity")
            r = await _request("POST", cfg["instance_url"].rstrip("/") + "/api/now/table/incident",
                               auth=(cfg["username"], cfg["password"]), headers={"Accept": "application/json"},
                               json={"short_description": f"[SOC] {alert.get('title', 'Security alert')}",
                                     "description": alert.get("description", ""), "category": "Security",
                                     "urgency": "1" if sev == "critical" else "2",
                                     "impact": "1" if sev in ("critical", "high") else "2"})
            return {"success": r.status_code == 201, "status_code": r.status_code}
        if kind == "pagerduty":
            sev = {"critical": "critical", "high": "error", "medium": "warning"}.get(alert.get("severity"), "info")
            r = await _request("POST", "https://events.pagerduty.com/v2/enqueue", json={
                "routing_key": cfg["routing_key"], "event_action": "trigger",
                "payload": {"summary": f"[SOC] {alert.get('title', 'Security alert')}", "severity": sev,
                            "source": "soc-platform", "custom_details": alert}})
            return {"success": r.status_code == 202, "status_code": r.status_code}
        if kind == "sentinel":
            if not re.fullmatch(r"[0-9a-fA-F-]{1,64}", cfg["workspace_id"]):
                return {"success": False, "error": "Invalid workspace ID"}
            body = json.dumps([alert])
            date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            r = await _request("POST", f"https://{cfg['workspace_id']}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
                               content=body, headers={"Content-Type": "application/json", "x-ms-date": date,
                                                      "Log-Type": cfg.get("log_type", "SOC_Alert"),
                                                      "Authorization": sentinel_signature(cfg["workspace_id"], cfg["shared_key"], date, len(body))})
            return {"success": r.status_code in (200, 202), "status_code": r.status_code}
    except Exception:
        log.exception("%s delivery failed", kind)
    return FAILED


async def test_connection(kind: str, cfg: dict) -> dict:
    if missing_fields(kind, cfg):
        return {"success": False, "error": f"{kind} is not fully configured"}
    try:
        if kind == "splunk":
            r = await _request("GET", cfg["hec_url"].rstrip("/") + "/services/collector/health",
                               headers={"Authorization": f"Splunk {cfg['hec_token']}"})
            return {"success": r.status_code == 200}
        if kind == "servicenow":
            r = await _request("GET", cfg["instance_url"].rstrip("/") + "/api/now/table/sys_user?sysparm_limit=1",
                               auth=(cfg["username"], cfg["password"]), headers={"Accept": "application/json"})
            return {"success": r.status_code == 200}
    except Exception:
        log.exception("%s test failed", kind)
        return FAILED
    return {"success": True, "message": "Credentials configured (no side-effect-free test available)"}
