"""Vulnerability feeds: NVD (CVE API 2.0) and CISA Known Exploited Vulnerabilities.

Parsers are pure so they can be tested against saved payloads; fetchers do the network I/O.
"""
import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.config import settings
from app.services.matching import parse_cpe23, severity_from_cvss

log = logging.getLogger(__name__)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_NVD_RESULTS = 2000


def _english(descriptions: list[dict]) -> str:
    return next((d["value"] for d in descriptions if d.get("lang") == "en"), "")


def _cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            return metrics[key][0]["cvssData"]["baseScore"]
    return None


def parse_nvd(payload: dict) -> list[dict]:
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item["cve"]
        criteria = []
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    base = parse_cpe23(m.get("criteria", ""))
                    if m.get("vulnerable") and base:
                        criteria.append({**base, "start_incl": m.get("versionStartIncluding"),
                                         "start_excl": m.get("versionStartExcluding"),
                                         "end_incl": m.get("versionEndIncluding"), "end_excl": m.get("versionEndExcluding")})
        score = _cvss(cve.get("metrics", {}))
        desc = _english(cve.get("descriptions", []))
        out.append({"cve_id": cve["id"], "title": f"{cve['id']}: {desc[:120]}".strip(), "description": desc,
                    "severity": severity_from_cvss(score), "cvss_score": score, "criteria": criteria,
                    "source_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}", "known_exploited": False,
                    "remediation": None})
    return out


def parse_kev(payload: dict) -> list[dict]:
    out = []
    for v in payload.get("vulnerabilities", []):
        out.append({"cve_id": v["cveID"], "title": f"{v['cveID']}: {v.get('vulnerabilityName', '')}".strip(),
                    "description": v.get("shortDescription", ""), "severity": "high", "cvss_score": None,
                    "criteria": [{"vendor": v.get("vendorProject", ""), "product": v.get("product", "")}],
                    "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "known_exploited": True,
                    "remediation": v.get("requiredAction")})
    return out


async def fetch_nvd(hours_back: int = 6) -> list[dict]:
    end = datetime.now(timezone.utc)
    params = {"lastModStartDate": (end - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%S.000"),
              "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"), "resultsPerPage": MAX_NVD_RESULTS}
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    async with httpx.AsyncClient(timeout=60) as http:
        r = await http.get(NVD_URL, params=params, headers=headers)
        r.raise_for_status()
        return parse_nvd(r.json())


async def fetch_kev(days_back: int = 3) -> list[dict]:
    """KEV is a full catalogue; keep only entries added recently so each run is incremental."""
    async with httpx.AsyncClient(timeout=60) as http:
        r = await http.get(KEV_URL)
        r.raise_for_status()
        payload = r.json()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days_back)).date().isoformat()
    payload["vulnerabilities"] = [v for v in payload.get("vulnerabilities", []) if v.get("dateAdded", "") >= cutoff]
    return parse_kev(payload)


async def fetch_all(hours_back: int = 6) -> list[dict]:
    advisories: list[dict] = []
    for name, fetch in (("NVD", lambda: fetch_nvd(hours_back)), ("CISA KEV", fetch_kev)):
        try:
            advisories += await fetch()
        except Exception as exc:
            log.warning("%s feed failed: %s", name, exc)
    return advisories
