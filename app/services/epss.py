import logging

import httpx

log = logging.getLogger(__name__)
EPSS_URL = "https://api.first.org/data/v1/epss"


async def fetch_epss(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """cve -> (epss probability, percentile)"""
    if not cve_ids:
        return {}
    async with httpx.AsyncClient(timeout=15) as http:
        r = await http.get(EPSS_URL, params={"cve": ",".join(cve_ids[:100])})
        r.raise_for_status()
    return {row["cve"]: (float(row["epss"]), float(row["percentile"])) for row in r.json().get("data", [])}
