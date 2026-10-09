"""Parse CycloneDX / SPDX JSON and cross-reference components with known vulnerabilities."""
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _norm(v):
    return v or None


def parse_cyclonedx(doc: dict) -> list[dict]:
    out = []
    for c in doc.get("components", []):
        sup = c.get("supplier")
        lic = (c.get("licenses") or [{}])[0].get("license", {}) if c.get("licenses") else {}
        out.append({
            "ref": c.get("bom-ref"), "name": c.get("name", ""), "version": _norm(c.get("version")),
            "supplier": sup.get("name") if isinstance(sup, dict) else sup, "purl": _norm(c.get("purl")),
            "cpe": next((r.get("url") for r in c.get("externalReferences", []) if r.get("type") == "cpe"), None) or _norm(c.get("cpe")),
            "license": lic.get("id") or lic.get("name"),
            "hash_sha256": next((h.get("content") for h in c.get("hashes", []) if h.get("alg") == "SHA-256"), None),
            "vulnerabilities": []})
    by_ref = {c["ref"]: c for c in out if c["ref"]}
    for v in doc.get("vulnerabilities", []):  # CycloneDX VEX section
        for aff in v.get("affects", []):
            comp = by_ref.get(aff.get("ref"))
            if comp and v.get("id"):
                comp["vulnerabilities"].append(v["id"])
    return out


def parse_spdx(doc: dict) -> list[dict]:
    out = []
    for p in doc.get("packages", []):
        refs = {r.get("referenceType"): r.get("referenceLocator") for r in p.get("externalRefs", [])}
        sup, lic = p.get("supplier"), p.get("licenseConcluded") or p.get("licenseDeclared")
        out.append({
            "name": p.get("name", ""), "version": _norm(p.get("versionInfo")),
            "supplier": None if sup in (None, "NOASSERTION") else sup, "purl": refs.get("purl"),
            "cpe": refs.get("cpe23Type") or refs.get("cpe22Type"),
            "license": None if lic in (None, "NOASSERTION") else lic,
            "hash_sha256": next((c.get("checksumValue") for c in p.get("checksums", []) if c.get("algorithm") == "SHA256"), None),
            "vulnerabilities": []})
    return out


def parse(doc: dict) -> tuple[str, str | None, list[dict]]:
    if "bomFormat" in doc:
        return "CycloneDX", doc.get("specVersion"), parse_cyclonedx(doc)
    if "spdxVersion" in doc:
        return "SPDX", doc.get("spdxVersion"), parse_spdx(doc)
    raise ValueError("Unsupported SBOM: expected 'bomFormat' (CycloneDX) or 'spdxVersion' (SPDX)")


async def cross_reference(db: AsyncSession, user_id: int, components: list[dict]) -> None:
    """Add CVEs from the user's own alerts when an alert's title/product names the component (whole word)."""
    alerts = (await db.execute(select(Alert).where(Alert.user_id == user_id, Alert.cve_id.isnot(None)))).scalars().all()
    for comp in components:
        name = (comp["name"] or "").strip()
        if len(name) < 3:
            continue
        pattern = re.compile(rf"(?<![\w-]){re.escape(name)}(?![\w-])", re.I)
        for a in alerts:
            if pattern.search(a.title or "") and a.cve_id not in comp["vulnerabilities"]:
                comp["vulnerabilities"].append(a.cve_id)
