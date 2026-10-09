"""Match advisories to assets. Pure functions.

An advisory carries `criteria`: [{vendor, product, version?, start_incl?, start_excl?, end_incl?, end_excl?}].
We are deliberately conservative (prefer a false positive to a missed vulnerability) in one place only: an asset with
no recorded version is treated as possibly affected.
"""
import re

CORP_WORDS = ("incorporated", "corporation", "company", "automation", "technologies", "inc", "corp", "ltd", "gmbh", "llc", "co")
MIN_CONTAINMENT = 4


def norm(text: str | None, strip_corp: bool = False) -> str:
    t = re.sub(r"[^a-z0-9 ]", " ", (text or "").lower().replace("_", " "))
    if strip_corp:
        t = " ".join(w for w in t.split() if w not in CORP_WORDS)
    return t.replace(" ", "")


def names_match(a: str | None, b: str | None, strip_corp: bool = False) -> bool:
    x, y = norm(a, strip_corp), norm(b, strip_corp)
    if not x or not y:
        return False
    if x == y:
        return True
    short, long_ = sorted((x, y), key=len)
    return len(short) >= MIN_CONTAINMENT and short in long_


def version_tuple(v: str | None) -> tuple[int, ...] | None:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:6]) if nums else None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_in_range(version: str | None, c: dict) -> bool:
    bounds = [c.get(k) for k in ("start_incl", "start_excl", "end_incl", "end_excl")]
    exact = c.get("version")
    exact = None if exact in (None, "", "*", "-") else exact
    if not any(bounds) and not exact:
        return True  # criterion doesn't constrain version
    v = version_tuple(version)
    if v is None:
        return True  # unknown asset version: cannot rule out
    if exact:
        e = version_tuple(exact)
        return e is not None and _cmp(v, e) == 0
    checks = ((c.get("start_incl"), lambda r: r >= 0), (c.get("start_excl"), lambda r: r > 0),
              (c.get("end_incl"), lambda r: r <= 0), (c.get("end_excl"), lambda r: r < 0))
    for bound, ok in checks:
        if bound:
            t = version_tuple(bound)
            if t is not None and not ok(_cmp(v, t)):
                return False
    return True


def parse_cpe23(cpe: str) -> dict | None:
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    return {"vendor": parts[3], "product": parts[4], "version": parts[5]}


def asset_matches(asset, advisory: dict) -> bool:
    own = parse_cpe23(asset.cpe_string) if getattr(asset, "cpe_string", None) else None
    for c in advisory.get("criteria", []):
        if own and norm(own["vendor"]) == norm(c.get("vendor")) and norm(own["product"]) == norm(c.get("product")):
            if version_in_range(own["version"] if own["version"] not in ("*", "-") else asset.version, c):
                return True
            continue
        if not (asset.vendor and asset.product):
            continue
        if names_match(asset.vendor, c.get("vendor"), strip_corp=True) and names_match(asset.product, c.get("product")):
            if version_in_range(asset.version, c):
                return True
    return False


def severity_from_cvss(score: float | None, default: str = "medium") -> str:
    if score is None:
        return default
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
