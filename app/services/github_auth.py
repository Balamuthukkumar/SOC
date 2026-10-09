import secrets
import time

import httpx

from app.config import settings

STATE_TTL = 600
_states: dict[str, float] = {}  # single-process CSRF store; use Redis/DB if you run several workers


def new_state() -> str:
    now = time.time()
    for k in [k for k, exp in _states.items() if exp <= now]:
        _states.pop(k, None)
    state = secrets.token_urlsafe(32)
    _states[state] = now + STATE_TTL
    return state


def consume_state(state: str | None) -> bool:
    exp = _states.pop(state or "", 0)
    return exp > time.time()


def authorize_url(state: str) -> str:
    return ("https://github.com/login/oauth/authorize?client_id=" + (settings.github_client_id or "")
            + "&scope=user:email&state=" + state + "&redirect_uri=" + settings.github_redirect_uri)


async def exchange_code(code: str) -> dict:
    """Returns {'id','login','name','email','avatar_url'} for the authenticated GitHub user."""
    async with httpx.AsyncClient(timeout=15) as http:
        tok = (await http.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"},
                               data={"client_id": settings.github_client_id, "client_secret": settings.github_client_secret,
                                     "code": code, "redirect_uri": settings.github_redirect_uri})).json()
        token = tok.get("access_token")
        if not token:
            raise ValueError("GitHub did not return an access token")
        h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        user = (await http.get("https://api.github.com/user", headers=h)).json()
        email = user.get("email")
        if not email:
            emails = (await http.get("https://api.github.com/user/emails", headers=h)).json()
            email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
    if not email:
        raise ValueError("No verified primary email on the GitHub account")
    return {"id": str(user["id"]), "login": user["login"], "name": user.get("name"), "email": email,
            "avatar_url": user.get("avatar_url")}
