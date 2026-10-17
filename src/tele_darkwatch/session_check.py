"""Active-session validation engine (non-intrusive liveness pings).

When a stolen bearer token surfaces, analysts need to know whether it is still
valid *before* paging the SOC. This module issues exactly one read-only status
call per provider — no data access, no state change — and maps the HTTP result
to a severity:

* 2xx → token LIVE → escalate to P1 (kill the session now)
* 401/403 → dead/expired → downgrade to informational
* network error → unknown → keep original severity

Endpoints used are the providers' own "who am I" calls (e.g. AWS STS
GetCallerIdentity, GitHub ``/user``, Slack ``auth.test``). A pluggable
transport keeps this fully testable offline.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

#: provider → (method, url, header builder, success predicate on status)
PROVIDERS = {
    "github": {
        "method": "GET",
        "url": "https://api.github.com/user",
        "header": lambda token: {"Authorization": f"token {token}"},
    },
    "slack": {
        "method": "POST",
        "url": "https://slack.com/api/auth.test",
        "header": lambda token: {"Authorization": f"Bearer {token}"},
    },
    "gitlab": {
        "method": "GET",
        "url": "https://gitlab.com/api/v4/user",
        "header": lambda token: {"PRIVATE-TOKEN": token},
    },
}


@dataclass
class ValidationResult:
    provider: str
    token_prefix: str          # never log full secrets
    status: str                # "live" | "dead" | "unknown" | "unsupported"
    http_status: Optional[int] = None
    severity: int = 3          # 1 = page now, 5 = ignore

    @property
    def is_live(self) -> bool:
        return self.status == "live"


def detect_provider(token: str) -> Optional[str]:
    if token.startswith("ghp_") or token.startswith("github_pat_"):
        return "github"
    if token.startswith("xox"):
        return "slack"
    if token.startswith("glpat-"):
        return "gitlab"
    return None


def validate_token(token: str,
                   client: Optional[httpx.Client] = None) -> ValidationResult:
    """Issue one headless read-only ping; classify liveness & severity."""
    provider = detect_provider(token)
    prefix = token[:8] + "…"
    if provider is None or provider not in PROVIDERS:
        return ValidationResult("unknown", prefix, "unsupported",
                                None, severity=3)
    spec = PROVIDERS[provider]
    own = client is None
    client = client or httpx.Client(timeout=10)
    try:
        resp = client.request(spec["method"], spec["url"],
                              headers=spec["header"](token))
        if 200 <= resp.status_code < 300:
            return ValidationResult(provider, prefix, "live",
                                    resp.status_code, severity=1)
        if resp.status_code in (401, 403):
            return ValidationResult(provider, prefix, "dead",
                                    resp.status_code, severity=5)
        return ValidationResult(provider, prefix, "unknown",
                                resp.status_code, severity=3)
    except httpx.HTTPError:
        return ValidationResult(provider, prefix, "unknown", None, severity=3)
    finally:
        if own:
            client.close()


def validate_from_text(text: str,
                       client: Optional[httpx.Client] = None) -> list[ValidationResult]:
    """Find candidate tokens in arbitrary text and validate each once."""
    from tele_darkwatch.entities import extract_api_keys
    results = []
    for ent in extract_api_keys(text):
        if ent.attributes.get("key_type") != "github_token":
            # Only providers with a safe whoami endpoint are checked live.
            if ent.attributes.get("key_type") != "slack_token":
                continue
        results.append(validate_token(ent.value, client=client))
    return results
