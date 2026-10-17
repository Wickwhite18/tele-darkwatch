"""SOAR playbook engine — turn alerts into automated response actions.

When the pipeline flags a match, this engine executes *defensive* playbooks:
  * enrich the alert with entity-graph risk scoring
  * escalate severity when a corporate-domain credential is live (P0/P1)
  * post structured incident payloads to a SOC webhook / Slack / Teams
  * open a local "incident ticket" record for audit

Everything here is outbound-defence only (SIEM/SOAR webhooks, read-only
validation pings). The engine never interacts with the leaked accounts
themselves beyond the passive checks in :mod:`tele_darkwatch.session_check`.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Callable, Optional

import httpx

from tele_darkwatch.models import Alert

log = logging.getLogger("tele_darkwatch.soar")


def _alert_severity(alert: Alert) -> int:
    """1..5 severity recorded by the alert engines (default 2)."""
    try:
        return int(alert.metadata.get("severity", 2))
    except (TypeError, ValueError):
        return 2


def _match_hint(alert: Alert) -> str:
    """Best-effort matched value for contextual validation.

    Keyword-engine alerts stash the needle under several possible keys; IOC
    regex alerts store extracted groups. Falls back to the message snippet.
    """
    md = alert.metadata or {}
    for key in ("needle", "match", "matched", "value", "extracted", "match_value"):
        v = md.get(key)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            for vv in v.values():
                if isinstance(vv, str) and vv:
                    return vv
    return alert.message_content or ""


def _domain_of(value: str) -> str:
    """Extract a bare domain from an email address, URL, or raw string."""
    v = (value or "").strip().lower()
    if "@" in v:
        return v.rsplit("@", 1)[-1]
    if "://" in v:
        rest = v.split("://", 1)[1]
        return rest.split("/", 1)[0].split(":", 1)[0]
    return v


# Domains whose compromise warrants immediate escalation.
_ENTERPRISE_RE = re.compile(
    r"(microsoftonline\.com|login\.microsoftonline|okta\.com|awsapps\.com|"
    r"sso\.[a-z0-9.-]+|slack\.com|github\.com|gitlab\.com)$", re.I)


def is_enterprise_domain(domain: str) -> bool:
    return bool(_ENTERPRISE_RE.search(domain.strip().lower()))


def _is_enterprise_match(match_hint: str) -> bool:
    """True if the match itself is an enterprise SSO domain, or the hint
    contains an email/URL whose domain is an enterprise SSO domain."""
    if is_enterprise_domain(match_hint):
        return True
    domain = _domain_of(match_hint)
    return domain != match_hint and is_enterprise_domain(domain)


class Ticket:
    """A minimal incident-ticket record persisted via store meta."""

    def __init__(self, tid: str, title: str, severity: str, alert_id: Optional[int],
                 detail: dict, opened: str) -> None:
        self.id = tid
        self.title = title
        self.severity = severity
        self.alert_id = alert_id
        self.detail = detail
        self.opened = opened

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "severity": self.severity,
                "alert_id": self.alert_id, "detail": self.detail,
                "opened": self.opened}


class SOAREngine:
    """Executes playbooks over alerts; pluggable transport for tests."""

    def __init__(self, store, webhook_url: str = "",
                 client: Optional[httpx.Client] = None,
                 enrich: bool = True) -> None:
        self.store = store
        self.webhook_url = webhook_url
        self._client = client or httpx.Client(timeout=10.0)
        self.enrich = enrich

    # ------------------------------------------------------------------ steps
    def _graph_risk(self, alert: Alert) -> dict:
        try:
            from tele_darkwatch.graph import build_graph
            graph = build_graph(self.store)
            seed = _match_hint(alert) or alert.channel
            best = {"identity": seed, "found": False, "score": 0}
            for cand in {seed, *(re.findall(r"[\w.+-]+@[\w.-]+", seed or ""))}:
                if not cand:
                    continue
                rs = graph.risk_score(cand)
                if rs.get("score", 0) > best.get("score", 0):
                    best = rs
            return best
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("graph enrichment failed: %s", exc)
            return {}

    def decide_severity(self, alert: Alert, risk: dict,
                        session_live: Optional[bool] = None) -> str:
        """Dynamic severity scoring.

        Live enterprise session cookie => P0/Sev-1. Graph blast radius bumps
        one level. Otherwise map the engine's 1..5 severity onto the P-scale.
        """
        sev = _alert_severity(alert)
        base = {1: "P1", 2: "P2", 3: "P3", 4: "P4", 5: "P5"}.get(sev, "P3")
        if session_live and _is_enterprise_match(_match_hint(alert)):
            return "P0"
        if session_live:
            return "P1" if base != "P1" else "P1"
        if risk.get("score", 0) >= 25 and base in ("P2", "P3"):
            return {"P2": "P1", "P3": "P2"}[base]
        return base

    def open_ticket(self, alert: Alert, severity: str, risk: dict) -> Ticket:
        now = datetime.now(timezone.utc).isoformat()
        tid = f"DWT-{alert.id or int(datetime.now(timezone.utc).timestamp())}"
        ticket = Ticket(tid, f"{alert.rule} @ {alert.channel}", severity,
                        alert.id, {"risk": risk, "snippet": (alert.message_content or "")[:400]},
                        now)
        key = f"ticket:{tid}"
        existing = self.store.get_meta(key)
        self.store.set_meta(key, json.dumps(ticket.to_dict()))
        if existing is None:
            idx = json.loads(self.store.get_meta("tickets:index") or "[]")
            idx.append(tid)
            self.store.set_meta("tickets:index", json.dumps(idx))
        return ticket

    def list_tickets(self, limit: int = 50) -> list[dict]:
        idx = json.loads(self.store.get_meta("tickets:index") or "[]")
        out = []
        for tid in idx[-limit:]:
            raw = self.store.get_meta(f"ticket:{tid}")
            if raw:
                out.append(json.loads(raw))
        return out

    # ------------------------------------------------------------------ run
    def run_playbook(self, alert: Alert,
                     session_validator: Optional[Callable[[str], Optional[bool]]] = None
                     ) -> dict:
        risk = self._graph_risk(alert) if self.enrich else {}
        live: Optional[bool] = None
        if session_validator:
            try:
                live = session_validator(_match_hint(alert))
            except Exception:  # pragma: no cover
                live = None
        severity = self.decide_severity(alert, risk, live)
        ticket = self.open_ticket(alert, severity, risk)
        payload = {
            "event_type": "darkwatch.incident",
            "ticket": ticket.to_dict(),
            "alert": alert.model_dump(mode="json"),
            "session_live": live,
            "graph_risk": risk,
        }
        delivered = self._post(payload)
        return {"ticket": ticket.id, "severity": severity, "session_live": live,
                "delivered": delivered, "payload": payload}

    def _post(self, payload: dict) -> bool:
        if not self.webhook_url:
            return False
        try:
            resp = self._client.post(self.webhook_url, json=payload)
            return resp.status_code < 300
        except Exception as exc:  # pragma: no cover - network dependent
            log.warning("SOAR webhook delivery failed: %s", exc)
            return False


def process_pending_alerts(store, settings, validator=None) -> list[dict]:
    """Run the playbook over every alert that has not been escalated yet."""
    engine = SOAREngine(store, webhook_url=getattr(settings, "soar_webhook_url", ""))
    results = []
    for alert in store.all_alerts(limit=200):
        marker = f"soar:alert:{alert.id}"
        if alert.id is None or store.get_meta(marker):
            continue
        res = engine.run_playbook(alert, session_validator=validator)
        store.set_meta(marker, res["ticket"])
        results.append({"alert": alert.rule, **{k: res[k] for k in ("severity", "ticket", "delivered")}})
    return results
