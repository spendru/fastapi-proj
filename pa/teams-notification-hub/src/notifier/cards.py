"""Adaptive Card builders (schema 1.4, posted by the Teams Flow bot)."""
from datetime import datetime, timezone

SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
MAX_MESSAGE = 1500

_STYLE = {
    "CRITICAL": ("🔴", "Attention"),
    "ERROR": ("🟠", "Attention"),
    "WARNING": ("🟡", "Warning"),
    "INFO": ("🔵", "Accent"),
}


def _ts(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _duration(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m = rem // 60
    return f"{h}h {m}m" if h else f"{m}m"


def _trim(text, limit=MAX_MESSAGE):
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def summary(n):
    return f"{n['severity']}: {n['app']} — {n['title']}"[:200]


def _facts(n, extra=None):
    facts = [("App", n["app"]), ("Environment", n["env"])]
    if n.get("account"):
        facts.append(("Account / Region", f"{n['account']} / {n['region']}"))
    facts += list((extra or {}).items())
    facts += list(n.get("attributes", {}).items())
    return {"type": "FactSet",
            "facts": [{"title": k, "value": _trim(str(v), 300)} for k, v in facts if v not in (None, "")]}


def _header(icon, color, label, title):
    return [
        {"type": "TextBlock", "text": f"{icon} {label}", "weight": "Bolder", "color": color,
         "size": "Small", "spacing": "None"},
        {"type": "TextBlock", "text": _trim(title, 200), "weight": "Bolder", "size": "Large", "wrap": True},
    ]


def _links(n):
    return [{"type": "Action.OpenUrl", "title": name, "url": url} for name, url in n.get("links", {}).items()]


def _card(body, actions):
    return {"type": "AdaptiveCard", "$schema": SCHEMA, "version": "1.4", "msteams": {"width": "Full"},
            "body": body, "actions": actions}


def alert_card(n, occurrences, first_seen, ack_hours, snooze_minutes):
    icon, color = _STYLE[n["severity"]]
    extra = {"First seen": _ts(first_seen), "Occurrences": str(occurrences), "Incident": n["incidentId"]}
    body = _header(icon, color, f"{n['severity']} · {n['app']} · {n['env']}", n["title"])
    if occurrences > 1:
        body.append({"type": "TextBlock", "text": f"⚠️ Still failing — {occurrences} occurrences since "
                     f"{_ts(first_seen)}", "color": "Warning", "wrap": True})
    if n.get("message"):
        body.append({"type": "TextBlock", "text": _trim(n["message"]), "wrap": True, "fontType": "Monospace"
                     if "\n" in n["message"] else "Default"})
    body.append(_facts(n, extra))
    actions = [
        {"type": "Action.Submit", "id": "ack", "title": "Acknowledge", "style": "positive",
         "data": {"action": "ack"}},
        {"type": "Action.Submit", "id": "snooze", "title": f"Snooze {snooze_minutes}m",
         "data": {"action": "snooze"}},
        {"type": "Action.Submit", "id": "resolve", "title": "Resolve", "data": {"action": "resolve"}},
    ] + _links(n)
    body.append({"type": "TextBlock", "isSubtle": True, "size": "Small", "wrap": True,
                 "text": f"Acknowledge stops repeat alerts until this resolves (max {ack_hours}h)."})
    return _card(body, actions)


def resolved_card(n, inc, now, resolved_by):
    first = inc.get("firstSeenAt", now)
    extra = {
        "Incident": n["incidentId"],
        "Duration": _duration(now - first),
        "Occurrences": str(inc.get("occurrences", 1)),
        "Acknowledged by": inc.get("ackBy", ""),
        "Resolved": resolved_by,
    }
    body = _header("🟢", "Good", f"RESOLVED · {n['app']} · {n['env']}", inc.get("title") or n["title"])
    if n.get("message"):
        body.append({"type": "TextBlock", "text": _trim(n["message"], 600), "wrap": True, "isSubtle": True})
    body.append(_facts(n, extra))
    return _card(body, _links(n))


def update_card(n):
    icon = "✅" if n["category"] in ("job-complete", "batch-complete") else "ℹ️"
    body = _header(icon, "Accent", f"{n['category'].upper()} · {n['app']} · {n['env']}", n["title"])
    if n.get("message"):
        body.append({"type": "TextBlock", "text": _trim(n["message"]), "wrap": True})
    body.append(_facts(n))
    return _card(body, _links(n))
