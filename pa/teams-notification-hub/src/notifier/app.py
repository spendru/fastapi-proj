"""Teams notification hub.

handler      - SQS consumer. Normalizes events from the notifications bus, applies
               incident state (dedupe / ack / snooze / resolve) and calls the
               Power Automate flow that posts to Teams.
ack_handler  - API Gateway callback the flow calls when someone clicks a card button.
"""
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import cards
import normalize

log = logging.getLogger()
log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

EVENTS_TABLE = os.environ.get("EVENTS_TABLE", "")
INCIDENTS_TABLE = os.environ.get("INCIDENTS_TABLE", "")
FLOW_SECRET_ARN = os.environ.get("FLOW_SECRET_ARN", "")
DEDUPE_MINUTES = int(os.environ.get("DEDUPE_MINUTES", "15"))
ACK_SUPPRESS_HOURS = int(os.environ.get("ACK_SUPPRESS_HOURS", "24"))
SNOOZE_MINUTES = int(os.environ.get("SNOOZE_MINUTES", "60"))
EVENT_RETENTION_DAYS = int(os.environ.get("EVENT_RETENTION_DAYS", "90"))
METRIC_NAMESPACE = os.environ.get("METRIC_NAMESPACE", "TeamsNotify")

ALERT_SEVERITIES = {"WARNING", "ERROR", "CRITICAL"}

_clients = {}
_secret = None
_token = {"value": None, "expires": 0}


def _client(name):
    # Lazy so the pure modules can be unit tested without boto3.
    if name not in _clients:
        import boto3
        _clients[name] = boto3.client(name)
    return _clients[name]


class DeliveryError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Metrics (CloudWatch Embedded Metric Format, no API calls needed)
# --------------------------------------------------------------------------- #
def metric(name, value=1, **dims):
    dims = {k: str(v) for k, v in dims.items()}
    print(json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [list(dims.keys())] if dims else [[]],
                "Metrics": [{"Name": name, "Unit": "Count"}],
            }],
        },
        name: value,
        **dims,
    }))


# --------------------------------------------------------------------------- #
# Power Automate client
# --------------------------------------------------------------------------- #
def _flow_config():
    global _secret
    if _secret is None:
        raw = _client("secretsmanager").get_secret_value(SecretId=FLOW_SECRET_ARN)["SecretString"]
        _secret = json.loads(raw)
    return _secret


def _access_token(cfg):
    if _token["value"] and _token["expires"] > time.time() + 60:
        return _token["value"]
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": cfg["clientId"],
        "client_secret": cfg["clientSecret"],
        "scope": cfg.get("scope", "https://service.flow.microsoft.com//.default"),
    }).encode()
    url = f"https://login.microsoftonline.com/{cfg['tenantId']}/oauth2/v2.0/token"
    with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=10) as resp:
        data = json.loads(resp.read())
    _token["value"] = data["access_token"]
    _token["expires"] = time.time() + int(data.get("expires_in", 3600))
    return _token["value"]


def call_flow(payload):
    cfg = _flow_config()
    headers = {"Content-Type": "application/json"}
    if cfg.get("authMode", "oauth") == "oauth":
        headers["Authorization"] = f"Bearer {_access_token(cfg)}"
    req = urllib.request.Request(
        cfg["flowUrl"], data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        detail = e.read()[:500].decode(errors="replace")
        if e.code == 401:
            _token["value"] = None
        raise DeliveryError(f"flow returned {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise DeliveryError(f"flow unreachable: {e.reason}") from e


# --------------------------------------------------------------------------- #
# Event log (idempotency + audit)
# --------------------------------------------------------------------------- #
def claim_event(event_id, n):
    """Returns False if this event was already processed (SQS redelivery)."""
    ddb = _client("dynamodb")
    try:
        ddb.put_item(
            TableName=EVENTS_TABLE,
            Item={
                "eventId": {"S": event_id},
                "status": {"S": "RECEIVED"},
                "receivedAt": {"S": datetime.now(timezone.utc).isoformat()},
                "app": {"S": n["app"]},
                "severity": {"S": n["severity"]},
                "incidentId": {"S": n["incidentId"]},
                "title": {"S": n["title"][:500]},
                "ttl": {"N": str(int(time.time()) + EVENT_RETENTION_DAYS * 86400)},
            },
            ConditionExpression="attribute_not_exists(eventId) OR #s IN (:received, :failed)",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":received": {"S": "RECEIVED"}, ":failed": {"S": "FAILED"}},
        )
        return True
    except ddb.exceptions.ConditionalCheckFailedException:
        return False


def finish_event(event_id, status, outcome):
    _client("dynamodb").update_item(
        TableName=EVENTS_TABLE,
        Key={"eventId": {"S": event_id}},
        UpdateExpression="SET #s = :s, outcome = :o, finishedAt = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": {"S": status}, ":o": {"S": outcome},
            ":t": {"S": datetime.now(timezone.utc).isoformat()},
        },
    )


# --------------------------------------------------------------------------- #
# Incident state
# --------------------------------------------------------------------------- #
def get_incident(incident_id):
    item = _client("dynamodb").get_item(
        TableName=INCIDENTS_TABLE, Key={"incidentId": {"S": incident_id}}, ConsistentRead=True
    ).get("Item")
    if not item:
        return None
    out = {}
    for k, v in item.items():
        out[k] = int(v["N"]) if "N" in v else v.get("S")
    return out


def _cond_update(incident_id, update, condition, names=None, values=None):
    ddb = _client("dynamodb")
    try:
        ddb.update_item(
            TableName=INCIDENTS_TABLE,
            Key={"incidentId": {"S": incident_id}},
            UpdateExpression=update,
            ConditionExpression=condition,
            ExpressionAttributeNames=names or {},
            ExpressionAttributeValues=values or {},
        )
        return True
    except ddb.exceptions.ConditionalCheckFailedException:
        return False


def decide_alert(inc, now):
    """Pure decision for an incoming 'open' alert given current incident state.

    Returns one of: 'new', 'repost', 'suppress'.
    """
    if inc is None or inc.get("state") == "resolved":
        return "new"
    state = inc.get("state")
    if state in ("acknowledged", "snoozed") and now < inc.get("suppressUntil", 0):
        return "suppress"
    if state == "open" and now - inc.get("lastPostedAt", 0) < DEDUPE_MINUTES * 60:
        return "suppress"
    return "repost"


def handle_alert(n, now):
    inc = get_incident(n["incidentId"])
    decision = decide_alert(inc, now)
    iid = n["incidentId"]
    vals = {
        ":open": {"S": "open"}, ":now": {"N": str(now)}, ":one": {"N": "1"},
        ":title": {"S": n["title"][:500]}, ":app": {"S": n["app"]}, ":sev": {"S": n["severity"]},
    }

    if decision == "suppress":
        _cond_update(iid, "ADD occurrences :one, suppressedCount :one SET lastSeenAt = :now",
                     "attribute_exists(incidentId)", values={":one": vals[":one"], ":now": vals[":now"]})
        return "SUPPRESSED", f"suppressed ({inc.get('state')})"

    if decision == "new":
        # Claim creation; a concurrent invocation that loses the race suppresses.
        ok = _cond_update(
            iid,
            "SET #st = :open, firstSeenAt = :now, lastSeenAt = :now, lastPostedAt = :now, "
            "occurrences = :one, suppressedCount = :zero, title = :title, app = :app, severity = :sev "
            "REMOVE suppressUntil, ackBy, resolvedBy",
            "attribute_not_exists(incidentId) OR #st = :resolved",
            names={"#st": "state"},
            values={**vals, ":zero": {"N": "0"}, ":resolved": {"S": "resolved"}},
        )
        if not ok:
            return "SUPPRESSED", "lost create race"
        occurrences, first_seen, prev_posted = 1, now, None
    else:  # repost: still failing after dedupe window or suppression expired
        prev_posted = inc.get("lastPostedAt", 0)
        ok = _cond_update(
            iid,
            "SET #st = :open, lastSeenAt = :now, lastPostedAt = :now, suppressedCount = :zero, "
            "severity = :sev ADD occurrences :one REMOVE suppressUntil",
            "lastPostedAt = :prev",
            names={"#st": "state"},
            values={":open": vals[":open"], ":now": vals[":now"], ":one": vals[":one"],
                    ":zero": {"N": "0"}, ":sev": vals[":sev"], ":prev": {"N": str(prev_posted)}},
        )
        if not ok:
            return "SUPPRESSED", "lost repost race"
        occurrences = inc.get("occurrences", 0) + 1
        first_seen = inc.get("firstSeenAt", now)

    try:
        call_flow({
            "kind": "alert",
            "channel": "alerts",
            "incidentId": iid,
            "summary": cards.summary(n),
            "card": cards.alert_card(n, occurrences=occurrences, first_seen=first_seen,
                                     ack_hours=ACK_SUPPRESS_HOURS, snooze_minutes=SNOOZE_MINUTES),
        })
    except DeliveryError:
        # Roll back the claim so the SQS retry posts instead of being deduped.
        if prev_posted is None:
            _client("dynamodb").delete_item(TableName=INCIDENTS_TABLE, Key={"incidentId": {"S": iid}})
        else:
            _cond_update(iid, "SET lastPostedAt = :prev", "lastPostedAt = :now",
                         values={":prev": {"N": str(prev_posted)}, ":now": vals[":now"]})
        raise
    return "DELIVERED", decision


def handle_resolved(n, now):
    """Returns (status, outcome) or None when there was no open incident."""
    inc = get_incident(n["incidentId"])
    if inc is None or inc.get("state") == "resolved":
        return None
    ok = _cond_update(
        n["incidentId"],
        "SET #st = :resolved, resolvedAt = :now, resolvedBy = :by",
        "#st <> :resolved",
        names={"#st": "state"},
        values={":resolved": {"S": "resolved"}, ":now": {"N": str(now)},
                ":by": {"S": f"auto ({n['sourceType']})"}},
    )
    if not ok:
        return None
    try:
        call_flow({
            "kind": "update",
            "channel": "alerts",
            "incidentId": n["incidentId"],
            "summary": f"RESOLVED: {n['title']}",
            "card": cards.resolved_card(n, inc, now, resolved_by="automatically"),
        })
    except DeliveryError:
        _cond_update(n["incidentId"], "SET #st = :prev", "#st = :resolved",
                     names={"#st": "state"},
                     values={":prev": {"S": inc.get("state", "open")}, ":resolved": {"S": "resolved"}})
        raise
    return "DELIVERED", "resolved"


def handle_update(n):
    call_flow({
        "kind": "update",
        "channel": "updates",
        "incidentId": n["incidentId"],
        "summary": cards.summary(n),
        "card": cards.update_card(n),
    })
    return "DELIVERED", "update"


def route(n):
    """Pure routing decision: 'heartbeat' | 'alert' | 'resolved' | 'update'."""
    if n["sourceType"] == "heartbeat":
        return "heartbeat"
    if n["status"] == "resolved":
        return "resolved"
    if n["severity"] in ALERT_SEVERITIES:
        return "alert"
    return "update"


def process(event):
    n = normalize.normalize(event)
    if n is None:
        log.info("ignored event source=%s detail-type=%s", event.get("source"), event.get("detail-type"))
        return

    kind = route(n)
    if kind == "heartbeat":
        call_flow({"kind": "heartbeat", "channel": "none", "incidentId": "heartbeat"})
        metric("HeartbeatDelivered")
        return

    event_id = event.get("id") or n["incidentId"] + ":" + str(time.time())
    if not claim_event(event_id, n):
        log.info("duplicate delivery of %s, skipping", event_id)
        return

    now = int(time.time())
    try:
        if kind == "alert":
            status, outcome = handle_alert(n, now)
        elif kind == "resolved":
            result = handle_resolved(n, now)
            if n["severity"] == "INFO":
                # e.g. a batch success that also clears an earlier failure
                handle_update(n)
                status, outcome = "DELIVERED", ("resolved+update" if result else "update")
            else:
                status, outcome = result or ("SUPPRESSED", "no open incident")
        else:
            status, outcome = handle_update(n)
    except Exception as e:
        finish_event(event_id, "FAILED", str(e)[:500])
        metric("DeliveryFailed", app=n["app"])
        raise

    finish_event(event_id, status, outcome)
    metric("Delivered" if status == "DELIVERED" else "Suppressed", app=n["app"])
    log.info("%s %s %s -> %s (%s)", n["app"], n["severity"], n["incidentId"], status, outcome)


def handler(event, context):
    failures = []
    for record in event.get("Records", []):
        try:
            process(json.loads(record["body"]))
        except Exception:
            log.exception("failed to process message %s", record.get("messageId"))
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}


# --------------------------------------------------------------------------- #
# Card button callback (called by the Power Automate flow)
# --------------------------------------------------------------------------- #
def _resp(code, body):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}


def ack_handler(event, context):
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _resp(400, {"error": "invalid JSON"})

    iid = body.get("incidentId")
    action = (body.get("action") or "").lower()
    responder = body.get("responder") or {}
    who = responder.get("displayName") or responder.get("email") or "someone"
    if not iid or action not in ("ack", "snooze", "resolve"):
        return _resp(400, {"error": "incidentId and action (ack|snooze|resolve) are required"})

    now = int(time.time())
    names = {"#st": "state"}
    common = {":now": {"N": str(now)}, ":who": {"S": who}, ":resolved": {"S": "resolved"}}
    cond = "attribute_exists(incidentId) AND #st <> :resolved"

    if action == "ack":
        until = now + ACK_SUPPRESS_HOURS * 3600
        ok = _cond_update(iid, "SET #st = :s, suppressUntil = :u, ackBy = :who, ackAt = :now", cond,
                          names, {**common, ":s": {"S": "acknowledged"}, ":u": {"N": str(until)}})
        msg = (f"✅ **Acknowledged** by {who}. Repeat alerts are suppressed until it resolves "
               f"or for {ACK_SUPPRESS_HOURS}h.")
    elif action == "snooze":
        until = now + SNOOZE_MINUTES * 60
        ok = _cond_update(iid, "SET #st = :s, suppressUntil = :u, snoozedBy = :who, snoozedAt = :now", cond,
                          names, {**common, ":s": {"S": "snoozed"}, ":u": {"N": str(until)}})
        msg = f"💤 **Snoozed** by {who} for {SNOOZE_MINUTES} minutes."
    else:
        ok = _cond_update(iid, "SET #st = :resolved, resolvedAt = :now, resolvedBy = :who", cond,
                          names, common)
        msg = f"🟢 **Resolved** by {who}. The next failure will open a new alert."

    inc = get_incident(iid) or {}
    title = inc.get("title", iid)
    if not ok:
        state = inc.get("state", "unknown")
        return _resp(200, {"result": "noop", "state": state,
                           "message": f"ℹ️ {title}: already {state}, no change made (clicked by {who})."})
    log.info("incident %s %s by %s", iid, action, who)
    metric("CardAction", action=action)
    return _resp(200, {"result": action, "message": f"**{title}** — {msg}"})
