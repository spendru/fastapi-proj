"""Turns every supported event shape into one normalized notification dict.

Normalized fields:
  sourceType  app | cloudwatch-alarm | ecs-task | lambda-failure | heartbeat
  app, env, severity (INFO|WARNING|ERROR|CRITICAL), category, title, message,
  incidentId, status (open|resolved), links {name: url}, attributes {k: v},
  account, region, time
Returns None for events that should be ignored.
"""
import os
import re
import urllib.parse

DEFAULT_ENV = os.environ.get("DEFAULT_ENV", "prod")
SEVERITIES = ("INFO", "WARNING", "ERROR", "CRITICAL")
_TOKEN = re.compile(r"\b(app|severity|env|runbook)=(\S+)", re.IGNORECASE)


def normalize(event):
    source = event.get("source", "")
    dtype = event.get("detail-type", "")
    if source == "notification-hub" and dtype == "Heartbeat":
        return {"sourceType": "heartbeat"}
    if dtype == "AppNotification" and source.startswith("app."):
        return _app(event)
    if source == "aws.cloudwatch" and dtype == "CloudWatch Alarm State Change":
        return _alarm(event)
    if source == "aws.ecs" and dtype == "ECS Task State Change":
        return _ecs(event)
    if source == "lambda" and dtype == "Lambda Function Invocation Result - Failure":
        return _lambda(event)
    return None


def _base(event, **kw):
    n = {
        "env": DEFAULT_ENV,
        "category": "failure",
        "status": "open",
        "links": {},
        "attributes": {},
        "account": event.get("account", ""),
        "region": event.get("region", ""),
        "time": event.get("time", ""),
    }
    n.update(kw)
    return n


def _sev(value, default):
    value = (value or "").upper()
    return value if value in SEVERITIES else default


def _app(event):
    d = event.get("detail") or {}
    app = d.get("app") or event["source"][len("app."):]
    title = (d.get("title") or "").strip() or "(no title)"
    links = d.get("links") if isinstance(d.get("links"), dict) else {}
    attrs = d.get("attributes") if isinstance(d.get("attributes"), dict) else {}
    return _base(
        event,
        sourceType="app",
        app=app,
        env=d.get("env") or DEFAULT_ENV,
        severity=_sev(d.get("severity"), "INFO"),
        category=d.get("category") or "update",
        title=title,
        message=d.get("message") or "",
        incidentId=d.get("incidentId") or f"{app}:{title}",
        status="resolved" if (d.get("status") or "").lower() == "resolved" else "open",
        links={str(k): str(v) for k, v in links.items() if str(v).startswith("https://")},
        attributes={str(k): str(v) for k, v in attrs.items()},
    )


def _alarm(event):
    d = event.get("detail") or {}
    state = (d.get("state") or {}).get("value")
    prev = (d.get("previousState") or {}).get("value")
    if state == "ALARM":
        status = "open"
    elif state == "OK" and prev == "ALARM":
        status = "resolved"
    else:
        return None  # INSUFFICIENT_DATA transitions are noise

    name = d.get("alarmName", "unknown-alarm")
    desc = ((d.get("configuration") or {}).get("description")) or ""
    tokens = {k.lower(): v for k, v in _TOKEN.findall(desc)}
    region = event.get("region", "")
    links = {"Alarm": (f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}"
                       f"#alarmsV2:alarm/{urllib.parse.quote(name, safe='')}")}
    if tokens.get("runbook", "").startswith("https://"):
        links["Runbook"] = tokens["runbook"]
    clean_desc = _TOKEN.sub("", desc).strip()
    return _base(
        event,
        sourceType="cloudwatch-alarm",
        app=tokens.get("app", name),
        env=tokens.get("env", DEFAULT_ENV),
        severity=_sev(tokens.get("severity"), "ERROR"),
        title=f"Alarm: {name}",
        message=(clean_desc + "\n\n" if clean_desc else "") + ((d.get("state") or {}).get("reason") or ""),
        incidentId=f"cwalarm:{event.get('account', '')}:{region}:{name}",
        status=status,
        links=links,
        attributes={"Alarm state": f"{prev} → {state}"},
    )


def _ecs(event):
    d = event.get("detail") or {}
    cluster = (d.get("clusterArn") or "").split("/")[-1]
    group = d.get("group") or ""
    app = group.split(":", 1)[-1] if group else (d.get("taskDefinitionArn") or "").split("/")[-1].split(":")[0]
    exits = [f"{c.get('name')}={c.get('exitCode')}" for c in d.get("containers", []) if "exitCode" in c]
    reasons = [c.get("reason") for c in d.get("containers", []) if c.get("reason")]
    region = event.get("region", "")
    task_id = (d.get("taskArn") or "").split("/")[-1]
    return _base(
        event,
        sourceType="ecs-task",
        app=app or "unknown-ecs-task",
        severity="ERROR",
        title=f"ECS task failed: {app}",
        message="\n".join(filter(None, [d.get("stoppedReason"), *reasons])),
        incidentId=f"ecs:{event.get('account', '')}:{region}:{cluster}:{group or app}",
        links={"Task": (f"https://{region}.console.aws.amazon.com/ecs/v2/clusters/{cluster}"
                        f"/tasks/{task_id}?region={region}")} if task_id else {},
        attributes={
            "Cluster": cluster,
            "Stop code": d.get("stopCode", ""),
            "Exit codes": ", ".join(exits) or "n/a",
        },
    )


def _lambda(event):
    d = event.get("detail") or {}
    ctx = d.get("requestContext") or {}
    arn = ctx.get("functionArn") or ""
    parts = arn.split(":")
    fn = parts[6] if len(parts) > 6 else arn
    region = parts[3] if len(parts) > 3 else event.get("region", "")
    payload = d.get("responsePayload") or {}
    err = payload.get("errorMessage") if isinstance(payload, dict) else str(payload)
    err_type = payload.get("errorType", "") if isinstance(payload, dict) else ""
    return _base(
        event,
        sourceType="lambda-failure",
        app=fn,
        severity="ERROR",
        title=f"Lambda failed: {fn}",
        message=f"{err_type}: {err}" if err_type else (err or ctx.get("condition", "")),
        incidentId=f"lambda:{':'.join(parts[:7])}",
        links={"Function": (f"https://{region}.console.aws.amazon.com/lambda/home?region={region}"
                            f"#/functions/{fn}?tab=monitoring")},
        attributes={
            "Condition": ctx.get("condition", ""),
            "Attempts": str(ctx.get("approximateInvokeCount", "")),
            "Request ID": ctx.get("requestId", ""),
        },
    )
