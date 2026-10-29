"""Run: pip install boto3 'moto[dynamodb]' pytest && pytest tests/"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "notifier"))
os.environ.update(AWS_DEFAULT_REGION="us-east-1", AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="x",
                  EVENTS_TABLE="events", INCIDENTS_TABLE="incidents")

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

import app  # noqa: E402
import cards  # noqa: E402
import normalize  # noqa: E402


def app_event(severity="ERROR", status="open", incident="orders-api:recon", eid="e1", **detail):
    return {"id": eid, "source": "app.orders-api", "detail-type": "AppNotification",
            "account": "111111111111", "region": "us-east-1",
            "detail": {"app": "orders-api", "severity": severity, "title": "Recon failed",
                       "message": "boom", "incidentId": incident, "status": status, **detail}}


@pytest.fixture
def hub(monkeypatch):
    with mock_aws():
        ddb = boto3.client("dynamodb")
        ddb.create_table(TableName="events", BillingMode="PAY_PER_REQUEST",
                         AttributeDefinitions=[{"AttributeName": "eventId", "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": "eventId", "KeyType": "HASH"}])
        ddb.create_table(TableName="incidents", BillingMode="PAY_PER_REQUEST",
                         AttributeDefinitions=[{"AttributeName": "incidentId", "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": "incidentId", "KeyType": "HASH"}])
        app._clients.clear()
        calls = []
        clock = {"now": 1_800_000_000}
        monkeypatch.setattr(app, "call_flow", lambda p: calls.append(p) or 200)
        monkeypatch.setattr(app.time, "time", lambda: clock["now"])
        yield calls, clock


def run(*events):
    records = [{"messageId": str(i), "body": json.dumps(e)} for i, e in enumerate(events)]
    return app.handler({"Records": records}, None)


def ack(action, incident="orders-api:recon"):
    r = app.ack_handler({"body": json.dumps({"incidentId": incident, "action": action,
                                             "responder": {"displayName": "Jane Doe"}})}, None)
    return json.loads(r["body"])


# ---------------------------------------------------------------- normalize / route
def test_alarm_normalization():
    ev = {"source": "aws.cloudwatch", "detail-type": "CloudWatch Alarm State Change",
          "account": "1", "region": "eu-west-1",
          "detail": {"alarmName": "notify-orders-5xx", "state": {"value": "ALARM", "reason": "x > 5"},
                     "previousState": {"value": "OK"},
                     "configuration": {"description": "app=orders-api severity=critical 5xx high"}}}
    n = normalize.normalize(ev)
    assert (n["app"], n["severity"], n["status"]) == ("orders-api", "CRITICAL", "open")
    assert n["message"].startswith("5xx high")
    ev["detail"]["state"]["value"], ev["detail"]["previousState"]["value"] = "OK", "ALARM"
    assert normalize.normalize(ev)["status"] == "resolved"
    ev["detail"]["state"]["value"] = "INSUFFICIENT_DATA"
    assert normalize.normalize(ev) is None


def test_ecs_and_lambda_normalization():
    ecs = normalize.normalize({
        "source": "aws.ecs", "detail-type": "ECS Task State Change", "account": "1", "region": "us-east-1",
        "detail": {"clusterArn": "arn:aws:ecs:us-east-1:1:cluster/prod", "group": "service:orders-api",
                   "taskArn": "arn:aws:ecs:us-east-1:1:task/prod/abc", "stopCode": "EssentialContainerExited",
                   "stoppedReason": "Essential container in task exited",
                   "containers": [{"name": "web", "exitCode": 1}]}})
    assert ecs["app"] == "orders-api" and ecs["severity"] == "ERROR"
    assert ecs["attributes"]["Exit codes"] == "web=1"

    lam = normalize.normalize({
        "source": "lambda", "detail-type": "Lambda Function Invocation Result - Failure",
        "detail": {"requestContext": {"functionArn": "arn:aws:lambda:us-east-1:1:function:ingest:$LATEST",
                                      "condition": "RetriesExhausted", "approximateInvokeCount": 3},
                   "responsePayload": {"errorType": "KeyError", "errorMessage": "'id'"}}})
    assert lam["app"] == "ingest"
    assert lam["incidentId"] == "lambda:arn:aws:lambda:us-east-1:1:function:ingest"
    assert lam["message"] == "KeyError: 'id'"


def test_route():
    assert app.route(normalize.normalize(app_event("INFO"))) == "update"
    assert app.route(normalize.normalize(app_event("WARNING"))) == "alert"
    assert app.route(normalize.normalize(app_event("INFO", status="resolved"))) == "resolved"
    assert normalize.normalize({"source": "app.x", "detail-type": "Other"}) is None


def test_cards_are_valid_json_and_have_buttons():
    n = normalize.normalize(app_event("CRITICAL", links={"Logs": "https://x", "bad": "http://y"}))
    card = cards.alert_card(n, occurrences=3, first_seen=1_800_000_000, ack_hours=24, snooze_minutes=60)
    json.dumps(card)
    ids = [a.get("id") for a in card["actions"] if a["type"] == "Action.Submit"]
    assert ids == ["ack", "snooze", "resolve"]
    assert [a["title"] for a in card["actions"] if a["type"] == "Action.OpenUrl"] == ["Logs"]
    assert not any(a["type"] == "Action.Submit" for a in cards.update_card(n)["actions"])


# ---------------------------------------------------------------- end-to-end with DynamoDB
def test_dedupe_then_repost_after_window(hub):
    calls, clock = hub
    run(app_event(eid="e1"))
    run(app_event(eid="e2"))              # inside 15 min -> suppressed
    assert len(calls) == 1 and calls[0]["kind"] == "alert"
    clock["now"] += 16 * 60
    run(app_event(eid="e3"))              # after window -> still failing card
    assert len(calls) == 2
    assert "Still failing — 3 occurrences" in json.dumps(calls[1]["card"], ensure_ascii=False)


def test_redelivery_is_idempotent(hub):
    calls, _ = hub
    run(app_event(eid="same"))
    run(app_event(eid="same"))
    assert len(calls) == 1


def test_ack_suppresses_until_resolved_then_new_incident(hub):
    calls, clock = hub
    run(app_event(eid="e1"))
    assert ack("ack")["result"] == "ack"
    clock["now"] += 3 * 3600
    run(app_event(eid="e2"))              # acked -> suppressed even after dedupe window
    assert len(calls) == 1
    run(app_event("INFO", status="resolved", eid="e3", category="job-complete"))
    kinds = [(c["kind"], c["channel"]) for c in calls[1:]]
    assert kinds == [("update", "alerts"), ("update", "updates")]   # RESOLVED card + completion update
    assert "Jane Doe" in json.dumps(calls[1]["card"])
    run(app_event(eid="e4"))              # fresh failure -> fresh alert
    assert calls[-1]["kind"] == "alert"
    assert ack("resolve")["result"] == "resolve"
    assert ack("ack")["result"] == "noop"


def test_ack_expires(hub):
    calls, clock = hub
    run(app_event(eid="e1"))
    ack("ack")
    clock["now"] += 25 * 3600
    run(app_event(eid="e2"))
    assert len(calls) == 2


def test_snooze(hub):
    calls, clock = hub
    run(app_event(eid="e1"))
    ack("snooze")
    clock["now"] += 30 * 60
    run(app_event(eid="e2"))
    assert len(calls) == 1
    clock["now"] += 31 * 60
    run(app_event(eid="e3"))
    assert len(calls) == 2


def test_failed_delivery_is_retried_not_deduped(hub, monkeypatch):
    calls, _ = hub

    def boom(p):
        raise app.DeliveryError("503")
    monkeypatch.setattr(app, "call_flow", boom)
    assert run(app_event(eid="e1")) == {"batchItemFailures": [{"itemIdentifier": "0"}]}
    monkeypatch.setattr(app, "call_flow", lambda p: calls.append(p) or 200)
    run(app_event(eid="e1"))              # SQS redelivery of the same event
    assert len(calls) == 1 and calls[0]["kind"] == "alert"


def test_resolved_without_open_incident_is_dropped(hub):
    calls, _ = hub
    run(app_event("ERROR", status="resolved", eid="e1"))
    assert calls == []


def test_heartbeat(hub, capsys):
    calls, _ = hub
    run({"id": "h1", "source": "notification-hub", "detail-type": "Heartbeat", "detail": {}})
    assert calls == [{"kind": "heartbeat", "channel": "none", "incidentId": "heartbeat"}]
    assert '"HeartbeatDelivered": 1' in capsys.readouterr().out


def test_ack_validation(hub):
    r = app.ack_handler({"body": json.dumps({"incidentId": "x", "action": "delete"})}, None)
    assert r["statusCode"] == 400
    assert ack("ack", incident="does-not-exist")["result"] == "noop"
