"""Tiny client apps use to publish to the Teams notification hub.

Inside AWS (Lambda / ECS / EC2) it calls EventBridge PutEvents. The caller's role
needs events:PutEvents on the hub bus ARN.
Outside AWS, set TEAMS_NOTIFY_URL and TEAMS_NOTIFY_API_KEY and it POSTs to the ingest API.

    from teams_notify import Notifier
    notify = Notifier(app="orders-api")
    notify.error("Reconciliation failed", "3 of 120 batches timed out",
                 incident_id="orders-api:recon", links={"Logs": "https://..."})
    notify.info("Reconciliation complete", "120 batches", category="job-complete",
                incident_id="orders-api:recon", resolves=True)

Never raises: a broken notification path must not break the application.
"""
import json
import logging
import os
import urllib.request

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, app, env=None, bus=None, url=None, api_key=None):
        self.app = app
        self.env = env or os.environ.get("TEAMS_NOTIFY_ENV", "prod")
        self.bus = bus or os.environ.get("TEAMS_NOTIFY_BUS", "teams-notify-bus")
        self.url = url or os.environ.get("TEAMS_NOTIFY_URL")
        self.api_key = api_key or os.environ.get("TEAMS_NOTIFY_API_KEY")
        self._events = None

    def send(self, severity, title, message="", category=None, incident_id=None,
             resolves=False, links=None, attributes=None):
        detail = {
            "schemaVersion": "1.0",
            "app": self.app,
            "env": self.env,
            "severity": severity,
            "category": category or ("update" if severity == "INFO" else "failure"),
            "title": title,
            "message": message,
            "status": "resolved" if resolves else "open",
            "links": links or {},
            "attributes": {k: str(v) for k, v in (attributes or {}).items()},
        }
        if incident_id:
            detail["incidentId"] = incident_id
        try:
            if self.url:
                self._post(detail)
            else:
                self._put_event(detail)
            return True
        except Exception:
            log.exception("teams notification failed: %s", title)
            return False

    def info(self, title, message="", **kw):
        return self.send("INFO", title, message, **kw)

    def warning(self, title, message="", **kw):
        return self.send("WARNING", title, message, **kw)

    def error(self, title, message="", **kw):
        return self.send("ERROR", title, message, **kw)

    def critical(self, title, message="", **kw):
        return self.send("CRITICAL", title, message, **kw)

    def _put_event(self, detail):
        if self._events is None:
            import boto3
            self._events = boto3.client("events")
        resp = self._events.put_events(Entries=[{
            "EventBusName": self.bus,
            "Source": f"app.{self.app}",
            "DetailType": "AppNotification",
            "Detail": json.dumps(detail),
        }])
        if resp.get("FailedEntryCount"):
            raise RuntimeError(resp["Entries"][0].get("ErrorMessage"))

    def _post(self, detail):
        req = urllib.request.Request(
            self.url, data=json.dumps(detail).encode(), method="POST",
            headers={"Content-Type": "application/json", "x-api-key": self.api_key or ""})
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
