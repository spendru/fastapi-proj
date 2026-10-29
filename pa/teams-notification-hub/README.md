# Teams Notification Hub

Sends alerts and updates from AWS Lambda, ECS Fargate and external apps to Microsoft Teams
through one Power Automate flow. Alerts are interactive: **Acknowledge**, **Snooze** and **Resolve** buttons.

```
Lambda / ECS code ──PutEvents──────────────┐
CloudWatch alarm (notify-*) ─┐             │
ECS task failed ─────────────┼ default bus ┤   hub bus ──► SQS (+DLQ) ──► notifier λ ──► Power Automate ──► Teams
Lambda async failure ────────┘  (producer  │   (hub.yaml)                  │  DynamoDB      flow             #app-alerts
                                 stack)    │                               │  (events,       │                #app-updates
External app ──► API GW /notify (API key) ─┘                               │   incidents)    │ button click
                                                                           └──◄── API GW /ack ◄─┘
Hourly heartbeat ──► SQS ──► notifier ──► flow (no post) ──► metric; alarm → email if missing
```

## Repository layout

| Path | What |
|---|---|
| `cloudformation/hub.yaml` | Central stack: bus, queue, DynamoDB, notifier and ack Lambdas, ingest API, callback API, health alarms |
| `cloudformation/producer-account.yaml` | One per app account/region: forwards alarm / ECS / Lambda failures to the hub |
| `src/notifier/` | Lambda code (`app.py` handlers, `normalize.py` event shapes, `cards.py` Adaptive Cards) |
| `client/teams_notify.py` | Drop-in Python client for apps (EventBridge inside AWS, REST outside) |
| `docs/power-automate-flow.md` | Step-by-step flow build, Entra app, ALM |
| `scripts/` | Deploy hub, add API key for an external app |
| `tests/` | Unit tests for normalization, routing, dedupe decisions and cards |

## Behaviour

| Event | Channel | What happens |
|---|---|---|
| `INFO` (job complete, deployment, update) | #app-updates | Plain card, no buttons |
| `WARNING` / `ERROR` / `CRITICAL`, new incident | #app-alerts | Interactive card |
| Same `incidentId` again, not acknowledged, within 15 min | — | Counted, not posted |
| Same `incidentId` after 15 min, still not acknowledged | #app-alerts | New card: "Still failing — N occurrences" |
| **Acknowledge** clicked | #app-alerts | Confirmation message; repeats suppressed until resolved (max 24h) |
| **Snooze** clicked | #app-alerts | Repeats suppressed for 60 min |
| **Resolve** clicked, or alarm → OK, or app sends `status: resolved` | #app-alerts | 🟢 RESOLVED card with duration; the next failure opens a new incident |
| INFO event that also has `status: resolved` (e.g. a batch succeeded after failing) | both | Resolves the incident **and** posts the completion update |

Tune with the stack parameters `DedupeMinutes`, `AckSuppressHours` and `SnoozeMinutes`.

## Deploy

1. **Hub** (central / shared-services account):
   ```bash
   scripts/deploy-hub.sh <artifact-bucket> platform-team@contoso.com [o-yourorgid]
   ```
   Confirm the SNS email subscription. This email is for alarms about the pipeline itself.
2. **Power Automate flow.** Follow [docs/power-automate-flow.md](docs/power-automate-flow.md), then put the flow URL and Entra credentials into the `teams-notify/power-automate` secret.
3. **Producer stack**, in every account/region running apps, including the hub account:
   ```bash
   aws cloudformation deploy --stack-name teams-notify-producer \
     --template-file cloudformation/producer-account.yaml --capabilities CAPABILITY_IAM \
     --parameter-overrides HubBusArn=<BusArn output>
   ```
4. **Verify.** Within an hour the `teams-notify-heartbeat-missing` alarm should move to OK. Then send a test event:
   ```bash
   aws events put-events --entries '[{"EventBusName":"teams-notify-bus","Source":"app.smoke-test","DetailType":"AppNotification","Detail":"{\"app\":\"smoke-test\",\"severity\":\"ERROR\",\"title\":\"Hub smoke test\",\"message\":\"Click Acknowledge\"}"}]'
   ```

## Onboarding an application

### Lambda / ECS (inside AWS)
- Grant the task or function role `events:PutEvents` on the hub `BusArn`. Set `TEAMS_NOTIFY_BUS` to the bus ARN when the app runs in another account.
- Use `client/teams_notify.py`, or call `PutEvents` with `Source: app.<name>`, `DetailType: AppNotification`.
- Give each repeating job a stable `incident_id` (e.g. `orders-api:nightly-recon`). Send the failure as `ERROR` and the next success as `info(..., resolves=True)`.

```python
notify = Notifier(app="orders-api")
notify.error("Nightly recon failed", str(exc), incident_id="orders-api:recon",
             links={"Logs": log_url, "Runbook": "https://wiki/recon"})
notify.info("Nightly recon complete", "120/120 batches", category="job-complete",
            incident_id="orders-api:recon", resolves=True)
```

### Failures the code can't report (automatic)
- **Async Lambdas** (triggered by S3, SNS, EventBridge, schedules): set an OnFailure destination to the account's default bus:
  ```yaml
  EventInvokeConfig:
    Type: AWS::Lambda::EventInvokeConfig
    Properties:
      FunctionName: !Ref MyFunction
      Qualifier: $LATEST
      MaximumRetryAttempts: 2
      DestinationConfig:
        OnFailure:
          Destination: !Sub arn:aws:events:${AWS::Region}:${AWS::AccountId}:event-bus/default
  ```
  (The function role needs `events:PutEvents` on the default bus.)
- **SQS- or API-triggered Lambdas** don't use destinations. Create a CloudWatch alarm named `notify-<app>-errors` on `AWS/Lambda Errors` or on the source DLQ depth.
- **ECS tasks**: covered automatically. Tasks that stop with a non-zero exit code or fail to start are forwarded. Stops caused by deployments or scale-in are ignored.
- **CloudWatch alarms**: any alarm whose name starts with `notify-` is forwarded. Put routing hints in the alarm description:
  `app=orders-api severity=CRITICAL runbook=https://wiki/orders-5xx  Order API 5xx rate above 5%`
  ALARM opens the incident and OK resolves it.

### External apps (REST)
```bash
scripts/add-ingest-key.sh billing-batch
```
```bash
curl -X POST "$INGEST_URL" -H "x-api-key: $KEY" -H "Content-Type: application/json" -d '{
  "app": "billing-batch", "severity": "ERROR", "title": "Invoice export failed",
  "message": "SFTP timeout after 3 retries", "incidentId": "billing-batch:export",
  "links": {"Runbook": "https://wiki/billing-export"}
}'
```
Fields: `app` (lowercase, hyphens), `severity` (INFO|WARNING|ERROR|CRITICAL), `title` are required.
Optional: `env`, `category`, `message`, `incidentId`, `status` (open|resolved), `links` (https only), `attributes`.
The API returns `200 {"status":"accepted","eventId":...}`, `400` when the schema check fails, and `403` for a bad key.

## Reliability

- **At-least-once delivery.** EventBridge retries for up to 24h. SQS retries 5 times, then moves the message to the DLQ, which triggers an alarm. Per-event idempotency in DynamoDB prevents duplicate posts on redelivery.
- **Audit.** Every event is logged with its outcome (DELIVERED, SUPPRESSED or FAILED) in `teams-notify-events` and kept for 90 days.
- **Health alarms go to email:** DLQ not empty, queue backlog over 10 min, more than 3 delivery failures in 5 min, and heartbeat missing for 2h. The last one catches an expired Entra secret, a turned-off flow or a broken connection.
- **Replaying the DLQ.** After fixing the cause, use SQS console → *Start DLQ redrive* back to the main queue.

## Known limits

- Each alert card accepts one click. The "Acknowledged by …" confirmation is posted as a separate message.
- RESOLVED notices are separate cards, not thread replies, because the wait-for-response action doesn't return a message ID.
- Ingest API keys identify the caller but are not bound to an `app` name. Any valid key can post as any app. Per-key app binding would need a Lambda authorizer.
