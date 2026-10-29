# Power Automate flow: "AWS Notifications → Teams"

One flow handles everything the hub sends. The notifier Lambda POSTs JSON with a
`kind` of `alert`, `update` or `heartbeat`.

## 0. Prerequisites

| Item | Notes |
|---|---|
| Service account | A dedicated, licensed M365 account (e.g. `svc-aws-notify@contoso.com`) that is a member of both Teams. It owns the flow and the Teams connection, so posts don't depend on a person. |
| Two channels | `#app-alerts` and `#app-updates`, in the same Team or in different ones. |
| Environment | Your production Power Platform environment. DLP must allow **HTTP**, **When an HTTP request is received** and **Microsoft Teams** in the same policy group. |
| Entra ID app registration | For OAuth on the trigger (see step 1). |

## 1. Entra ID app registration (caller identity for AWS)

1. Go to Entra admin center → App registrations → **New registration**, name it `aws-teams-notify`, single tenant.
2. Under **Certificates & secrets**, create a client secret. Pick a 12–24 month expiry and add a calendar reminder to rotate it. The hub's heartbeat alarm also fires if the secret expires.
3. Note the **Directory (tenant) ID** and **Application (client) ID**.
4. Under Enterprise applications → `aws-teams-notify`, note the **Object ID** of the service principal. You need it for "Specific users" on the trigger.

No API permissions are needed. The Lambda requests a client-credentials token for
`https://service.flow.microsoft.com//.default`. The double slash is correct: it is the
resource `https://service.flow.microsoft.com/` plus `/.default`. Microsoft requires the
token audience to exactly match `https://service.flow.microsoft.com/`. For GCC, use
`https://gov.service.flow.microsoft.us/` and change `scope` in the secret to match.

## 2. Create a Solution and environment variables

In make.powerautomate.com → **Solutions** → New solution `AwsTeamsNotifications`. Inside it, add:

| Environment variable | Type | Value |
|---|---|---|
| `AlertsTeamId` | Text | Group ID of the Team holding #app-alerts |
| `AlertsChannelId` | Text | Channel ID of #app-alerts |
| `UpdatesTeamId` | Text | Group ID of the Team holding #app-updates |
| `UpdatesChannelId` | Text | Channel ID of #app-updates |
| `AckUrl` | Text | `CallbackUrl` output of the hub stack |
| `AckApiKey` | Secret (Azure Key Vault) **or** Text | Value of the `PowerAutomateApiKeyId` key: `aws apigateway get-api-key --api-key <id> --include-value` |

To get IDs: in Teams, open the channel's **⋯ → Get link to channel**. The link contains
`groupId=` (the Team) and `/channel/19%3A...%40thread.tacv2/` (the channel ID, URL-encoded).
Decode it to `19:...@thread.tacv2`.

Add a **connection reference** for Microsoft Teams that uses the service account.

## 3. Build the flow (inside the solution)

New → Automation → Cloud flow → Instant → **When an HTTP request is received**.

### Trigger

- **Who can trigger the flow:** *Specific users in my tenant*. Enter the service principal Object ID from step 1.4.
  If calls return 401 with that setting, try *Any user in my tenant*. Some tenants also require the service principal to be a co-owner of the flow.
- **Request Body JSON Schema:**

```json
{
  "type": "object",
  "properties": {
    "kind":       { "type": "string" },
    "channel":    { "type": "string" },
    "incidentId": { "type": "string" },
    "summary":    { "type": "string" },
    "card":       { "type": "object" }
  },
  "required": ["kind"]
}
```

After the first save, copy the **HTTP URL** into the AWS secret (step 4).

### Switch on `triggerBody()?['kind']`

#### Case `heartbeat`
- **Response**: status `200`, body `{"ok": true}`

This proves the flow, its auth and the run quota are healthy. It posts nothing to Teams.

#### Case `update`  (job completions, info, and RESOLVED notices)
1. **Compose** `TeamId`:
   `if(equals(triggerBody()?['channel'],'alerts'), <AlertsTeamId>, <UpdatesTeamId>)`
2. **Compose** `ChannelId`:
   `if(equals(triggerBody()?['channel'],'alerts'), <AlertsChannelId>, <UpdatesChannelId>)`
   (Insert the environment variables from the dynamic content pane.)
3. **Microsoft Teams – Post card in a chat or channel**
   - Post as: *Flow bot* · Post in: *Channel*
   - Team: *Enter custom value* → `outputs('TeamId')`
   - Channel: *Enter custom value* → `outputs('ChannelId')`
   - Adaptive Card: `string(triggerBody()?['card'])`
4. **Response**: status `200`, body `{"ok": true}`

The flow decides the target from `channel` and only knows the two IDs in its environment
variables. AWS cannot make it post anywhere else.

#### Case `alert`  (interactive)
1. **Response**: status `202`, body `{"accepted": true}`.
   This releases the Lambda right away. The flow keeps running and waits for a click.
2. **Microsoft Teams – Post adaptive card and wait for a response**
   - Post as: *Flow bot* · Post in: *Channel*
   - Team: `AlertsTeamId` · Channel: `AlertsChannelId`
   - Message: `string(triggerBody()?['card'])`
   - Update message: `Response recorded — see the follow-up below.`
   - Should update card: **Yes**
   - Action **Settings → Timeout**: `P7D`
3. **HTTP** (premium)
   - Method `POST`, URI: `AckUrl`
   - Headers: `Content-Type: application/json`, `x-api-key: <AckApiKey>`
   - Body:
     ```
     {
       "incidentId": "@{triggerBody()?['incidentId']}",
       "action": "@{coalesce(body('Post_adaptive_card_and_wait_for_a_response')?['data']?['action'], body('Post_adaptive_card_and_wait_for_a_response')?['submitActionId'])}",
       "responder": @{body('Post_adaptive_card_and_wait_for_a_response')?['responder']}
     }
     ```
     If you rename the wait action, change its name in the expressions. Check a test run's
     outputs to confirm where `action` appears in your tenant.
   - Settings → Retry policy: Exponential, count 4.
4. **Microsoft Teams – Post message in a chat or channel**
   - Flow bot, Channel, `AlertsTeamId` / `AlertsChannelId`
   - Message: `body('HTTP')?['message']`

   The callback returns ready-made text such as
   "✅ Acknowledged by Jane Doe. Repeat alerts are suppressed until it resolves or for 24h."

Optional: add a parallel branch after step 2 set to **Configure run after → has timed out**
that posts "Not acknowledged after 7 days".

#### Default case
- **Response**: status `400`, body `{"error": "unknown kind"}`

### Notes on the card behaviour
- A card created by *wait for a response* accepts **one** click. After the click it is
  replaced by the "Update message" text. That is why each alert card has exactly one decision:
  Acknowledge, Snooze or Resolve. If something is still failing after a snooze or ack expires,
  a fresh card is posted.
- This action does not return a Teams message ID, so the RESOLVED notice is a separate card
  in #app-alerts rather than a reply in a thread.

## 4. Point AWS at the flow

```bash
aws secretsmanager put-secret-value --secret-id teams-notify/power-automate --secret-string '{
  "flowUrl": "<HTTP URL from trigger>",
  "authMode": "oauth",
  "tenantId": "<tenant id>",
  "clientId": "<app client id>",
  "clientSecret": "<client secret>",
  "scope": "https://service.flow.microsoft.com//.default"
}'
```

The Lambda caches the secret per container. Force a reload after changing it:
`aws lambda update-function-configuration --function-name teams-notify-notifier --description "secret rotated $(date +%F)"`.

Fallback if your tenant blocks OAuth on the trigger: set the trigger to *Anyone*, and set
`"authMode": "url"`. The signed URL then acts as the credential, so keep it only in Secrets
Manager.

## 5. ALM without CI/CD (for now)

1. Build in a **Dev** environment.
2. Solutions → Export → **Managed**. Commit the zip to the same git repo as the CloudFormation (`powerplatform/AwsTeamsNotifications_managed.zip`).
3. Import into **Prod**. The import wizard asks for environment variable values and the Teams connection reference.
4. Turn on the flow and copy the prod trigger URL into the prod secret.

When you're ready for automation, the built-in **Power Platform Pipelines** need no extra
tooling. The `pac solution export/import` CLI also slots into any CI system.
