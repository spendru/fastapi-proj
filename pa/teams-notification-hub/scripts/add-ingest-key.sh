#!/usr/bin/env bash
# Creates an API key for one external application and attaches it to the ingest usage plan.
# Usage: scripts/add-ingest-key.sh <app-name>
set -euo pipefail
APP=${1:?app name}
STACK=${STACK:-teams-notify-hub}

PLAN=$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='IngestUsagePlanId'].OutputValue" --output text)

KEY_ID=$(aws apigateway create-api-key --name "ingest-$APP" --enabled \
  --tags app="$APP" --query id --output text)
aws apigateway create-usage-plan-key --usage-plan-id "$PLAN" --key-id "$KEY_ID" --key-type API_KEY >/dev/null

echo "API key id for $APP: $KEY_ID"
echo "Retrieve the value (hand it to the app owner via your secret store, not chat/email):"
echo "  aws apigateway get-api-key --api-key $KEY_ID --include-value --query value --output text"
