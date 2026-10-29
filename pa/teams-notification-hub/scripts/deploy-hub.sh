#!/usr/bin/env bash
# Usage: scripts/deploy-hub.sh <artifact-bucket> <pipeline-alarm-email> [org-id]
set -euo pipefail
cd "$(dirname "$0")/.."

BUCKET=${1:?artifact S3 bucket}
EMAIL=${2:?email for pipeline alarms}
ORG=${3:-}
STACK=${STACK:-teams-notify-hub}

mkdir -p build
aws cloudformation package \
  --template-file cloudformation/hub.yaml \
  --s3-bucket "$BUCKET" --s3-prefix teams-notify \
  --output-template-file build/hub.packaged.yaml

aws cloudformation deploy \
  --stack-name "$STACK" \
  --template-file build/hub.packaged.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides PipelineAlarmEmail="$EMAIL" OrgId="$ORG"

aws cloudformation describe-stacks --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table
