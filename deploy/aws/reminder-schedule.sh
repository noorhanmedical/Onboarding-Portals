#!/usr/bin/env bash
# Creates a scheduled EventBridge rule that calls /api/cron/reminders every 15 minutes.
# Usage: AWS_REGION=us-west-2 APP_URL=https://onboarding.plexusclinical.com CRON_SECRET=... ./deploy/aws/reminder-schedule.sh
set -euo pipefail
REGION="${AWS_REGION:-us-west-2}"
: "${APP_URL:?set APP_URL}"; : "${CRON_SECRET:?set CRON_SECRET (same value as the app secret)}"
NAME=plexus-onboarding-reminders
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
# 1. Connection holding the secret header
aws events create-connection --region "$REGION" --name "$NAME" --authorization-type API_KEY \
  --auth-parameters "ApiKeyAuthParameters={ApiKeyName=x-cron-secret,ApiKeyValue=$CRON_SECRET}" >/dev/null 2>&1 || true
CONN_ARN="$(aws events describe-connection --region "$REGION" --name "$NAME" --query ConnectionArn --output text)"
# 2. API destination
aws events create-api-destination --region "$REGION" --name "$NAME" --connection-arn "$CONN_ARN" \
  --invocation-endpoint "$APP_URL/api/cron/reminders" --http-method POST >/dev/null 2>&1 || true
DEST_ARN="$(aws events describe-api-destination --region "$REGION" --name "$NAME" --query ApiDestinationArn --output text)"
# 3. Role EventBridge uses to call it
aws iam create-role --role-name "$NAME-events" --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null 2>&1 || true
aws iam put-role-policy --role-name "$NAME-events" --policy-name invoke --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"events:InvokeApiDestination\",\"Resource\":\"$DEST_ARN\"}]}"
# 4. Rule every 15 minutes (the app itself only sends 9am–5pm clinic time, and skips weekends if set)
aws events put-rule --region "$REGION" --name "$NAME" --schedule-expression "rate(15 minutes)" --state ENABLED >/dev/null
aws events put-targets --region "$REGION" --rule "$NAME" --targets "[{\"Id\":\"app\",\"Arn\":\"$DEST_ARN\",\"RoleArn\":\"arn:aws:iam::$ACCOUNT:role/$NAME-events\",\"Input\":\"{}\",\"HttpParameters\":{\"HeaderParameters\":{\"Content-Type\":\"application/json\"}}}]" >/dev/null
echo "Rule $NAME created — reminders run every 15 minutes"
