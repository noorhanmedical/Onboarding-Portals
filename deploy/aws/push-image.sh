#!/usr/bin/env bash
# Build the image and push it to Amazon ECR. App Runner redeploys automatically if "automatic deployment" is on.
# Usage: AWS_REGION=us-west-2 ./deploy/aws/push-image.sh
set -euo pipefail
REGION="${AWS_REGION:-us-west-2}"
REPO="${ECR_REPO:-plexus-onboarding}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
URI="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/$REPO"
aws ecr describe-repositories --repository-names "$REPO" --region "$REGION" >/dev/null 2>&1 \
  || aws ecr create-repository --repository-name "$REPO" --region "$REGION" --image-scanning-configuration scanOnPush=true >/dev/null
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
docker build --platform linux/amd64 -t "$URI:$TAG" -t "$URI:latest" .
docker push "$URI:$TAG"
docker push "$URI:latest"
echo "Pushed $URI:$TAG"
