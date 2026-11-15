#!/usr/bin/env bash
set -eo pipefail

BRANCH="${1:-main}"
echo "Watching latest CI run for branch: $BRANCH"

RUN_ID=""
for attempt in $(seq 1 30); do
  RUN_ID=$(gh run list --branch "$BRANCH" --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
  STATUS=$(gh run list --branch "$BRANCH" --limit 1 --json status --jq '.[0].status' 2>/dev/null || true)
  if [ -n "$RUN_ID" ]; then
    echo "Found run $RUN_ID (status: $STATUS)"
    break
  fi
  sleep 3
done

if [ -z "$RUN_ID" ]; then
  echo "Error: No CI run found for branch $BRANCH."
  exit 1
fi

echo "Tracking CI run $RUN_ID..."
gh run watch "$RUN_ID" --interval 15 || true

CONCLUSION=$(gh run view "$RUN_ID" --json conclusion --jq '.conclusion')
STATUS=$(gh run view "$RUN_ID" --json status --jq '.status')

echo "Run $RUN_ID status=$STATUS conclusion=$CONCLUSION"

if [ "$CONCLUSION" != "success" ]; then
  echo "=== CI RUN FAILED ($CONCLUSION) ==="
  gh run view "$RUN_ID" --log-failed || true
  exit 1
fi

echo "=== CI RUN PASSED CLEANLY ==="
exit 0
