#!/usr/bin/env sh
# Send the sample reports to your site's endpoint to check that reporting works.
# The plugin must have CSP mode set to Report-Only or Enforce, with
# "Send violation reports" switched on. The document URL in the samples must
# use your site's host, so edit them first (example.com -> your domain).
#
# Usage: sh examples/send-test-report.sh https://your-site.example
set -eu

SITE="${1:?Usage: $0 https://your-site.example}"
ENDPOINT="$SITE/wp-json/security-headers/v1/report"
DIR="$(dirname "$0")/reports"

curl -sS -o /dev/null -w 'report-uri format: HTTP %{http_code}\n' \
  -H 'Content-Type: application/csp-report' \
  --data-binary "@$DIR/csp-report.json" "$ENDPOINT"

curl -sS -o /dev/null -w 'Reporting API format: HTTP %{http_code}\n' \
  -H 'Content-Type: application/reports+json' \
  --data-binary "@$DIR/reports-api.json" "$ENDPOINT"

# 204 = stored, 400 = document URL is not on this site,
# 403 = reporting is off, 429 = rate limited.
