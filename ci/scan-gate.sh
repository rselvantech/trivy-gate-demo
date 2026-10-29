#!/usr/bin/env bash
set -euo pipefail

# The pin: an exact release and the SHA-256 of its archive (from demo 02's pin table).
TRIVY_VERSION="${TRIVY_VERSION:-0.74.0}"
TRIVY_SHA256="${TRIVY_SHA256:-2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a}"
# Severities that fail the gate, as a comma-separated list.
THRESHOLD="${THRESHOLD:-CRITICAL}"
TARGET="${1:?usage: scan-gate.sh <directory to scan>}"
TARGET="$(cd "${TARGET}" && pwd)"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
ARCHIVE="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
BASE="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"

# Download the release asset and its checksum list, then verify the archive twice before running anything.
cd "${WORKDIR}"
curl -fsSL -O "${BASE}/${ARCHIVE}"
curl -fsSL -O "${BASE}/trivy_${TRIVY_VERSION}_checksums.txt"
grep " ${ARCHIVE}\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -
echo "${TRIVY_SHA256}  ${ARCHIVE}" | sha256sum -c -
tar -xzf "${ARCHIVE}" trivy
echo "Trivy ${TRIVY_VERSION} verified against the release checksums and the recorded SHA-256"

# Scan with an empty cache, as a fresh runner would, and give findings their own exit code.
set +e
./trivy filesystem --cache-dir "${WORKDIR}/cache" --skip-version-check --scanners vuln --severity "${THRESHOLD}" --exit-code 10 "${TARGET}"
STATUS=$?
set -e

# Record which database produced the verdict.
META="${WORKDIR}/cache/db/metadata.json"
if [ -f "${META}" ]; then
  DB_UPDATED="$(sed -n 's/.*"UpdatedAt":"\([^"]*\)".*/\1/p' "${META}")"
else
  DB_UPDATED="not recorded (no database was downloaded)"
fi
RECORD="scan record: Trivy ${TRIVY_VERSION}, database UpdatedAt ${DB_UPDATED}, threshold ${THRESHOLD}"
echo "${RECORD}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "${RECORD}" >> "${GITHUB_STEP_SUMMARY}"
fi

# Map Trivy's result to three outcomes.
case "${STATUS}" in
  0)
    echo "GATE PASSED: no findings at ${THRESHOLD}"
    ;;
  10)
    echo "GATE FAILED: findings at ${THRESHOLD}"
    exit 1
    ;;
  *)
    echo "SCAN ERROR: Trivy exited with ${STATUS}, so the gate cannot pass"
    exit 2
    ;;
esac
