#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
PICUS_DOCKER_PLATFORM="${PICUS_DOCKER_PLATFORM:-linux/amd64}"
PICUS_LOCAL_IMAGE="${PICUS_LOCAL_IMAGE:-picus:v0}"
PICUS_SOURCE_DIR="${1:-${PICUS_SOURCE_DIR:-}}"

if [[ -z "${PICUS_SOURCE_DIR}" ]]; then
  echo "Usage: $0 /path/to/Picus [image tag via PICUS_LOCAL_IMAGE]" >&2
  exit 2
fi

exec "${DOCKER_BIN}" buildx build \
  --platform "${PICUS_DOCKER_PLATFORM}" \
  -t "${PICUS_LOCAL_IMAGE}" \
  --load \
  "${PICUS_SOURCE_DIR}"
