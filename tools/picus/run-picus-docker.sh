#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
PICUS_DOCKER_IMAGE="${PICUS_DOCKER_IMAGE:-}"
PICUS_DOCKER_PLATFORM="${PICUS_DOCKER_PLATFORM:-linux/amd64}"
PICUS_DOCKER_MEMORY="${PICUS_DOCKER_MEMORY:-10g}"
PICUS_DOCKER_WORKDIR="${PICUS_DOCKER_WORKDIR:-/workspace}"
PICUS_DOCKER_ARTIFACTS_DIR="${PICUS_DOCKER_ARTIFACTS_DIR:-${PWD}/artifacts}"
PICUS_DOCKER_CMD="${PICUS_DOCKER_CMD:-}"
PICUS_SOURCE_DIR="${PICUS_SOURCE_DIR:-}"
PICUS_ALLOW_MUTABLE_IMAGE="${PICUS_ALLOW_MUTABLE_IMAGE:-0}"

if ! command -v "${DOCKER_BIN}" >/dev/null 2>&1; then
  echo "Missing docker binary: ${DOCKER_BIN}" >&2
  exit 127
fi

if [[ -z "${PICUS_DOCKER_IMAGE}" ]]; then
  echo "PICUS_DOCKER_IMAGE must be set to a digest-pinned image reference, for example:" >&2
  echo "  veridise/picus:base@sha256:fc396dbabd92cb0026a52dd3f2f72893374a1fc29367409cb49f251923089162" >&2
  exit 64
fi

if [[ "${PICUS_DOCKER_IMAGE}" != *@sha256:* && "${PICUS_ALLOW_MUTABLE_IMAGE}" != "1" ]]; then
  echo "Refusing mutable Picus image '${PICUS_DOCKER_IMAGE}'." >&2
  echo "Use a digest-pinned image or set PICUS_ALLOW_MUTABLE_IMAGE=1 for local experiments." >&2
  exit 64
fi

mkdir -p "${PICUS_DOCKER_ARTIFACTS_DIR}"

DOCKER_ARGS=(
  run --rm
  --platform "${PICUS_DOCKER_PLATFORM}"
  --memory "${PICUS_DOCKER_MEMORY}"
  -v "${PWD}:${PICUS_DOCKER_WORKDIR}:ro"
  -v "${PICUS_DOCKER_ARTIFACTS_DIR}:${PICUS_DOCKER_WORKDIR}/artifacts"
  -w "${PICUS_DOCKER_WORKDIR}"
)

if [[ -n "${PICUS_SOURCE_DIR}" ]]; then
  DOCKER_ARGS+=(-v "${PICUS_SOURCE_DIR}:/Picus:ro")
fi

if [[ -z "${PICUS_DOCKER_CMD}" ]]; then
  if [[ -n "${PICUS_SOURCE_DIR}" ]]; then
    PICUS_DOCKER_CMD="/Picus/run-picus"
  else
    PICUS_DOCKER_CMD="run-picus"
  fi
fi

exec "${DOCKER_BIN}" "${DOCKER_ARGS[@]}" "${PICUS_DOCKER_IMAGE}" "${PICUS_DOCKER_CMD}" "$@"
