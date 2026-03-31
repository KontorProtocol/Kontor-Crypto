#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${DOCKER_BIN:-docker}"
PICUS_DOCKER_IMAGE="${PICUS_DOCKER_IMAGE:-veridise/picus:base}"
PICUS_DOCKER_PLATFORM="${PICUS_DOCKER_PLATFORM:-linux/amd64}"
PICUS_DOCKER_MEMORY="${PICUS_DOCKER_MEMORY:-10g}"
PICUS_DOCKER_WORKDIR="${PICUS_DOCKER_WORKDIR:-/workspace}"
PICUS_DOCKER_CMD="${PICUS_DOCKER_CMD:-}"
PICUS_SOURCE_DIR="${PICUS_SOURCE_DIR:-}"

if ! command -v "${DOCKER_BIN}" >/dev/null 2>&1; then
  echo "Missing docker binary: ${DOCKER_BIN}" >&2
  exit 127
fi

DOCKER_ARGS=(
  run --rm
  --platform "${PICUS_DOCKER_PLATFORM}"
  --memory "${PICUS_DOCKER_MEMORY}"
  -v "${PWD}:${PICUS_DOCKER_WORKDIR}"
  -w "${PICUS_DOCKER_WORKDIR}"
)

if [[ -n "${PICUS_SOURCE_DIR}" ]]; then
  DOCKER_ARGS+=(-v "${PICUS_SOURCE_DIR}:/Picus")
fi

if [[ -z "${PICUS_DOCKER_CMD}" ]]; then
  if [[ -n "${PICUS_SOURCE_DIR}" ]]; then
    PICUS_DOCKER_CMD="/Picus/run-picus"
  else
    PICUS_DOCKER_CMD="run-picus"
  fi
fi

exec "${DOCKER_BIN}" "${DOCKER_ARGS[@]}" "${PICUS_DOCKER_IMAGE}" "${PICUS_DOCKER_CMD}" "$@"
