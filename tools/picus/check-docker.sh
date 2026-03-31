#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Reuse the main Docker wrapper setup logic and ask Picus for help output.
exec "${SCRIPT_DIR}/run-picus-docker.sh" --help
