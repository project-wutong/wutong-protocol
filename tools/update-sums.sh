#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Recompute SHA256SUMS.txt over the normative artefacts (spec, docs, schemas, openapi, examples, vectors).
set -euo pipefail
cd "$(dirname "$0")/.."
find docs spec schemas openapi examples vectors -type f | LC_ALL=C sort | xargs sha256sum > SHA256SUMS.txt
