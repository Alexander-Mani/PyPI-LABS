#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SRC_DIR="$ROOT_DIR/docs/diagrams/mermaid"
OUT_DIR="$ROOT_DIR/overleaf_docs/thesis/images"

if ! command -v npx >/dev/null 2>&1; then
  echo "error: npx is required to render Mermaid diagrams" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

render_one() {
  local input="$1"
  local base
  base="$(basename "$input" .mmd)"
  local svg="$OUT_DIR/diagram_${base}.svg"
  local png="$OUT_DIR/diagram_${base}.png"

  echo "rendering $base -> $(basename "$svg"), $(basename "$png")"
  npx -y @mermaid-js/mermaid-cli -i "$input" -o "$svg" -b white
  npx -y @mermaid-js/mermaid-cli -i "$input" -o "$png" -b white -s 2
}

for file in \
  "$SRC_DIR/system_overview.mmd" \
  "$SRC_DIR/deployment_trust_boundaries.mmd" \
  "$SRC_DIR/analyzer_pipeline.mmd" \
  "$SRC_DIR/evaluation_outputs.mmd"
  do
    render_one "$file"
  done

echo "done: rendered Mermaid diagrams into $OUT_DIR"
