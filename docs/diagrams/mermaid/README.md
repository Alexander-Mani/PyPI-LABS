# Mermaid System Diagrams

This directory is the canonical source for the system diagrams used in the thesis and presentation.

## Files

- `system_overview.mmd`: end-to-end pipeline from staged samples to thesis evidence
- `deployment_trust_boundaries.mmd`: runtime trust boundaries and network isolation
- `analyzer_pipeline.mmd`: analyzer evidence path and detector lanes
- `evaluation_outputs.mmd`: DB, repairs, summaries, frozen-cut packaging, and reporting outputs

## Visual Conventions

- Use `flowchart LR` for overview / boundary diagrams and `flowchart TB` for dense pipeline diagrams.
- Use solid edges for active canonical flows.
- Use dashed edges for sidecars, overlays, or legacy/non-canonical paths.
- Use repo terms exactly: `Injector`, `Simulator`, `Analyzer`, `LiteLLM`, `eval_result`, `raw`, `hybrid`, `agentic`.
- Keep node text short. Put explanation in captions, notes, or nearby prose instead of inside the diagram body.

## Rendering

The repo does not expect Overleaf to render Mermaid directly. Render SVG and PNG assets into `overleaf_thesis/images/` first.

From the repo root:

```bash
bash scripts/render_mermaid_diagrams.sh
```

The render script uses Mermaid CLI through `npx`:

```bash
npx -y @mermaid-js/mermaid-cli -i docs/diagrams/mermaid/system_overview.mmd -o overleaf_thesis/images/diagram_system_overview.svg
```

If the package is not already installed locally, `npx` may download it on first use.
