#!/bin/bash

HEADER="header.md"
SCHEDULE="schedule.md"
READING="reading_list.md"
MD_OUT="final_report.md"
PDF_OUT="final_report.pdf"

# Pandoc Flags:
# --toc: Automatically generates a Table of Contents from your headers (#, ##).
# --toc-depth=2: Includes only H1 and H2 in the index.
# --standalone: Required for TOC to render properly in many formats.
# --pdf-engine=weasyprint: Good for handling HTML tags like <details> in PDFs.

# Create Merged Markdown
pandoc "$HEADER" "$SCHEDULE" "$READING" --toc --toc-depth=2 -t gfm -o "$MD_OUT"

# Create PDF
pandoc "$HEADER" "$SCHEDULE" "$READING" --toc --toc-depth=2 -o "$PDF_OUT" --pdf-engine=weasyprint

echo "Build complete: $MD_OUT and $PDF_OUT"
