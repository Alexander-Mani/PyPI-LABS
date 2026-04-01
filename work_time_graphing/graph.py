"""
graph.py — Generate work-time charts from timewarrior data.

Usage:
    python graph.py

Outputs:
    hours.png        — Stacked weekly bar chart of hours worked by activity
    distribution.png — Pie chart of hours by activity tag
    burndown.png     — Hours remaining vs ideal line (Phase 1+2, 190-hour budget)
"""

import re
import subprocess
from collections import defaultdict
from datetime import date, timedelta

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Colour scheme for dark backgrounds.
_FG = "white"
plt.rcParams.update({
    "text.color":          _FG,
    "axes.labelcolor":     _FG,
    "axes.edgecolor":      _FG,
    "axes.facecolor":      "none",
    "figure.facecolor":    "none",
    "xtick.color":         _FG,
    "ytick.color":         _FG,
    "legend.edgecolor":    _FG,
    "legend.facecolor":    "#00000066",
    "grid.color":          _FG,
})

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TIMEW_START = "2026-01-08T00:00:00"
TIMEW_END   = "2026-04-12T00:00:00"

BURNDOWN_START = date(2026, 1, 8)
BURNDOWN_END   = date(2026, 3, 18)
BUDGET_HOURS   = 190.0  # Phase 1+2: 380 / 4 * 2

TAG_NAMES: dict[str, str] = {
    "final-project": "Final Project",
    "lecture":       "Lecture",
    "reading":       "Reading",
    "planning":      "Planning",
    "meeting":       "Meeting",
    "writing":       "Writing",
    "presentation":  "Presentation",
    "development":   "Development",
    "testing":       "Testing",
}

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _col_starts(sep_line: str) -> list[int]:
    """Return the start index of each dash-group in the separator line."""
    starts: list[int] = []
    in_dash = False
    for i, ch in enumerate(sep_line):
        if ch == "-" and not in_dash:
            starts.append(i)
            in_dash = True
        elif ch != "-":
            in_dash = False
    return starts


def _parse_duration(s: str) -> float:
    """Convert 'H:MM:SS' or 'HH:MM:SS' to fractional hours."""
    parts = s.strip().split(":")
    h, m, sec = int(parts[0]), int(parts[1]), int(parts[2])
    return h + m / 60.0 + sec / 3600.0


def _col_slice(line: str, starts: list[int], col: int) -> str:
    """Extract the content of column `col` from a fixed-width line."""
    begin = starts[col]
    end   = starts[col + 1] if col + 1 < len(starts) else len(line)
    return line[begin:end]


def fetch_and_parse() -> list[tuple[date, list[str], float]]:
    """
    Run timew and parse its fixed-width output.

    Returns a list of (entry_date, tags, hours) tuples, one per @ID entry.
    Tags are raw strings (e.g. 'final-project', 'reading').
    """
    result = subprocess.run(
        ["timew", "summary", TIMEW_START, "-", TIMEW_END],
        capture_output=True, text=True, check=True,
    )
    lines = result.stdout.splitlines()

    # Find the separator line that follows the header row.
    sep_idx = next(
        (i for i, ln in enumerate(lines) if re.match(r"^[-\s]+$", ln) and "---" in ln),
        None,
    )
    if sep_idx is None:
        raise RuntimeError("Could not find separator line in timew output.")

    starts = _col_starts(lines[sep_idx])
    # Expected columns (0-indexed): Wk=0 Date=1 Day=2 ID=3 Tags=4
    #   Annotation=5 Start=6 End=7 Time=8 Total=9
    ID_COL   = 3
    TAGS_COL = 4
    TIME_COL = 8

    entries: list[tuple[date, list[str], float]] = []
    current_date: date | None = None
    current_tags: list[str] = []
    current_hours: float | None = None

    def _flush():
        if current_hours is not None and current_date is not None:
            entries.append((current_date, list(current_tags), current_hours))

    for raw_line in lines[sep_idx + 1:]:
        # Skip blank lines and the grand-total footer (no @ID anywhere).
        if not raw_line.strip():
            continue

        line = raw_line  # keep original for column slicing

        # Try to read date from column 1 (only on first entry of a day).
        date_str = _col_slice(line, starts, 1).strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_str):
            current_date = date.fromisoformat(date_str)

        # Check whether this line opens a new entry (@ID present in ID column).
        id_str = _col_slice(line, starts, ID_COL).strip()
        if re.fullmatch(r"@\d+", id_str):
            # Save previous entry before starting a new one.
            _flush()
            current_tags = []
            current_hours = None

            # Extract time for this entry.
            time_str = _col_slice(line, starts, TIME_COL).strip()
            if re.fullmatch(r"\d+:\d{2}:\d{2}", time_str):
                current_hours = _parse_duration(time_str)

            # Extract tags from this line (may be partial — more on next lines).
            tags_raw = _col_slice(line, starts, TAGS_COL).strip().rstrip(",")
            for tag in tags_raw.split(","):
                t = tag.strip()
                if t:
                    current_tags.append(t)
        else:
            # Continuation line — may contain more tags in the Tags column.
            # The tags field on continuation lines aligns with TAGS_COL.
            tags_raw = _col_slice(line, starts, TAGS_COL).strip().rstrip(",")
            if tags_raw and not re.search(r"\d+:\d{2}:\d{2}", tags_raw):
                for tag in tags_raw.split(","):
                    t = tag.strip()
                    if t:
                        current_tags.append(t)

    _flush()
    return entries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def secondary_tag_label(tags: list[str]) -> str:
    """Return the pretty label for the secondary tag (not final-project)."""
    for t in tags:
        if t != "final-project":
            return TAG_NAMES.get(t, t)
    return "Other"


# ---------------------------------------------------------------------------
# Chart 1 — Burndown
# ---------------------------------------------------------------------------

def build_burndown(entries: list[tuple[date, list[str], float]]) -> None:
    # Aggregate hours per day within the burndown window.
    daily: dict[date, float] = defaultdict(float)
    for entry_date, _tags, hours in entries:
        if BURNDOWN_START <= entry_date <= BURNDOWN_END:
            daily[entry_date] += hours

    # Build sorted date range and cumulative hours worked.
    total_days = (BURNDOWN_END - BURNDOWN_START).days
    dates = [BURNDOWN_START + timedelta(days=d) for d in range(total_days + 1)]

    cumulative = 0.0
    actual_remaining: list[float] = []
    for d in dates:
        cumulative += daily.get(d, 0.0)
        actual_remaining.append(BUDGET_HOURS - cumulative)

    # Ideal straight line: 190 → 0 over the window.
    ideal_remaining = [
        BUDGET_HOURS * (1.0 - i / total_days) for i in range(total_days + 1)
    ]

    fig, ax = plt.subplots(figsize=(12, 5))

    ax.plot(dates, ideal_remaining, linestyle="--", color="gray",
            linewidth=1.5, label="Ideal burndown")
    ax.plot(dates, actual_remaining, color="#1f77b4",
            linewidth=2, label="Actual remaining")

    # Shade regions: green where ahead of schedule, red where behind.
    ax.fill_between(dates, actual_remaining, ideal_remaining,
                    where=[a <= i for a, i in zip(actual_remaining, ideal_remaining)],
                    alpha=0.15, color="green", label="Ahead of schedule")
    ax.fill_between(dates, actual_remaining, ideal_remaining,
                    where=[a > i for a, i in zip(actual_remaining, ideal_remaining)],
                    alpha=0.15, color="red", label="Behind schedule")

    ax.set_title("Phase 1+2 Burndown (190-hour budget)", fontsize=14)
    ax.set_xlabel("Date")
    ax.set_ylabel("Hours remaining")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.WeekdayLocator(byweekday=mdates.MO))
    fig.autofmt_xdate()
    ax.legend()
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    ax.set_xlim(BURNDOWN_START, BURNDOWN_END)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig("burndown.png", dpi=150, transparent=True)
    plt.close(fig)
    print("Saved burndown.png")


# ---------------------------------------------------------------------------
# Chart 2 — Tag distribution pie
# ---------------------------------------------------------------------------

def build_distribution(entries: list[tuple[date, list[str], float]]) -> None:
    totals: dict[str, float] = defaultdict(float)
    for _date, tags, hours in entries:
        label = secondary_tag_label(tags)
        totals[label] += hours

    labels = list(totals.keys())
    sizes  = [totals[l] for l in labels]

    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=None,
        autopct=lambda pct: f"{pct:.1f}%" if pct >= 2.5 else "",
        startangle=140,
        pctdistance=0.82,
    )
    for t in autotexts:
        t.set_color(_FG)
    ax.legend(wedges, labels, title="Activity", loc="lower right",
              bbox_to_anchor=(1.15, 0.0))
    # ax.set_title("Time distribution by activity tag", fontsize=14)

    fig.tight_layout()
    fig.savefig("distribution.png", dpi=150, transparent=True)
    plt.close(fig)
    print("Saved distribution.png")


# ---------------------------------------------------------------------------
# Chart 3 — Weekly hours stacked bar
# ---------------------------------------------------------------------------

def build_weekly_hours(entries: list[tuple[date, list[str], float]]) -> None:
    # Cumulative hours worked, plotted at each week boundary.
    weekly: dict[date, float] = defaultdict(float)
    for entry_date, _tags, hours in entries:
        week_start = entry_date - timedelta(days=entry_date.weekday())
        weekly[week_start] += hours

    weeks = sorted(weekly)
    cumulative, running = [], 0.0
    for w in weeks:
        running += weekly[w]
        cumulative.append(running)

    fig, ax = plt.subplots(figsize=(11, 4))
    ax.fill_between(weeks, cumulative, alpha=0.25, color="salmon")
    ax.plot(weeks, cumulative, color="salmon", linewidth=2)

    # Label the final total.
    ax.annotate(
        f"{running:.0f}h total",
        xy=(weeks[-1], cumulative[-1]),
        xytext=(-10, 30), textcoords="offset points",
        ha="right", fontsize=11, color=_FG,
    )

    ax.set_title("Cumulative hours worked", fontsize=14)
    ax.set_xlabel("Week")
    ax.set_ylabel("Hours")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.WeekdayLocator(byweekday=mdates.MO))
    fig.autofmt_xdate()
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig("hours.png", dpi=150, transparent=True)
    plt.close(fig)
    print("Saved hours.png")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Fetching timewarrior data...")
    entries = fetch_and_parse()
    print(f"Parsed {len(entries)} entries.")

    total_h = sum(h for _, _, h in entries)
    print(f"Total hours in range: {total_h:.2f}")

    build_weekly_hours(entries)
    build_distribution(entries)
    build_burndown(entries)
