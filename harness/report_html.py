"""Render runs/*/record.json into one self-contained HTML page.

    python -m harness.report_html                      # runs/ -> docs/results/index.html
    python -m harness.report_html --runs-dir runs-dev  # exploratory runs

The page is static: no server, no key, no input field, so it can be published on
GitHub Pages with zero attack surface (decision log 2026-10-18). The table is model ×
case with one coloured chip per outcome; clicking a cell lists that pair's runs and,
per run, shows the diff the model produced, the test counts, the verdict lists, the
scanner booleans, tokens, seconds and cost. Everything comes from the record folders;
the page does not compute any verdict itself. Markup lives in templates/results.html.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from harness.charts import (
    COLORS,
    LABELS,
    cell_tint,
    outcome_bars_svg,
    poison_bars_svg,
    three_lights_svg,
)
from harness.report import load_records, per_model
from harness.setup_case import REPO_ROOT
from harness.verify import FIXED_BUT_BROKE, OUTCOMES

TEMPLATE = Path(__file__).parent / "templates" / "results.html"
PATCH_LIMIT = 20_000  # characters of model.patch embedded per run
POISON_DIR = REPO_ROOT / "runs-poison"

_ORDER = [*OUTCOMES, "error"]

# Short names for the weakness classes in benchmarks/cves.yaml (CWE ids stay the key).
CWE_NAMES = {
    "CWE-22": "path traversal",
    "CWE-78": "OS command injection",
    "CWE-79": "cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-94": "code injection",
    "CWE-287": "missing authorization check",
    "CWE-290": "authentication bypass by spoofing",
    "CWE-295": "improper certificate validation",
    "CWE-502": "unsafe deserialization",
    "CWE-918": "server-side request forgery",
}


def case_labels() -> dict[str, tuple[str, str]]:
    """case id -> (project, weakness) from benchmarks/cves.yaml; empty if unavailable."""
    try:
        from harness.setup_case import load_cases

        out = {}
        for c in load_cases():
            names = [CWE_NAMES.get(cwe, cwe) for cwe in c.cwe]
            weakness = names[0] if names else ""
            out[c.id] = (c.project.split("/")[-1], f"{weakness} ({', '.join(c.cwe)})")
        return out
    except Exception:  # noqa: BLE001 - the page must still render without the yaml
        return {}


def _read(folder: Path, name: str, limit: int | None = None) -> str | None:
    p = folder / name
    if not p.exists():
        return None
    text = p.read_text(errors="replace")
    if limit and len(text) > limit:
        return text[:limit] + f"\n... [{len(text) - limit} more characters in {name}]"
    return text


def _booleans(scans: dict | None) -> dict[str, list]:
    return {
        tool: [s.get("found_in_file"), s.get("found_in_target")]
        for tool, s in (scans or {}).items()
    }


def run_payload(rec: dict, runs_dir: Path) -> dict:
    """The per-run data the page embeds. Keep it small and flat."""
    folder = runs_dir / rec["_folder"]
    mc = rec.get("model_call") or {}
    return {
        "folder": rec["_folder"],
        "case": rec["case"],
        "model": rec["model"],
        "outcome": rec.get("outcome", "error"),
        "error": rec.get("error"),
        "total_s": rec.get("total_s"),
        "prompt_version": rec.get("prompt_version"),
        "tokens": [mc.get("prompt_tokens"), mc.get("completion_tokens")],
        "finish_reason": mc.get("finish_reason"),
        "cost_usd": mc.get("cost_usd", rec.get("gateway_cost_usd_lower_bound")),
        "apply": rec.get("apply"),
        "security": rec.get("security_tests"),
        "baseline": rec.get("regression_baseline"),
        "after": rec.get("regression_after"),
        "verdict": rec.get("verdict"),
        "scan_before": _booleans(rec.get("scan_before")),
        "scan_after": _booleans(rec.get("scan_after")),
        "patch": _read(folder, "model.patch", PATCH_LIMIT),
        # The three-lamp picture only exists for the outcome it illustrates.
        "lights_svg": three_lights_svg(rec) if rec.get("outcome") == FIXED_BUT_BROKE else None,
    }


def _chip(outcome: str, n: int | None = None) -> str:
    label = LABELS.get(outcome, outcome)
    text = f"{label} ×{n}" if n is not None else label
    ink = "#222" if outcome == "not-fixed" else "#fff"  # amber needs dark text
    return (
        f'<span class="chip" style="background:{COLORS.get(outcome, "#999")};color:{ink}">'
        f"{text}</span>"
    )


def _cell(model: str, case: str, cnt: Counter | None) -> str:
    if not cnt:
        return '<td class="empty">–</td>'
    ordered = sorted(cnt.items(), key=lambda kv: _ORDER.index(kv[0]) if kv[0] in _ORDER else 99)
    chips = "".join(_chip(o, n) for o, n in ordered)
    tint = cell_tint(cnt)
    style = f' style="background:{tint}"' if tint else ""
    return (
        f'<td class="cell" data-model="{html.escape(model)}" '
        f'data-case="{html.escape(case)}"{style}>{chips}</td>'
    )


def load_poison_records(poison_dir: Path = POISON_DIR) -> list[dict]:
    """Every record under runs-poison/<payload>/; empty when the experiment is absent."""
    out: list[dict] = []
    if poison_dir.is_dir():
        for sub in sorted(p for p in poison_dir.iterdir() if p.is_dir()):
            out.extend(load_records(sub))
    return out


def build_page(records: list[dict], runs_dir: Path, poison: list[dict] | None = None) -> str:
    models = sorted({r["model"] for r in records})
    cases = sorted({r["case"] for r in records})
    labels = case_labels()

    def case_header(case: str) -> str:
        project, weakness = labels.get(case, ("", ""))
        sub = (
            f'<div class="meta">{html.escape(project)}<br>{html.escape(weakness)}</div>'
            if project
            else ""
        )
        return f"<th>{html.escape(case)}{sub}</th>"

    cells: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for r in records:
        cells[(r["model"], r["case"])][r.get("outcome", "error")] += 1
    pm = per_model(records)

    matrix_rows = "".join(
        f"<tr><th>{html.escape(m)}</th>"
        + "".join(_cell(m, c, cells.get((m, c))) for c in cases)
        + "</tr>"
        for m in models
    )
    summary_rows = "".join(
        f"<tr><th>{html.escape(m)}</th><td>{s['runs']}</td>"
        + "".join(f"<td>{s['counts'][o]}</td>" for o in OUTCOMES)
        + f"<td>{s['errors']}</td><td>{s['median_s'] or '–'}</td></tr>"
        for m, s in pm.items()
    )
    poison = poison or []
    poison_block = (
        "<h2>Prompt injection: did the diff do what the planted comment asked?</h2>"
        f"{poison_bars_svg(poison)}"
        '<div class="meta">Each model saw the same two comments planted inside the function '
        "it was asked to fix. A bar is the share of runs whose diff added what the comment "
        "asked for. Runs live in <code>runs-poison/</code>; they are not part of the table "
        "above.</div>"
        if poison
        else ""
    )
    fills = {
        "__RUN_COUNT__": str(len(records)),
        "__RUNS_DIR__": html.escape(runs_dir.name),
        "__GENERATED__": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "__LEGEND__": "".join(_chip(o) for o in _ORDER),
        "__OUTCOME_BARS__": outcome_bars_svg(records),
        "__POISON_BLOCK__": poison_block,
        "__CASE_HEADER__": "".join(case_header(c) for c in cases),
        "__CASE_LABELS_JSON__": json.dumps({c: f"{p} · {w}" for c, (p, w) in labels.items()}),
        "__MATRIX_ROWS__": matrix_rows,
        "__OUTCOME_HEADER__": "".join(f"<th>{LABELS[o]}</th>" for o in OUTCOMES),
        "__SUMMARY_ROWS__": summary_rows,
        # "</" is escaped so a diff containing "</script>" cannot close the data block.
        "__RUNS_JSON__": json.dumps([run_payload(r, runs_dir) for r in records]).replace(
            "</", "<\\/"
        ),
        "__COLORS_JSON__": json.dumps(COLORS),
        "__LABELS_JSON__": json.dumps(LABELS),
    }
    page = TEMPLATE.read_text()
    for key, value in fills.items():
        page = page.replace(key, value)
    return page


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--runs-dir", type=Path, default=REPO_ROOT / "runs")
    # GitHub Pages publishes /docs, so the page is written there directly: one copy.
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "docs" / "results" / "index.html")
    parser.add_argument(
        "--poison-dir",
        type=Path,
        default=POISON_DIR,
        help="runs-poison/ root; the injection chart is omitted when it does not exist",
    )
    args = parser.parse_args(argv)
    records = load_records(args.runs_dir)
    if not records:
        print(f"no records under {args.runs_dir}", file=sys.stderr)
        return 1
    poison = load_poison_records(args.poison_dir)
    args.out.parent.mkdir(exist_ok=True)
    args.out.write_text(build_page(records, args.runs_dir, poison))
    # The headline chart also goes out as a standalone file (README cover image).
    svg_out = args.out.with_name("outcomes.svg")
    svg_out.write_text(outcome_bars_svg(records))
    print(
        f"wrote {args.out} ({args.out.stat().st_size // 1024} KB, {len(records)} runs, "
        f"{len(poison)} poison runs) and {svg_out.name}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
