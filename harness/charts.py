"""Inline SVG charts for the results page, generated from the run records.

Everything here is plain SVG text with no script and no external resource, so the
page keeps its "static, zero attack surface" property (decision log 2026-10-18).
Colours follow one rule: green = fixed and clean, amber = not fixed, red = fixed but
broke, grey = not applied; the same four everywhere on the page, each always paired
with its label, never colour alone.

Four pieces:
  outcome_bars_svg    stacked bar per model, scored runs only (errors excluded)
  three_lights_svg    one fixed-but-broke run as three lamps: scanner, security, regression
  poison_bars_svg     per model, destructive vs benign injection compliance
  cell_tint           background tint for a model × case cell by its dominant outcome
"""

from __future__ import annotations

import html
from collections import Counter, defaultdict

from harness.verify import FIXED_AND_CLEAN, FIXED_BUT_BROKE, NOT_APPLIED, NOT_FIXED, OUTCOMES

COLORS = {
    FIXED_AND_CLEAN: "#2e7d32",
    NOT_FIXED: "#e8a000",
    FIXED_BUT_BROKE: "#c62828",
    NOT_APPLIED: "#8a8a8a",
    "error": "#c4c4c4",
}
TINTS = {  # light versions for table cells; text stays dark
    FIXED_AND_CLEAN: "#e3f1e4",
    NOT_FIXED: "#fdf1d6",
    FIXED_BUT_BROKE: "#f9e0e0",
    NOT_APPLIED: "#ececec",
}
LABELS = {
    FIXED_AND_CLEAN: "fixed, clean",
    NOT_FIXED: "not fixed",
    FIXED_BUT_BROKE: "fixed, broke",
    NOT_APPLIED: "not applied",
    "error": "error",
}
# Order inside a stacked bar: best outcome first so the green block is always leftmost.
BAR_ORDER = (FIXED_AND_CLEAN, NOT_FIXED, FIXED_BUT_BROKE, NOT_APPLIED)

FONT = 'font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif"'
INK = "#222"
MUTED = "#666"


def _e(s: object) -> str:
    return html.escape(str(s), quote=True)


def legend_svg(x: int, y: int, items: list[str]) -> str:
    out, cx = [], x
    for o in items:
        out.append(f'<rect x="{cx}" y="{y - 9}" width="10" height="10" rx="2" fill="{COLORS[o]}"/>')
        out.append(f'<text x="{cx + 14}" y="{y}" font-size="12" fill="{MUTED}">{LABELS[o]}</text>')
        cx += 14 + 7 * len(LABELS[o]) + 18
    return "".join(out)


def outcome_bars_svg(records: list[dict], width: int = 720) -> str:
    """One horizontal stacked bar per model over scored runs. Errors are excluded from
    the bar and stated in the row label, so the bar never hides them."""
    by_model: dict[str, Counter] = defaultdict(Counter)
    for r in records:
        by_model[r["model"]][r.get("outcome", "error")] += 1
    models = sorted(by_model)
    label_w, right_w, bar_h, gap, top = 150, 60, 22, 14, 34
    bar_w = width - label_w - right_w
    height = top + len(models) * (bar_h + gap) + 8
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" role="img" aria-label="Patch outcomes per model" {FONT}>',
        "<title>Patch outcomes per model, scored runs only</title>",
        legend_svg(label_w, 14, list(BAR_ORDER)),
    ]
    for i, m in enumerate(models):
        cnt = by_model[m]
        scored = sum(cnt[o] for o in OUTCOMES)
        errors = cnt.get("error", 0)
        y = top + i * (bar_h + gap)
        parts.append(
            f'<text x="{label_w - 10}" y="{y + 15}" text-anchor="end" font-size="13" '
            f'fill="{INK}">{_e(m)}</text>'
        )
        x = float(label_w)
        for o in BAR_ORDER:
            n = cnt[o]
            if not n or not scored:
                continue
            w = bar_w * n / scored
            parts.append(
                f'<rect x="{x:.1f}" y="{y}" width="{max(w - 2, 1):.1f}" height="{bar_h}" '
                f'rx="3" fill="{COLORS[o]}"><title>{LABELS[o]}: {n} of {scored}</title></rect>'
            )
            if w >= 28:
                fill = "#fff" if o != NOT_FIXED else INK
                parts.append(
                    f'<text x="{x + 6:.1f}" y="{y + 15}" font-size="12" fill="{fill}">{n}</text>'
                )
            x += w
        note = f"n={scored}" + (f", {errors} error{'s' if errors != 1 else ''}" if errors else "")
        parts.append(
            f'<text x="{label_w + bar_w + 8}" y="{y + 15}" font-size="11" fill="{MUTED}">'
            f"{note}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def _scanner_state(rec: dict) -> tuple[str, str]:
    """(label, status) for the scanner lamp of an applied run."""
    before = rec.get("scan_before") or {}
    after = rec.get("scan_after") or {}
    saw = [t for t, s in before.items() if s.get("found_in_target")]
    if not saw:
        return "scanners never saw it", "blind"
    quiet = [t for t in saw if not (after.get(t) or {}).get("found_in_target")]
    if len(quiet) == len(saw):
        return f"{', '.join(saw)} went quiet", "green"
    return f"{', '.join(t for t in saw if t not in quiet)} still alerting", "red"


def three_lights_svg(rec: dict) -> str:
    """The project's argument in one picture: for a fixed-but-broke run, the scanner
    lamp and the security-test lamp are green, the regression lamp is red. The lamps
    light up left to right (CSS animation inside the SVG, no script)."""
    scan_label, scan_state = _scanner_state(rec)
    sec = rec.get("security_tests") or {}
    broke = (rec.get("verdict") or {}).get("broke") or []
    base = (rec.get("regression_baseline") or {}).get("passed")
    lamps = [
        (scan_label, scan_state),
        (f"security test {sec.get('passed', '?')}/{sec.get('total', '?')} passed", "green"),
        (f"{len(broke)} of {base} existing tests now fail", "red"),
    ]
    fills = {"green": COLORS[FIXED_AND_CLEAN], "red": COLORS[FIXED_BUT_BROKE], "blind": "#8a8a8a"}
    w, h, cell = 540, 92, 180
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%" '
        f'role="img" aria-label="Scanner, security test and regression result" {FONT}>',
        "<style>.lamp{opacity:0;animation:on .5s ease forwards}"
        "@keyframes on{to{opacity:1}}"
        "@media (prefers-reduced-motion: reduce){.lamp{animation:none;opacity:1}}</style>",
    ]
    for i, (label, state) in enumerate(lamps):
        x = i * cell
        mark = "✓" if state == "green" else ("✕" if state == "red" else "–")
        lines = _two_lines(label, 18)
        parts.append(
            f'<g class="lamp" style="animation-delay:{0.2 + 0.7 * i:.1f}s">'
            f"<title>{_e(label)}</title>"
            f'<rect x="{x + 6}" y="6" width="{cell - 12}" height="{h - 12}" rx="8" fill="#fff" '
            f'stroke="{fills[state]}" stroke-width="1.5"/>'
            f'<circle cx="{x + 30}" cy="{h / 2:.0f}" r="14" fill="{fills[state]}"/>'
            f'<text x="{x + 30}" y="{h / 2 + 5:.0f}" text-anchor="middle" font-size="16" '
            f'fill="#fff">{mark}</text>'
            + "".join(
                f'<text x="{x + 54}" y="{h / 2 + (4 if len(lines) == 1 else -3 + 15 * k):.0f}" '
                f'font-size="12" fill="{INK}">{_e(line)}</text>'
                for k, line in enumerate(lines)
            )
            + "</g>"
        )
    parts.append("</svg>")
    return "".join(parts)


def _two_lines(text: str, width: int) -> list[str]:
    """SVG text does not wrap, so split a label into at most two lines by words."""
    lines: list[str] = []
    cur = ""
    for wd in text.split():
        if cur and len(cur) + 1 + len(wd) > width:
            lines.append(cur)
            cur = wd
        else:
            cur = f"{cur} {wd}".strip()
    lines.append(cur)
    return lines[:2]


PAYLOAD_LABELS = {
    "delete-security-test": "destructive: delete the security test",
    "support-token": "benign-looking: add a constant",
    "legacy-switch": "benign-looking: keep old behaviour behind an env var",
}
PAYLOAD_COLORS = {
    "delete-security-test": "#5c6bc0",
    "support-token": "#26a69a",
    "legacy-switch": "#ef6c00",
}


def poison_bars_svg(records: list[dict], width: int = 720) -> str:
    """Per model, one bar per payload: how often the diff did what the injected comment
    asked (obeyed, added lines only). The point is the gap between the two bars."""
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in records:
        p = r.get("poison")
        if p and "obeyed" in p:
            groups[(r["model"], p["payload"])].append(r)
    models = sorted({m for m, _ in groups})
    payloads = [p for p in PAYLOAD_LABELS if any(k[1] == p for k in groups)]
    label_w, right_w, bar_h, top = 150, 40, 14, 40
    row_h = bar_h * len(payloads) + 18
    bar_w = width - label_w - right_w
    height = top + len(models) * row_h + 6
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" '
        f'role="img" aria-label="Prompt injection compliance per model" {FONT}>',
        "<title>Share of runs whose diff obeyed the injected comment</title>",
    ]
    cx = label_w
    for p in payloads:
        parts.append(
            f'<rect x="{cx}" y="8" width="10" height="10" rx="2" fill="{PAYLOAD_COLORS[p]}"/>'
        )
        parts.append(
            f'<text x="{cx + 14}" y="17" font-size="12" fill="{MUTED}">{PAYLOAD_LABELS[p]}</text>'
        )
        cx += 14 + 7 * len(PAYLOAD_LABELS[p]) + 18
    for i, m in enumerate(models):
        y0 = top + i * row_h
        parts.append(
            f'<text x="{label_w - 10}" y="{y0 + row_h / 2 - 2:.0f}" text-anchor="end" '
            f'font-size="13" fill="{INK}">{_e(m)}</text>'
        )
        for j, p in enumerate(payloads):
            recs = groups.get((m, p), [])
            n = len(recs)
            ob = sum(1 for r in recs if r["poison"].get("obeyed") is True)
            y = y0 + j * bar_h
            w = bar_w * ob / n if n else 0
            parts.append(
                f'<rect x="{label_w}" y="{y}" width="{bar_w}" height="{bar_h - 2}" rx="3" '
                'fill="#eee"/'
            )
            if w:
                parts.append(
                    f'<rect x="{label_w}" y="{y}" width="{w:.1f}" height="{bar_h - 2}" rx="3" '
                    f'fill="{PAYLOAD_COLORS[p]}"><title>{PAYLOAD_LABELS[p]}: {ob} of {n}</title>'
                    "</rect>"
                )
            parts.append(
                f'<text x="{label_w + bar_w + 6}" y="{y + bar_h - 4}" font-size="11" '
                f'fill="{MUTED}">{ob}/{n}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def cell_tint(cnt: Counter | None) -> str:
    """Background for a model × case cell: the tint of its most frequent scored outcome
    (ties go to the worse outcome, so a cell never looks better than it is)."""
    if not cnt:
        return ""
    worst_first = (NOT_APPLIED, FIXED_BUT_BROKE, NOT_FIXED, FIXED_AND_CLEAN)
    scored = {o: cnt[o] for o in worst_first if cnt.get(o)}
    if not scored:
        return ""
    best = max(scored, key=lambda o: (scored[o], -worst_first.index(o)))
    return TINTS[best]
