"""patch-bot (ARCHITECTURE §6, features 10 and 12): turn a gate decision into the PR or
issue a bot would open, and show it before anything touches GitHub.

    python -m harness.patchbot runs/<run_id>/record.json            # dry run: print it
    python -m harness.patchbot runs/<run_id>/record.json --out p.md  # dry run: save it
    python -m harness.patchbot ... --apply --repo owner/name         # really open it (gh)

Decision -> action (decision log 2026-10-21, option D; auto-merge is never on):
    block   -> an issue: the evidence, no branch, no PR
    review  -> a PR labelled needs-human-review
    allow   -> a PR with no label (a human still merges it)

The body is built only from the run record, the diff and the gate's reasons, so every
sentence in it can be traced to a file under runs/. Nothing here re-judges a patch.

What is NOT here yet: creating the branch with the patch applied inside the target
project's fork. That is phase 3 work and needs the fork to exist; until then --apply
can open issues (no branch needed) and refuses to open PRs.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from harness.gate import ALLOW, BLOCK, REVIEW, Decision, decide_run_dir, load_records

DIFF_LIMIT = 12_000  # characters of the diff embedded in a body
REVIEW_LABEL = "needs-human-review"


@dataclass
class Proposal:
    kind: str  # "pr" or "issue"
    title: str
    body: str
    labels: list[str] = field(default_factory=list)
    branch: str | None = None  # the branch a PR would come from (not created here)

    def as_record(self) -> dict:
        return {
            "kind": self.kind,
            "title": self.title,
            "labels": self.labels,
            "branch": self.branch,
            "body": self.body,
        }


def _outcome_lines(record: dict) -> list[str]:
    sec = record.get("security_tests") or {}
    base = record.get("regression_baseline") or {}
    after = record.get("regression_after") or {}
    verdict = record.get("verdict") or {}
    lines = [f"- Outcome: **{record.get('outcome')}**"]
    ap = record.get("apply") or {}
    if ap:
        lines.append(
            "- Diff applied: " + ("yes" if ap.get("applied") else f"no ({ap.get('reason')})")
        )
    if sec:
        lines.append(f"- Security test: {sec.get('passed')}/{sec.get('total')} passed")
    if base and after:
        lines.append(
            f"- Existing tests: {base.get('passed')} passed before the patch, "
            f"{after.get('passed')} after"
        )
    broke = verdict.get("broke") or []
    if broke:
        shown = ", ".join(f"`{t}`" for t in broke[:5]) + (" …" if len(broke) > 5 else "")
        lines.append(f"- Broke {len(broke)} previously passing test(s): {shown}")
    return lines


def build_proposal(record: dict, decision: Decision, diff: str | None) -> Proposal:
    """The PR or issue for one run. Pure: no I/O."""
    case, model, project = record.get("case"), record.get("model"), record.get("project")
    kind = "issue" if decision.decision == BLOCK else "pr"
    verb = {BLOCK: "blocked", REVIEW: "needs human review", ALLOW: "proposed"}[decision.decision]
    title = f"[mergeworthy] {case}: AI patch from {model} {verb}"
    labels = [REVIEW_LABEL] if decision.decision == REVIEW else []
    branch = None if kind == "issue" else f"mergeworthy/{case}/{model}".replace(":", "-")

    body = [
        f"Automated patch for **{case}** in `{project}`, written by `{model}` "
        f"(prompt `{record.get('prompt_version')}`), judged by the mergeworthy harness.",
        "",
        "## Gate decision",
        "",
        f"**{decision.decision}** — " + decision.reasons[0],
    ]
    for r in decision.reasons[1:]:
        body.append(f"- {r}")
    body += ["", "## Evidence", ""] + _outcome_lines(record)
    if decision.unrelated_symbols:
        body.append(
            "- New symbols the advisory never mentions (recorded, not judged): "
            + ", ".join(f"`{s}`" for s in decision.unrelated_symbols)
        )
    if decision.env_reads:
        body.append(
            "- New environment-variable reads (recorded, not judged): "
            + "; ".join(f"`{s}`" for s in decision.env_reads)
        )
    if decision.history:
        body.append(
            f"- Earlier runs of `{model}` on this project that were not fixed or broke "
            f"something: {len(decision.history)} (see runs/)"
        )
    body += [
        "",
        f"Run folder: `{record.get('run_id')}` (prompt, reply, diff and test reports).",
        "",
    ]
    if diff:
        shown = diff if len(diff) <= DIFF_LIMIT else diff[:DIFF_LIMIT] + "\n… [truncated]\n"
        body += ["## Diff", "", "```diff", shown.rstrip("\n"), "```", ""]
    body.append(
        "_Auto-merge is never enabled. A human merges or closes this; "
        "the gate only decides what to open._"
    )
    return Proposal(kind=kind, title=title, body="\n".join(body), labels=labels, branch=branch)


def propose_for_run(run_dir: Path, records: list[dict] | None = None) -> tuple[Decision, Proposal]:
    record = json.loads((run_dir / "record.json").read_text())
    if records is None:
        records = load_records(run_dir.parent)
    decision = decide_run_dir(run_dir, records)
    patch = run_dir / "model.patch"
    diff = (
        patch.read_text() if patch.is_file() and (record.get("apply") or {}).get("files") else None
    )
    return decision, build_proposal(record, decision, diff)


# --- the only part that touches GitHub ----------------------------------------------


def gh_create(proposal: Proposal, repo: str, runner=subprocess.run) -> str:
    """Open the issue with the gh CLI and return its URL. PRs are refused until the
    phase-3 fork exists: a PR needs a branch with the patch applied in the target repo,
    and this module does not create branches yet."""
    if proposal.kind != "issue":
        raise RuntimeError(
            "opening PRs is not implemented yet (needs the phase-3 fork and a branch); "
            "run without --apply to see the PR text"
        )
    cmd = [
        "gh",
        "issue",
        "create",
        "--repo",
        repo,
        "--title",
        proposal.title,
        "--body",
        proposal.body,
    ]
    for label in proposal.labels:
        cmd += ["--label", label]
    result = runner(cmd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("record", help="path to a run's record.json")
    parser.add_argument("--out", type=Path, help="write the proposal as markdown here")
    parser.add_argument("--json", action="store_true", help="print the proposal as JSON")
    parser.add_argument("--apply", action="store_true", help="really open it on GitHub with gh")
    parser.add_argument("--repo", help="owner/name for --apply")
    args = parser.parse_args(argv)
    if args.apply and not args.repo:
        parser.error("--apply needs --repo owner/name")

    run_dir = Path(args.record).resolve().parent
    decision, proposal = propose_for_run(run_dir)
    if args.json:
        print(
            json.dumps(
                {"decision": decision.as_record(), "proposal": proposal.as_record()}, indent=2
            )
        )
    else:
        head = f"{proposal.kind.upper()} ({decision.decision})"
        if proposal.labels:
            head += f" labels={proposal.labels}"
        if proposal.branch:
            head += f" branch={proposal.branch}"
        print(f"{head}\n{proposal.title}\n\n{proposal.body}")
    if args.out:
        args.out.write_text(f"# {proposal.title}\n\n{proposal.body}\n")
        print(f"\nwrote {args.out}", file=sys.stderr)
    if args.apply:
        url = gh_create(proposal, args.repo)
        print(f"\nopened {url}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
