"""Step 2 of the pipeline: build the prompt for one case and turn the model's reply
into a change in repo/.

Prompt v1 ("small", ARCHITECTURE §7): the model sees the advisory plus only the
function or class that CVE-Bench's locate.md names. Scanner alerts arrive as
file:line, so this is the amount of context a real patch bot would have.
Prompt v2 (whole file + tests) is a later experiment, not implemented here.

What this module deliberately does NOT do: run tests, classify outcomes, call the
model. Those live in setup_case.py, verify.py (later) and llm.py.
"""

from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from harness.setup_case import Case, HarnessError

# v1.0 showed the snippet with a line-number gutter; v1.1 shows it verbatim.
PROMPT_VERSION = "v1.1-snippet"


# --- locate.md -> what to show the model ---------------------------------------------


@dataclass(frozen=True)
class Target:
    """The code location CVE-Bench points at, e.g. File.__init__ in multipart.py."""

    file: str  # path relative to the repo root
    qualname: str  # "File.__init__", "InfoExtractor._get_netrc_login_info", "KeyCache"


_LOCATE_FIELD = re.compile(r"^\s*(File|Function|Class|Method):\s*(\S+)\s*$", re.MULTILINE)


def parse_locate(text: str) -> Target:
    """Read the `File:` / `Function:` / `Class:` / `Method:` lines of locate.md.

    Seen shapes in the first five cases:
        File + Function: File.__init__            -> qualname File.__init__
        File + Class: JustHTML + Method: __init__ -> qualname JustHTML.__init__
        File + Class: KeyCache                    -> qualname KeyCache
    """
    fields = {k: v for k, v in _LOCATE_FIELD.findall(text)}
    file = fields.get("File")
    if not file:
        raise HarnessError("locate.md has no `File:` line")

    if "Function" in fields:
        qualname = fields["Function"]
    elif "Class" in fields and "Method" in fields:
        qualname = f"{fields['Class']}.{fields['Method']}"
    elif "Method" in fields:  # "Method: Class.method" with no separate Class line
        qualname = fields["Method"]
    elif "Class" in fields:
        qualname = fields["Class"]
    else:
        raise HarnessError("locate.md names a file but no function, class or method")
    return Target(file=file, qualname=qualname)


@dataclass(frozen=True)
class Snippet:
    """A contiguous region of one source file, 1-indexed and inclusive."""

    path: Path
    start_line: int
    end_line: int
    text: str


def _find_node(tree: ast.Module, qualname: str) -> ast.AST | None:
    """Walk ClassDef/FunctionDef bodies following a dotted name."""
    scope: list[ast.stmt] = tree.body
    node: ast.AST | None = None
    for part in qualname.split("."):
        node = next(
            (
                n
                for n in scope
                if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == part
            ),
            None,
        )
        if node is None:
            return None
        scope = getattr(node, "body", [])
    return node


def extract_snippet(repo_dir: Path, target: Target) -> Snippet:
    """Cut the named function/class (decorators included) out of the vulnerable file."""
    path = repo_dir / target.file
    if not path.is_file():
        raise HarnessError(f"locate.md points at {target.file}, which is not in the repo")

    source = path.read_text()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise HarnessError(f"{target.file} does not parse: {exc}") from exc

    node = _find_node(tree, target.qualname)
    if node is None:
        raise HarnessError(f"{target.qualname} not found in {target.file}")

    decorators = getattr(node, "decorator_list", [])
    start = min([node.lineno, *[d.lineno for d in decorators]])
    end = node.end_lineno or node.lineno
    lines = source.splitlines()
    return Snippet(
        path=path,
        start_line=start,
        end_line=end,
        text="\n".join(lines[start - 1 : end]),
    )


def load_target(case: Case) -> tuple[str, Target, Snippet]:
    """Everything prompt v1 needs for a case: advisory text, target, code snippet."""
    advisory_path = case.task_dir / "advisory.md"
    locate_path = case.task_dir / "locate.md"
    for p in (advisory_path, locate_path):
        if not p.is_file():
            raise HarnessError(f"{p.name} missing for {case.id}")
    target = parse_locate(locate_path.read_text())
    snippet = extract_snippet(case.repo_dir, target)
    return advisory_path.read_text(), target, snippet


# --- prompt ------------------------------------------------------------------------

SYSTEM_PROMPT_V1 = (
    "You are a security engineer fixing a reported vulnerability in a Python library. "
    "You will receive the public advisory and the exact function or class it concerns. "
    "Fix the vulnerability in that code. Do not weaken, skip or delete tests. "
    "Keep existing behaviour for non-malicious input."
)


def build_prompt_v1(advisory: str, target: Target, snippet: Snippet) -> tuple[str, str]:
    """Return (system, user) messages for prompt v1.

    The code is shown verbatim (no line-number gutter: the first Ollama run copied the
    gutter into its diff). The line range is stated once in the Location section so
    the model can write correct hunk headers.
    """
    user = (
        f"## Advisory\n\n{advisory.strip()}\n\n"
        f"## Location\n\nFile: `{target.file}`\nTarget: `{target.qualname}`\n"
        f"The code below is lines {snippet.start_line}-{snippet.end_line} of that file, "
        f"shown exactly as in the repository.\n\n"
        f"## Current code\n\n```python\n{snippet.text}\n```\n\n"
        f"{OUTPUT_CONTRACT_V1.format(file=target.file)}"
    )
    return SYSTEM_PROMPT_V1, user


# Decision (2026-10-17, see decision log): the model returns a unified diff and the
# harness applies it with `git apply`, because that is what a patch bot would open a
# PR with. The cost is that some "did not apply" outcomes are diff-formatting errors
# rather than wrong fixes, so apply_reply() records WHY a patch did not apply.
OUTPUT_CONTRACT_V1 = (
    "## Output\n\n"
    "Reply with ONE unified diff and nothing else, inside a ```diff code fence. "
    "Paths are relative to the repository root with the usual a/ and b/ prefixes "
    "(for example `--- a/{file}` / `+++ b/{file}`). Every hunk header must carry real "
    "line numbers, like `@@ -376,4 +376,6 @@`. Context lines must match the file "
    "exactly. The diff must apply cleanly with `git apply` from the repository root. "
    "Do not add explanations before or after it."
)


# --- model reply -> change in repo/ -------------------------------------------------

_DIFF_FENCE = re.compile(r"```(?:diff|patch)?\s*\n(.*?)```", re.DOTALL)
_DIFF_START = re.compile(r"^(diff --git |--- (?:a/|/dev/null))", re.MULTILINE)
_TEST_PATH = re.compile(r"(^|/)(tests?|testing)(/|$)|(^|/)test_[^/]*\.py$|_test\.py$")


def extract_diff(reply: str) -> str | None:
    """Pull the unified diff out of a model reply, or None if there is none.

    Prefers a fenced block; otherwise takes everything from the first diff header
    to the end. Returns the text with a trailing newline (git apply needs it).
    """
    candidates = [m.group(1) for m in _DIFF_FENCE.finditer(reply)] or [reply]
    for text in candidates:
        m = _DIFF_START.search(text)
        if m:
            return text[m.start() :].rstrip("\n") + "\n"
    return None


def patched_files(diff: str) -> list[str]:
    """Paths a diff touches, taken from its `+++ b/...` lines."""
    return [m.group(1) for m in re.finditer(r"^\+\+\+ b/(\S+)", diff, re.MULTILINE)]


@dataclass
class ApplyResult:
    applied: bool
    reason: str  # "" when applied; else "no-diff-in-reply" or "git-apply-failed"
    detail: str  # git's stderr when it refused the patch
    diff: str | None
    files: list[str]
    touches_tests: bool
    # Only meaningful when reason == "git-apply-failed": would `--ignore-whitespace`
    # have accepted it? Recorded, never used for the outcome (strict apply is the
    # measurement), so the "formatting vs wrong fix" split exists without a rerun.
    would_apply_ignoring_whitespace: bool = False

    @property
    def outcome(self) -> str:
        return "applied" if self.applied else "not-applied"


def apply_reply(case: Case, reply: str, patch_path: Path) -> ApplyResult:
    """Save the model's diff to patch_path and try to apply it in case.repo_dir.

    `--recount` lets git recompute the line counts in each `@@` header, the one part
    of a diff that language models most often get wrong; context lines and paths are
    still matched strictly. Nothing else is relaxed.
    """
    diff = extract_diff(reply)
    if diff is None:
        patch_path.write_text(reply)  # keep the raw reply for the post-mortem
        return ApplyResult(False, "no-diff-in-reply", "", None, [], False)

    patch_path.write_text(diff)
    files = patched_files(diff)
    touches_tests = any(_TEST_PATH.search(f) for f in files)

    result = subprocess.run(
        ["git", "apply", "--recount", str(patch_path)],
        cwd=case.repo_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        lenient = subprocess.run(
            ["git", "apply", "--check", "--recount", "--ignore-whitespace", str(patch_path)],
            cwd=case.repo_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        return ApplyResult(
            False,
            "git-apply-failed",
            result.stderr.strip(),
            diff,
            files,
            touches_tests,
            would_apply_ignoring_whitespace=lenient.returncode == 0,
        )
    return ApplyResult(True, "", "", diff, files, touches_tests)
