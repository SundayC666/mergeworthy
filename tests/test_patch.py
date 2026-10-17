"""Unit tests for harness/patch.py: locate.md parsing and ast-based snippet extraction.
No CVE-Bench checkout and no model are needed."""

import subprocess
import textwrap

import pytest

from harness.patch import (
    Target,
    apply_reply,
    extract_diff,
    extract_snippet,
    parse_locate,
    patched_files,
)
from harness.setup_case import Case, HarnessError

LOCATE_FUNCTION = """\
A security vulnerability has been identified in the following location:

  File: python_multipart/multipart.py
  Function: File.__init__

Inspect the function, identify the vulnerability, and fix it.
"""

LOCATE_CLASS_METHOD = """\
  File: src/justhtml/parser.py
  Class: JustHTML
  Method: __init__
"""

LOCATE_CLASS_ONLY = """\
  File: src/scitokens/utils/keycache.py
  Class: KeyCache
"""


def test_parse_locate_function():
    assert parse_locate(LOCATE_FUNCTION) == Target("python_multipart/multipart.py", "File.__init__")


def test_parse_locate_class_and_method():
    assert parse_locate(LOCATE_CLASS_METHOD) == Target(
        "src/justhtml/parser.py", "JustHTML.__init__"
    )


def test_parse_locate_class_only():
    assert parse_locate(LOCATE_CLASS_ONLY) == Target("src/scitokens/utils/keycache.py", "KeyCache")


def test_parse_locate_without_file_fails_closed():
    with pytest.raises(HarnessError):
        parse_locate("  Function: foo\n")


SOURCE = textwrap.dedent(
    '''\
    import os

    def helper():
        return 1

    class File:
        """A class."""

        @staticmethod
        def other():
            pass

        def __init__(self, name):
            self.name = name
            self.path = os.path.join("/up", name)

    class KeyCache:
        async def fetch(self):
            return await something()
    '''
)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text(SOURCE)
    return tmp_path


def test_extract_method_inside_class(repo):
    s = extract_snippet(repo, Target("pkg/mod.py", "File.__init__"))
    assert (s.start_line, s.end_line) == (13, 15)
    assert s.text.startswith("    def __init__(self, name):")
    assert s.text.endswith('os.path.join("/up", name)')


def test_extract_includes_decorators(repo):
    s = extract_snippet(repo, Target("pkg/mod.py", "File.other"))
    assert s.start_line == 9  # the @staticmethod line, not the def line
    assert s.text.splitlines()[0].strip() == "@staticmethod"


def test_extract_whole_class(repo):
    s = extract_snippet(repo, Target("pkg/mod.py", "KeyCache"))
    assert (s.start_line, s.end_line) == (17, 19)


def test_extract_async_def(repo):
    s = extract_snippet(repo, Target("pkg/mod.py", "KeyCache.fetch"))
    assert s.start_line == 18


def test_extract_unknown_name_fails_closed(repo):
    with pytest.raises(HarnessError):
        extract_snippet(repo, Target("pkg/mod.py", "File.nope"))


def test_extract_missing_file_fails_closed(repo):
    with pytest.raises(HarnessError):
        extract_snippet(repo, Target("pkg/missing.py", "File"))


# --- reply -> diff -> git apply ------------------------------------------------------

GOOD_DIFF = """\
diff --git a/pkg/mod.py b/pkg/mod.py
--- a/pkg/mod.py
+++ b/pkg/mod.py
@@ -1,7 +1,7 @@
 import os

 def helper():
-    return 1
+    return 2

 class File:
     \"\"\"A class.\"\"\"
"""


def test_extract_diff_from_fence():
    reply = "Here is the fix:\n```diff\n" + GOOD_DIFF + "```\nHope it helps."
    assert extract_diff(reply) == GOOD_DIFF


def test_extract_diff_without_fence():
    assert extract_diff("Sure.\n" + GOOD_DIFF) == GOOD_DIFF


def test_extract_diff_none_when_only_prose():
    assert extract_diff("I cannot determine the fix from this snippet.") is None


def test_patched_files_and_test_detection():
    diff = GOOD_DIFF + "--- a/tests/test_mod.py\n+++ b/tests/test_mod.py\n"
    assert patched_files(diff) == ["pkg/mod.py", "tests/test_mod.py"]


@pytest.fixture
def git_repo(repo):
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@x",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@x",
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }
    for cmd in (["git", "init", "-q"], ["git", "add", "."], ["git", "commit", "-q", "-m", "base"]):
        subprocess.run(cmd, cwd=repo, check=True, env=env)
    return repo


@pytest.fixture
def fake_case(git_repo, tmp_path_factory):
    # Case.repo_dir is task_dir / "repo": make a task dir whose repo/ is the git repo.
    task_dir = tmp_path_factory.mktemp("task")
    (task_dir / "repo").symlink_to(git_repo)
    return Case("X", "x/y", ["CWE-1"], 1.0, "a^", "a", "t", task_dir)


def test_apply_good_diff(fake_case, tmp_path):
    r = apply_reply(fake_case, "```diff\n" + GOOD_DIFF + "```", tmp_path / "p.patch")
    assert r.applied and r.reason == ""
    assert r.files == ["pkg/mod.py"] and not r.touches_tests
    assert "return 2" in (fake_case.repo_dir / "pkg" / "mod.py").read_text()


def test_apply_recounts_wrong_hunk_header(fake_case, tmp_path):
    wrong = GOOD_DIFF.replace("@@ -1,4 +1,4 @@", "@@ -1,9 +1,9 @@")
    r = apply_reply(fake_case, wrong, tmp_path / "p.patch")
    assert r.applied


def test_apply_mismatched_context_is_rejected_with_reason(fake_case, tmp_path):
    bad = GOOD_DIFF.replace("-    return 1", "-    return 999")
    r = apply_reply(fake_case, bad, tmp_path / "p.patch")
    assert not r.applied and r.reason == "git-apply-failed"
    assert r.detail  # git explained why
    assert "return 1" in (fake_case.repo_dir / "pkg" / "mod.py").read_text()  # untouched


def test_apply_no_diff_keeps_raw_reply(fake_case, tmp_path):
    r = apply_reply(fake_case, "no idea, sorry", tmp_path / "p.patch")
    assert not r.applied and r.reason == "no-diff-in-reply"
    assert (tmp_path / "p.patch").read_text() == "no idea, sorry"


def test_apply_flags_patches_that_touch_tests(fake_case, tmp_path):
    diff = GOOD_DIFF.replace("pkg/mod.py", "tests/test_mod.py")
    r = apply_reply(fake_case, diff, tmp_path / "p.patch")
    assert r.touches_tests


def test_whitespace_only_mismatch_is_rejected_but_flagged(fake_case, tmp_path):
    # Strict apply is the measurement (a real patch bot would reject this too), but we
    # also record whether git would have accepted it with --ignore-whitespace, so the
    # "formatting vs wrong fix" split is available without rerunning anything.
    # git's --ignore-whitespace forgives indentation differences in context lines but
    # NOT trailing whitespace (checked experimentally, 2026-10-18), so the flag is a
    # narrow "indentation was off" signal, not "any whitespace".
    sloppy = GOOD_DIFF.replace('     """A class."""', '      """A class."""')  # one extra indent
    r = apply_reply(fake_case, sloppy, tmp_path / "p.patch")
    assert not r.applied and r.reason == "git-apply-failed"
    assert r.would_apply_ignoring_whitespace is True


def test_real_context_mismatch_is_not_flagged_as_whitespace(fake_case, tmp_path):
    bad = GOOD_DIFF.replace("-    return 1", "-    return 999")
    r = apply_reply(fake_case, bad, tmp_path / "p.patch")
    assert r.would_apply_ignoring_whitespace is False
