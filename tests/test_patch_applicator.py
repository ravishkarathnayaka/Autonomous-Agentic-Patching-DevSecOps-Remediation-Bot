"""Unit tests for PatchApplicator."""

from agent_engine.tools.patch_applicator import PatchApplicator


def test_split_multi_file_diff():
    compound_diff = """--- a/target_repo/app.py
+++ b/target_repo/app.py
@@ -28,2 +28,2 @@
-    query = f"SELECT * FROM items WHERE name = '{name}'"
+    query = "SELECT * FROM items WHERE name = ?"
--- a/target_repo/requirements.txt
+++ b/target_repo/requirements.txt
@@ -1,1 +1,1 @@
-Flask==2.2.0
+Flask==2.2.5
"""
    hunks = PatchApplicator.split_multi_file_diff(compound_diff)
    assert len(hunks) == 2
    assert hunks[0].target_file == "target_repo/app.py"
    assert "SELECT" in hunks[0].diff_text
    assert hunks[1].target_file == "target_repo/requirements.txt"
    assert "Flask==2.2.5" in hunks[1].diff_text


def test_apply_simple_substitution():
    original = "line 1\nold code block\nline 3"
    result = PatchApplicator.apply_simple_substitution(
        original,
        remove_lines=["old code block"],
        add_lines=["new secure code"]
    )
    assert "new secure code" in result
    assert "old code block" not in result
