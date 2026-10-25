"""Offline regression tests for Git-pinned wordlist updates."""

import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("update-dirsearch-wordlists.py")
SPEC = importlib.util.spec_from_file_location("wordlist_sync", SCRIPT)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.repo = base / "source"
        self.repo.mkdir()
        self.git("init", "--quiet")
        (self.repo / "db/categories").mkdir(parents=True)
        (self.repo / "db/categories/common.txt").write_text("admin\n", encoding="utf-8")
        (self.repo / "README.md").write_text("Upstream attribution\n", encoding="utf-8")
        (self.repo / "pyproject.toml").write_text('license = "GPL-2.0-only"\n', encoding="utf-8")
        self.first = self.commit()
        self.destination = base / "vendor/snapshot"
        self.override = patch.object(sync, "DESTINATION", self.destination)
        self.override.start()
        self.addCleanup(self.override.stop)

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout.decode().strip()

    def commit(self):
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--quiet", "-m", "fixture")
        return self.git("rev-parse", "HEAD")

    def update(self, ref=None):
        args = [str(SCRIPT), "--source", str(self.repo)]
        if ref:
            args += ["--ref", ref]
        with patch("sys.argv", args), redirect_stdout(io.StringIO()):
            sync.main()

    def test_export_uses_commit_and_default_stays_pinned(self):
        (self.repo / "db/categories/common.txt").write_text("dirty\n", encoding="utf-8")
        self.update(self.first)
        self.assertEqual((self.destination / "db/categories/common.txt").read_text(), "admin\n")
        self.commit()
        self.update()
        self.assertEqual(sync.check(self.destination)["commit"], self.first)

    def test_update_removes_deleted_upstream_files(self):
        self.update(self.first)
        (self.repo / "db/categories/common.txt").unlink()
        (self.repo / "db/dicc.txt").write_text("login\n", encoding="utf-8")
        second = self.commit()
        self.update(second)
        self.assertFalse((self.destination / "db/categories/common.txt").exists())
        self.assertEqual((self.destination / "db/dicc.txt").read_text(), "login\n")
        self.assertEqual(sync.check(self.destination)["commit"], second)

    def test_local_edits_are_not_overwritten(self):
        self.update(self.first)
        path = self.destination / "db/categories/common.txt"
        path.write_text("local changes\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "snapshot differs"):
            self.update(self.first)
        self.assertEqual(path.read_text(), "local changes\n")

    def test_bad_ref_keeps_existing_snapshot(self):
        self.update(self.first)
        before = sync.check(self.destination)
        with self.assertRaises(subprocess.CalledProcessError):
            self.update("nonexistent-ref")
        self.assertEqual(sync.check(self.destination), before)

    def test_upstream_symlink_is_rejected_without_replacing_snapshot(self):
        self.update(self.first)
        before = sync.check(self.destination)
        (self.repo / "db/escape").symlink_to("/etc/passwd")
        second = self.commit()
        with self.assertRaisesRegex(ValueError, "unsupported Git entry"):
            self.update(second)
        self.assertEqual(sync.check(self.destination), before)


if __name__ == "__main__":
    unittest.main()
