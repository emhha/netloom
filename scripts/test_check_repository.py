"""Offline regression coverage for the repository checker."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "check_repository", Path(__file__).with_name("check-repository.py")
)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class RepositoryChecks(unittest.TestCase):
    def fixture(self, root):
        for name in checker.REQUIRED:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        (root / "go.mod").write_text(f"module {checker.MODULE}\n")
        (root / "doc.go").write_text("package netloom\n")
        (root / "httpdata/netloomdata/convert.go").write_text("package netloomdata\n")

    def test_valid_repository_and_encoded_relative_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "space file.md").write_text("# target\n")
            (root / "README.md").write_text(
                "[doc](docs/README.md#usage) [space](<space%20file.md>) "
                "[external](https://example.invalid/missing) [anchor](#usage)\n"
                "`[sample](not-real.md)`\n```md\n[x](missing.md)\n```\n"
            )
            self.assertEqual(checker.check(root), [])

    def test_missing_and_outside_links_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "README.md").write_text("[x](absent.md) [y](../outside.md)\n")
            errors = checker.check(root)
            self.assertTrue(any("missing link target" in error for error in errors))
            self.assertTrue(any("leaves repository" in error for error in errors))

    def test_old_module_package_and_adapter_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "go.mod").write_text("module netrt.local/netrt\n")
            (root / "doc.go").write_text("package netrt\n")
            (root / "httpdata/netrtdata").mkdir()
            (root / "httpdata/netloomdata/convert.go").write_text("package wrong\n")
            errors = checker.check(root)
            for expected in ("must declare module", "obsolete Go name", "obsolete adapter", "root Go package", "adapter Go package"):
                self.assertTrue(any(expected in error for error in errors), expected)

    def test_local_domain_prefix_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "go.mod").write_text("module netloom.local/netloom\n")
            (root / "httpdata/netloomdata/convert.go").write_text(
                'package netloomdata\nimport "netloom.local/netloom"\n'
            )
            errors = checker.check(root)
            self.assertTrue(any(f"must declare module {checker.MODULE}" in error for error in errors))
            self.assertTrue(any("obsolete Go name/import" in error for error in errors))

    def test_legacy_bare_module_and_imports_rejected(self):
        for old in ("netloom", "netloom/httpdata", "netloom.local/netloom/httpdata", "netrt.local/netrt/httpdata"):
            with self.subTest(path=old), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                (root / "go.mod").write_text("module netloom\n")
                (root / "httpdata/netloomdata/convert.go").write_text(
                    f'package netloomdata\nimport legacy "{old}"\n'
                )
                errors = checker.check(root)
                self.assertTrue(any("must declare module" in error for error in errors))
                self.assertTrue(any("obsolete Go name/import" in error for error in errors))

    def test_canonical_imports_allowed_and_brand_string_not_an_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "doc.go").write_text('package netloom\nconst brand = "netloom"\n')
            (root / "httpdata/netloomdata/convert.go").write_text(
                f'package netloomdata\nimport (\n sdk "{checker.MODULE}"\n "{checker.MODULE}/httpdata"\n)\n'
            )
            self.assertEqual(checker.check(root), [])

    def test_runtime_and_snapshot_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "runtime.go").write_text(f'package netloom\nimport "{checker.MODULE}/probe"\n')
            (root / "httpdata/types.go").write_text(f'package httpdata\nimport "{checker.MODULE}"\n')
            errors = checker.check(root)
            self.assertTrue(any("root runtime must not import" in error for error in errors))
            self.assertTrue(any("neutral httpdata must not import" in error for error in errors))

    def test_reviewed_private_proxy_helper_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "runtime.go").write_text(
                f'package netloom\nimport "{checker.MODULE}/internal/proxyconfig"\n'
            )
            helper = root / "internal/proxyconfig/proxy.go"
            helper.parent.mkdir(parents=True)
            helper.write_text('package proxyconfig\nimport "net/url"\n')
            self.assertEqual(checker.check(root), [])

    def test_private_helper_exception_does_not_weaken_boundaries(self):
        for imported in ("probe", "internal/unreviewed", "internal/proxyconfig/extension"):
            with self.subTest(imported=imported), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                (root / "runtime.go").write_text(
                    f'package netloom\nimport "{checker.MODULE}/internal/proxyconfig"\n'
                    f'import "{checker.MODULE}/{imported}"\n'
                )
                self.assertTrue(any("root runtime must not import" in error for error in checker.check(root)))
        for imported in ("", "/probe", "/httpdata", "/internal/other"):
            with self.subTest(helper_import=imported), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                helper = root / "internal/proxyconfig/proxy.go"
                helper.parent.mkdir(parents=True)
                helper.write_text(f'package proxyconfig\nimport "{checker.MODULE}{imported}"\n')
                self.assertTrue(any("shared proxy validation must not import" in error for error in checker.check(root)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "httpdata/types.go").write_text(
                f'package httpdata\nimport "{checker.MODULE}/internal/proxyconfig"\n'
            )
            self.assertTrue(any("neutral httpdata must not import" in error for error in checker.check(root)))

    def test_missing_required_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            errors = checker.check(root)
            self.assertTrue(any("missing required file: Makefile" in error for error in errors))

    def test_retired_infoextract_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            usage = root / "passive/plugin_test.go"
            usage.write_text(f'package passive_test\nimport "{checker.MODULE}/passive/plugins/infoextract"\n')
            self.assertEqual(checker.check(root), [])
            (root / "infoextract").mkdir()
            usage.write_text(f'package passive_test\nimport "{checker.MODULE}/infoextract"\n')
            errors = checker.check(root)
            self.assertTrue(any("obsolete plugin directory: infoextract" in error for error in errors))
            self.assertTrue(any("obsolete infoextract import" in error for error in errors))

    def test_serialization_source_belongs_to_its_plugin_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "passive/plugins/serialization/serialization.go").write_text("package serialization\n")
            self.assertEqual(checker.check(root), [])
            (root / "passive/plugins/serialization_match.go").write_text("package plugins\n")
            errors = checker.check(root)
            self.assertTrue(any("place serialization implementation" in error for error in errors))

    def test_upstream_excluded_but_maintained_history_and_provenance_checked(self):
        for name in (
            "dirscan/wordlists/dirsearch/README.upstream.md",
            "fingerprint/rules/README.upstream.md", "fingerprint/rules/README.wappalyzergo.md",
            "fingerprint/rules/LICENSE.md",
        ):
            self.assertFalse(checker.maintained_markdown(Path(name)), name)
        for name in (
            "docs/history/design.md", "docs/provenance/upstream-origin.md",
            "docs/provenance/README.md", "fingerprint/rules/README.md",
        ):
            self.assertTrue(checker.maintained_markdown(Path(name)), name)

    def test_history_and_provenance_links_checked(self):
        for name in ("docs/history/design.md", "docs/provenance/upstream-origin.md"):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("[missing](missing.md)\n")
                self.assertTrue(any("missing link target" in error for error in checker.check(root)))

    def test_private_deployment_urls_and_workspace_paths_rejected(self):
        for content, expected in (
            ("```sh\ncurl https://10.0.0.1:8443/api\n```\n", "private deployment URL"),
            ("`http://127.0.0.1:8443/`\n", "private deployment URL"),
            ("`/home/developer/project`\n", "per-user absolute workspace path"),
            ("`/Users/developer/project`\n", "per-user absolute workspace path"),
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                (root / "docs/provenance/README.md").write_text(content)
                self.assertTrue(any(expected in error for error in checker.check(root)))

    def test_public_resource_links_and_reserved_examples_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            (root / "README.md").write_text(
                "[source](https://github.com/example/resource)\n"
                "`https://service.example.com/api` `https://192.0.2.1/api`\n"
                "`https://198.51.100.1/api` `https://203.0.113.1/api`\n"
            )
            self.assertEqual(checker.check(root), [])


if __name__ == "__main__":
    unittest.main()
