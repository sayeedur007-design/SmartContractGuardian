import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from frontend_poc import app as frontend_app


VALID_SOURCE = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract InputContract {}\n"


class SolidityInputNormalizationTests(unittest.TestCase):
    def _compile(self, source):
        with tempfile.TemporaryDirectory() as temporary_directory:
            contract_path = Path(temporary_directory) / "InputContract.sol"
            contract_path.write_text(source, encoding="utf-8", newline="")
            return subprocess.run(
                [shutil.which("solc"), "--bin", str(contract_path)],
                capture_output=True,
                text=True,
                check=False,
            )

    @unittest.skipUnless(shutil.which("solc"), "solc is required for compiler regression checks")
    def test_raw_spdx_source_is_preserved_and_compiles(self):
        normalized = frontend_app._normalize_uploaded_solidity(VALID_SOURCE)

        self.assertEqual(normalized, VALID_SOURCE)
        self.assertEqual(self._compile(normalized).returncode, 0)

    @unittest.skipUnless(shutil.which("solc"), "solc is required for compiler regression checks")
    def test_complete_solidity_markdown_fence_is_unwrapped_and_compiles(self):
        normalized = frontend_app._normalize_uploaded_solidity(f"```solidity\n{VALID_SOURCE}```\n")

        self.assertEqual(normalized, VALID_SOURCE.rstrip("\n"))
        self.assertEqual(self._compile(normalized).returncode, 0)

    @unittest.skipUnless(shutil.which("solc"), "solc is required for compiler regression checks")
    def test_bom_and_leading_whitespace_are_accepted(self):
        normalized = frontend_app._normalize_uploaded_solidity(" \n\t\ufeff" + VALID_SOURCE)

        self.assertNotIn("\ufeff", normalized)
        self.assertEqual(self._compile(normalized).returncode, 0)

    @unittest.skipUnless(shutil.which("solc"), "solc is required for compiler regression checks")
    def test_invalid_source_is_not_rewritten_and_reports_compiler_location(self):
        invalid_source = "this is not Solidity;\n"
        normalized = frontend_app._normalize_uploaded_solidity(invalid_source)
        completed = self._compile(normalized)

        self.assertEqual(normalized, invalid_source)
        self.assertNotEqual(completed.returncode, 0)
        self.assertRegex(completed.stderr, r":1:\d+:")
        self.assertIn("Error", completed.stderr)

    def test_upload_retains_original_source_for_diagnostics(self):
        wrapped_source = f"```solidity\n{VALID_SOURCE}```\n"
        with tempfile.TemporaryDirectory() as temporary_directory:
            with patch.object(frontend_app, "UPLOAD_FOLDER", temporary_directory):
                response = frontend_app.app.test_client().post(
                    "/api/upload-contract",
                    data={"file": (io.BytesIO(wrapped_source.encode("utf-8")), "InputContract.sol")},
                    content_type="multipart/form-data",
                )

                self.assertEqual(response.status_code, 200)
                job = frontend_app.jobs[response.get_json()["job_id"]]
                self.assertEqual(job["original_source"], wrapped_source)
                self.assertEqual(Path(job["contract_path"]).read_text(encoding="utf-8"), VALID_SOURCE.rstrip("\n"))


class BrowserStartupTests(unittest.TestCase):
    def test_root_route_remains_available(self):
        response = frontend_app.app.test_client().get("/")

        self.assertEqual(response.status_code, 200)
        response.close()

    def test_normal_startup_allows_one_browser_launch(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WERKZEUG_RUN_MAIN", None)
            self.assertTrue(frontend_app._should_open_browser())

        with patch("webbrowser.open") as browser_open:
            frontend_app.open_browser()
        browser_open.assert_called_once_with("http://localhost:3000")

    def test_reloader_child_does_not_launch_another_browser(self):
        with patch.dict(os.environ, {"WERKZEUG_RUN_MAIN": "true"}, clear=False):
            self.assertFalse(frontend_app._should_open_browser())


if __name__ == "__main__":
    unittest.main()
