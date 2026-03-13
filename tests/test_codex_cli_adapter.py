import os
import stat
import tempfile
import textwrap
import time
import unittest

from core.mcp_adapters.base import StageRequest
from core.mcp_adapters.codex_cli import CodexCLIAdapter


class CodexCliAdapterTests(unittest.TestCase):
    def _make_exe(self, path: str, content: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def test_early_abort_signature_detects_auth_failure(self):
        adapter = CodexCLIAdapter(codex_bin="codex")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
            f.write("ERROR: unexpected status 401 Unauthorized: Missing bearer or basic authentication in header\n")
            path = f.name
        try:
            self.assertEqual(adapter._early_abort_signature(path), "codex auth unavailable")
        finally:
            os.unlink(path)

    def test_run_stage_aborts_early_on_auth_failure_output(self):
        with tempfile.TemporaryDirectory() as td:
            fake_codex = self._make_exe(
                os.path.join(td, "fake_codex.py"),
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import sys
                    import time

                    print('OpenAI Codex v0.test')
                    print('mcp startup: ready: gdb, pyghidra-mcp')
                    print('Reconnecting... 1/5 (unexpected status 401 Unauthorized: Missing bearer or basic authentication in header)')
                    sys.stdout.flush()
                    time.sleep(10)
                    """
                ),
            )
            output_log = os.path.join(td, "adapter.log")
            adapter = CodexCLIAdapter(codex_bin=fake_codex, retries=0, extra_args=[])
            req = StageRequest(
                session_id="ut_auth_abort",
                stage="recon",
                prompt="reply with ok",
                timeout_sec=30,
                workdir=td,
                output_log=output_log,
            )

            started = time.monotonic()
            result = adapter.run_stage(req)
            elapsed = time.monotonic() - started

            self.assertFalse(result.ok)
            self.assertEqual(result.return_code, 125)
            self.assertIn("codex auth unavailable", result.error or "")
            self.assertLess(elapsed, 5.0)
            with open(output_log, "r", encoding="utf-8") as f:
                log_text = f.read()
            self.assertIn("early-abort signature: codex auth unavailable", log_text)


if __name__ == "__main__":
    unittest.main()
