import os
import tempfile
import unittest
from unittest import mock

from core.stdin_seed_utils import display_seed_file, select_seed_input


class StdinSeedUtilsTests(unittest.TestCase):
    def test_display_seed_file_keeps_relative_input(self):
        self.assertEqual(
            display_seed_file("challenge/demo/payload.bin", root_dir="/repo"),
            "challenge/demo/payload.bin",
        )

    def test_display_seed_file_relativizes_repo_absolute_path(self):
        self.assertEqual(
            display_seed_file(
                "/repo/challenge/demo/payload.bin",
                resolved="/repo/challenge/demo/payload.bin",
                root_dir="/repo",
            ),
            "challenge/demo/payload.bin",
        )

    def test_select_seed_input_prefers_repo_relative_source_label_for_repo_absolute_env(self):
        with tempfile.TemporaryDirectory() as td:
            payload = os.path.join(td, "challenge", "demo", "payload.bin")
            os.makedirs(os.path.dirname(payload), exist_ok=True)
            with open(payload, "wb") as f:
                f.write(b"AAAA")
            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_TEST_STDIN_FILE": payload,
                },
                clear=False,
            ):
                data, source, kind, size = select_seed_input(
                    file_env="DIRGE_TEST_STDIN_FILE",
                    hex_env="DIRGE_TEST_STDIN_HEX",
                    text_env="DIRGE_TEST_STDIN_TEXT",
                    auto_len_env="DIRGE_TEST_STDIN_AUTO_LEN",
                    cyclic_factory=lambda n: b"A" * n,
                    root_dir=td,
                    error_prefix="test_stdin",
                )
            self.assertEqual(data, b"AAAA")
            self.assertEqual(source, "file:challenge/demo/payload.bin")
            self.assertEqual(kind, "seeded_file")
            self.assertEqual(size, 4)

    def test_select_seed_input_prefers_cwd_relative_seed_file_before_repo_root(self):
        with tempfile.TemporaryDirectory() as td:
            repo_payload = os.path.join(td, "challenge", "demo", "payload.bin")
            cwd = os.path.join(td, "challenge", "demo")
            os.makedirs(cwd, exist_ok=True)
            with open(repo_payload, "wb") as f:
                f.write(b"BBBB")
            cwd_before = os.getcwd()
            try:
                os.chdir(cwd)
                with mock.patch.dict(
                    os.environ,
                    {
                        "DIRGE_TEST_STDIN_FILE": "./payload.bin",
                    },
                    clear=False,
                ):
                    data, source, kind, size = select_seed_input(
                        file_env="DIRGE_TEST_STDIN_FILE",
                        hex_env="DIRGE_TEST_STDIN_HEX",
                        text_env="DIRGE_TEST_STDIN_TEXT",
                        auto_len_env="DIRGE_TEST_STDIN_AUTO_LEN",
                        cyclic_factory=lambda n: b"A" * n,
                        root_dir=td,
                        error_prefix="test_stdin",
                    )
            finally:
                os.chdir(cwd_before)
            self.assertEqual(data, b"BBBB")
            self.assertEqual(source, "file:./payload.bin")
            self.assertEqual(kind, "seeded_file")
            self.assertEqual(size, 4)

    def test_select_seed_input_can_resolve_seed_file_from_explicit_search_dir(self):
        with tempfile.TemporaryDirectory() as td:
            payload_dir = os.path.join(td, "challenge", "demo")
            payload = os.path.join(payload_dir, "payload.bin")
            os.makedirs(payload_dir, exist_ok=True)
            with open(payload, "wb") as f:
                f.write(b"CCCC")
            cwd_before = os.getcwd()
            try:
                os.chdir("/")
                with mock.patch.dict(
                    os.environ,
                    {
                        "DIRGE_TEST_STDIN_FILE": "./payload.bin",
                    },
                    clear=False,
                ):
                    data, source, kind, size = select_seed_input(
                        file_env="DIRGE_TEST_STDIN_FILE",
                        hex_env="DIRGE_TEST_STDIN_HEX",
                        text_env="DIRGE_TEST_STDIN_TEXT",
                        auto_len_env="DIRGE_TEST_STDIN_AUTO_LEN",
                        cyclic_factory=lambda n: b"A" * n,
                        root_dir=td,
                        search_dirs=[payload_dir],
                        error_prefix="test_stdin",
                    )
            finally:
                os.chdir(cwd_before)
            self.assertEqual(data, b"CCCC")
            self.assertEqual(source, "file:./payload.bin")
            self.assertEqual(kind, "seeded_file")
            self.assertEqual(size, 4)


if __name__ == "__main__":
    unittest.main()
