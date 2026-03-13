import os
import shutil
import subprocess
import tempfile
import unittest


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT_DIR, "scripts", "start_session.sh")
STATE_FILE = os.path.join(ROOT_DIR, "state", "state.json")
SESSIONS_DIR = os.path.join(ROOT_DIR, "sessions")


class StartSessionTests(unittest.TestCase):
    # stable-edit-anchor: start_session repo-relative cli coverage
    def setUp(self) -> None:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            self._state_backup = f.read()
        self._created_paths: list[str] = []

    def tearDown(self) -> None:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            f.write(self._state_backup)
        for path in reversed(self._created_paths):
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            elif os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    def _make_prompt_file(self, content: str) -> tuple[str, str]:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=ROOT_DIR, suffix=".prompt", delete=False) as tf:
            tf.write(content)
            prompt_path = tf.name
        self._created_paths.append(prompt_path)
        return prompt_path, os.path.relpath(prompt_path, ROOT_DIR)

    def test_start_session_repo_anchors_challenge_dir_and_prompt_file_from_non_root_cwd(self) -> None:
        session_id = "test_start_session_repo_relative"
        session_dir = os.path.join(SESSIONS_DIR, session_id)
        self._created_paths.append(session_dir)

        _, prompt_rel = self._make_prompt_file("repo-relative prompt file works\n")

        subprocess.run(
            [
                "bash",
                SCRIPT,
                "--challenge-dir",
                "challenge/bench_local_nonpie",
                "--prompt-file",
                prompt_rel,
                "--session-id",
                session_id,
                "--no-codex",
            ],
            check=True,
            cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
            env=os.environ.copy(),
        )

        copied_prompt = os.path.join(session_dir, "prompt.txt")
        self.assertTrue(os.path.isdir(session_dir))
        self.assertTrue(os.path.isfile(copied_prompt))
        with open(copied_prompt, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "repo-relative prompt file works\n")

    def test_start_session_accepts_inline_equals_flags_from_non_root_cwd(self) -> None:
        session_id = "test_start_session_inline_equals"
        session_dir = os.path.join(SESSIONS_DIR, session_id)
        self._created_paths.append(session_dir)

        _, prompt_rel = self._make_prompt_file("inline equals prompt works\n")

        subprocess.run(
            [
                "bash",
                SCRIPT,
                "--challenge-dir=challenge/bench_local_nonpie",
                f"--prompt-file={prompt_rel}",
                f"--session-id={session_id}",
                "--no-codex",
            ],
            check=True,
            cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
            env=os.environ.copy(),
        )

        copied_prompt = os.path.join(session_dir, "prompt.txt")
        self.assertTrue(os.path.isdir(session_dir))
        self.assertTrue(os.path.isfile(copied_prompt))
        with open(copied_prompt, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "inline equals prompt works\n")

    def test_start_session_prefers_cwd_relative_prompt_file_before_repo_root(self) -> None:
        session_id = "test_start_session_cwd_relative_prompt"
        session_dir = os.path.join(SESSIONS_DIR, session_id)
        challenge_cwd = os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie")
        prompt_dir = os.path.join(challenge_cwd, "tmp_prompts")
        prompt_path = os.path.join(prompt_dir, "host_run.txt")
        self._created_paths.extend([session_dir, prompt_path, prompt_dir])
        os.makedirs(prompt_dir, exist_ok=True)
        with open(prompt_path, "w", encoding="utf-8") as f:
            f.write("cwd-relative prompt file works\n")

        subprocess.run(
            [
                "bash",
                SCRIPT,
                "--challenge-dir",
                "challenge/bench_local_nonpie",
                "--prompt-file",
                "./tmp_prompts/host_run.txt",
                "--session-id",
                session_id,
                "--no-codex",
            ],
            check=True,
            cwd=challenge_cwd,
            env=os.environ.copy(),
        )

        copied_prompt = os.path.join(session_dir, "prompt.txt")
        self.assertTrue(os.path.isdir(session_dir))
        self.assertTrue(os.path.isfile(copied_prompt))
        with open(copied_prompt, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "cwd-relative prompt file works\n")

    def test_start_session_prefers_challenge_relative_prompt_file_before_repo_root(self) -> None:
        session_id = "test_start_session_challenge_relative_prompt"
        session_dir = os.path.join(SESSIONS_DIR, session_id)
        challenge_dir = os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie")
        prompt_path = os.path.join(challenge_dir, "tmp_prompt_relative_to_challenge.txt")
        self._created_paths.extend([session_dir, prompt_path])
        with open(prompt_path, "w", encoding="utf-8") as f:
            f.write("challenge-relative prompt file works\n")

        subprocess.run(
            [
                "bash",
                SCRIPT,
                "--challenge-dir",
                "challenge/bench_local_nonpie",
                "--prompt-file",
                os.path.basename(prompt_path),
                "--session-id",
                session_id,
                "--no-codex",
            ],
            check=True,
            cwd=ROOT_DIR,
            env=os.environ.copy(),
        )

        copied_prompt = os.path.join(session_dir, "prompt.txt")
        self.assertTrue(os.path.isdir(session_dir))
        self.assertTrue(os.path.isfile(copied_prompt))
        with open(copied_prompt, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "challenge-relative prompt file works\n")

    def test_start_session_prefers_cwd_relative_challenge_dir_before_repo_root(self) -> None:
        session_id = "test_start_session_cwd_relative_challenge_dir"
        session_dir = os.path.join(SESSIONS_DIR, session_id)
        challenge_cwd = os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie")
        self._created_paths.append(session_dir)

        subprocess.run(
            [
                "bash",
                SCRIPT,
                "--challenge-dir=.",
                "--binary=chall",
                f"--session-id={session_id}",
                "--no-codex",
            ],
            check=True,
            cwd=challenge_cwd,
            env=os.environ.copy(),
        )

        meta_path = os.path.join(session_dir, "meta.json")
        self.assertTrue(os.path.isdir(session_dir))
        self.assertTrue(os.path.isfile(meta_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = f.read()
        self.assertIn('"binary_path": "challenge/bench_local_nonpie/chall"', meta)


if __name__ == "__main__":
    unittest.main()
