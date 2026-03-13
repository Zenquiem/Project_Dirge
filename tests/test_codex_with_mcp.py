import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WRAPPER = os.path.join(ROOT_DIR, "scripts", "codex_with_mcp.sh")


class CodexWithMcpTests(unittest.TestCase):
    # Stable edit anchor: wrapper/runtime portability tests live in this class.
    # Keep nearby test names/ordering relatively stable so isolated iteration
    # runs can patch focused cases without large-context rewrites.
    def _make_exe(self, path: str, content: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def _run_wrapper(
        self,
        extra_env: dict[str, str],
        *,
        set_codex_bin_real: bool = True,
        cwd: str | None = None,
        include_system_path: bool = True,
        inject_path_codex_when_unset: bool = True,
        inject_path_pyghidra: bool = True,
        expect_capture: bool = True,
        capture_env_keys: list[str] | None = None,
        subcommand: str = "exec",
        extra_args: list[str] | None = None,
    ) -> list[str] | dict[str, str]:
        with tempfile.TemporaryDirectory() as td:
            capture_path = os.path.join(td, "argv.json")
            env_capture_path = os.path.join(td, "env.json")
            capture_env_keys = list(capture_env_keys or [])
            fake_codex = self._make_exe(
                os.path.join(td, "fake_codex.py"),
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env python3
                    import json, os, sys
                    with open({capture_path!r}, 'w', encoding='utf-8') as f:
                        json.dump(sys.argv[1:], f, ensure_ascii=False)
                    capture_env_keys = {capture_env_keys!r}
                    if capture_env_keys:
                        payload = {{key: os.environ.get(key, "") for key in capture_env_keys}}
                        with open({env_capture_path!r}, 'w', encoding='utf-8') as f:
                            json.dump(payload, f, ensure_ascii=False)
                    """
                ),
            )
            fake_ghidra = self._make_exe(os.path.join(td, "fake_pyghidra_mcp"), "#!/usr/bin/env bash\nexit 0\n")
            if inject_path_pyghidra:
                self._make_exe(os.path.join(td, "pyghidra-mcp"), "#!/usr/bin/env bash\nexit 0\n")
            ghidra_dir = os.path.join(td, "ghidra")
            os.makedirs(os.path.join(ghidra_dir, "support"), exist_ok=True)
            self._make_exe(os.path.join(ghidra_dir, "support", "analyzeHeadless"), "#!/usr/bin/env bash\nexit 0\n")

            env = os.environ.copy()
            env.update(
                {
                    "GHIDRA_MCP_BIN": fake_ghidra,
                    "GHIDRA_INSTALL_DIR": ghidra_dir,
                    "CODEX_HOME": os.path.join(td, "codex-home"),
                    "CODEX_RUNTIME_HOME": os.path.join(td, "codex-runtime"),
                    "GHIDRA_RUNTIME_ROOT": os.path.join(td, "ghidra-runtime"),
                    "MCP_JSONLINE_BRIDGE_LOG": os.path.join(td, "bridge.log"),
                    "DIRGE_SESSION_ID": "test-session",
                    "OPENAI_API_KEY": "unit-test-key",
                    "PATH": f"{td}:{os.environ.get('PATH', '')}" if include_system_path else f"{td}:/usr/bin:/bin",
                }
            )
            if set_codex_bin_real:
                env["CODEX_BIN_REAL"] = fake_codex
            else:
                env.pop("CODEX_BIN_REAL", None)
                if inject_path_codex_when_unset:
                    env["PATH"] = f"{td}:{env.get('PATH', '')}"
                    self._make_exe(os.path.join(td, "codex"), f"#!/usr/bin/env bash\nexec {fake_codex} \"$@\"\n")
            env.update(extra_env)
            command = ["/bin/bash", WRAPPER, subcommand]
            command.extend(extra_args if extra_args is not None else ["--skip-git-repo-check", "echo", "hi"])
            subprocess.run(
                command,
                check=True,
                env=env,
                cwd=cwd or ROOT_DIR,
            )
            if capture_env_keys:
                with open(env_capture_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            if not expect_capture:
                return []
            with open(capture_path, "r", encoding="utf-8") as f:
                return json.load(f)

    # --- gdb MCP command resolution tests ---
    def test_wrapper_uses_env_driven_gdb_mcp_command(self):
        argv = self._run_wrapper(
            {
                "DIRGE_GDB_MCP_CMD": "python3 -u scripts/fake_gdb_mcp.py",
                "DIRGE_GDB_MCP_CWD": ".",
            }
        )
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.command="python3"', joined)
        self.assertIn(
            f'mcp_servers.gdb.args=["-u", "{os.path.join(ROOT_DIR, "scripts", "fake_gdb_mcp.py")}"]',
            joined,
        )
        self.assertIn(f'mcp_servers.gdb.cwd="{ROOT_DIR}"', joined)
        self.assertIn("mcp_servers.gdb.enabled=true", joined)

    def test_wrapper_supports_env_launcher_gdb_mcp_command(self):
        argv = self._run_wrapper(
            {
                "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 -u scripts/fake_gdb_mcp.py",
                "DIRGE_GDB_MCP_CWD": ".",
            }
        )
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.command="/usr/bin/env"', joined)
        self.assertIn(
            f'mcp_servers.gdb.args=["python3", "-u", "{os.path.join(ROOT_DIR, "scripts", "fake_gdb_mcp.py")}"]',
            joined,
        )
        self.assertIn(f'mcp_servers.gdb.cwd="{ROOT_DIR}"', joined)
        self.assertIn("mcp_servers.gdb.enabled=true", joined)

    def test_wrapper_keeps_python_module_launcher_module_name(self):
        argv = self._run_wrapper(
            {
                "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 -m fake_gdb_mcp",
                "DIRGE_GDB_MCP_CWD": ".",
            }
        )
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.command="/usr/bin/env"', joined)
        self.assertIn('mcp_servers.gdb.args=["python3", "-m", "fake_gdb_mcp"]', joined)
        self.assertNotIn(f'{ROOT_DIR}/fake_gdb_mcp', joined)
        self.assertIn(f'mcp_servers.gdb.cwd="{ROOT_DIR}"', joined)

    def test_wrapper_skips_python_flag_values_before_script_path(self):
        argv = self._run_wrapper(
            {
                "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 -W ignore -X dev scripts/fake_gdb_mcp.py",
                "DIRGE_GDB_MCP_CWD": ".",
            }
        )
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.command="/usr/bin/env"', joined)
        self.assertIn(
            f'mcp_servers.gdb.args=["python3", "-W", "ignore", "-X", "dev", "{os.path.join(ROOT_DIR, "scripts", "fake_gdb_mcp.py")}"]',
            joined,
        )
        self.assertNotIn(f'mcp_servers.gdb.args=["python3", "-W", "{ROOT_DIR}/ignore"', joined)
        self.assertIn(f'mcp_servers.gdb.cwd="{ROOT_DIR}"', joined)

    def test_wrapper_normalizes_env_split_string_launcher_payload(self):
        argv = self._run_wrapper(
            {
                "DIRGE_GDB_MCP_CMD": 'env -S "python3 -u scripts/fake_gdb_mcp.py"',
                "DIRGE_GDB_MCP_CWD": ".",
            }
        )
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.command="env"', joined)
        self.assertIn(
            f"mcp_servers.gdb.args=[\"-S\", \"python3 -u {os.path.join(ROOT_DIR, 'scripts', 'fake_gdb_mcp.py')}\"]",
            joined,
        )
        self.assertIn(f'mcp_servers.gdb.cwd="{ROOT_DIR}"', joined)

    def test_wrapper_skips_python_long_flag_values_before_script_path(self):
        argv = self._run_wrapper(
            {
                "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 --check-hash-based-pycs always scripts/fake_gdb_mcp.py",
                "DIRGE_GDB_MCP_CWD": ".",
            }
        )
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.command="/usr/bin/env"', joined)
        self.assertIn(
            f'mcp_servers.gdb.args=["python3", "--check-hash-based-pycs", "always", "{os.path.join(ROOT_DIR, "scripts", "fake_gdb_mcp.py")}"]',
            joined,
        )
        self.assertNotIn(f'mcp_servers.gdb.args=["python3", "--check-hash-based-pycs", "{ROOT_DIR}/always"', joined)
        self.assertIn(f'mcp_servers.gdb.cwd="{ROOT_DIR}"', joined)

    def test_wrapper_disables_gdb_mcp_without_env_or_legacy_install(self):
        argv = self._run_wrapper({}, include_system_path=False)
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.command=""', joined)
        self.assertIn('mcp_servers.gdb.args=[]', joined)
        self.assertIn('mcp_servers.gdb.enabled=false', joined)
        self.assertNotIn('/home/zenduk/桌面/mcp/GDB-MCP', joined)

    def test_wrapper_prefers_repo_launcher_for_path_gdb_mcp_when_env_unset(self):
        argv = self._run_wrapper({})
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.enabled=true', joined)
        self.assertIn('mcp_servers.gdb.command="/usr/bin/python3"', joined)
        self.assertIn(
            f'mcp_servers.gdb.args=["{os.path.join(ROOT_DIR, "scripts", "gdb_mcp_launcher.py")}"]',
            joined,
        )
        self.assertIn(f'mcp_servers.gdb.cwd="{ROOT_DIR}"', joined)
        self.assertNotIn('mcp_servers.gdb.cwd=""', joined)
        self.assertNotIn('/home/zenduk/桌面/mcp/GDB-MCP', joined)
    

    # --- Codex launcher resolution tests ---
    def test_wrapper_fails_fast_when_exec_auth_material_missing(self):
        with self.assertRaises(subprocess.CalledProcessError) as ctx:
            self._run_wrapper({"CODEX_HOME": "", "OPENAI_API_KEY": ""})
        self.assertEqual(ctx.exception.returncode, 2)

    def test_wrapper_allows_non_auth_subcommands_without_auth_material(self):
        argv = self._run_wrapper(
            {"CODEX_HOME": "", "OPENAI_API_KEY": ""},
            subcommand="--version",
            extra_args=[],
        )
        joined = "\n".join(argv)
        self.assertIn(f'-C\n{ROOT_DIR}', joined)

    def test_wrapper_accepts_exec_when_openai_api_key_present_without_auth_json(self):
        argv = self._run_wrapper(
            {"CODEX_HOME": "", "OPENAI_API_KEY": "test-key"},
        )
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.enabled=true', joined)

    def test_wrapper_prefers_path_codex_when_codex_bin_real_unset(self):
        argv = self._run_wrapper({}, set_codex_bin_real=False)
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.enabled=true', joined)
        self.assertNotIn('/home/zenduk/.npm-global/bin/codex', joined)

    def test_wrapper_uses_home_relative_legacy_codex_fallback_when_path_missing(self):
        with tempfile.TemporaryDirectory() as home_td:
            capture_path = os.path.join(home_td, "legacy-codex-argv.json")
            legacy_bin = os.path.join(home_td, ".npm-global", "bin", "codex")
            os.makedirs(os.path.dirname(legacy_bin), exist_ok=True)
            self._make_exe(
                legacy_bin,
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env python3
                    import json, sys
                    with open({capture_path!r}, 'w', encoding='utf-8') as f:
                        json.dump(sys.argv[1:], f, ensure_ascii=False)
                    """
                ),
            )
            self._run_wrapper(
                {"HOME": home_td},
                set_codex_bin_real=False,
                include_system_path=False,
                inject_path_codex_when_unset=False,
                expect_capture=False,
            )
            with open(capture_path, "r", encoding="utf-8") as f:
                argv = json.load(f)
        joined = "\n".join(argv)
        self.assertIn(f'-C\n{ROOT_DIR}', joined)
        self.assertNotIn('/home/zenduk/.npm-global/bin/codex', joined)

    def test_wrapper_repo_anchors_relative_codex_bin_real_from_non_root_cwd(self):
        with tempfile.TemporaryDirectory(dir=ROOT_DIR) as td:
            capture_path = os.path.join(td, "argv.json")
            fake_codex_rel = os.path.relpath(os.path.join(td, "fake_codex.py"), ROOT_DIR)
            self._make_exe(
                os.path.join(td, "fake_codex.py"),
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env python3
                    import json, sys
                    with open({capture_path!r}, 'w', encoding='utf-8') as f:
                        json.dump(sys.argv[1:], f, ensure_ascii=False)
                    """
                ),
            )
            fake_ghidra = self._make_exe(os.path.join(td, "fake_pyghidra_mcp"), "#!/usr/bin/env bash\nexit 0\n")
            ghidra_dir = os.path.join(td, "ghidra")
            os.makedirs(os.path.join(ghidra_dir, "support"), exist_ok=True)
            self._make_exe(os.path.join(ghidra_dir, "support", "analyzeHeadless"), "#!/usr/bin/env bash\nexit 0\n")

            env = os.environ.copy()
            env.update(
                {
                    "CODEX_BIN_REAL": fake_codex_rel,
                    "GHIDRA_MCP_BIN": fake_ghidra,
                    "GHIDRA_INSTALL_DIR": ghidra_dir,
                    "CODEX_HOME": os.path.join(td, "codex-home"),
                    "CODEX_RUNTIME_HOME": os.path.join(td, "codex-runtime"),
                    "GHIDRA_RUNTIME_ROOT": os.path.join(td, "ghidra-runtime"),
                    "MCP_JSONLINE_BRIDGE_LOG": os.path.join(td, "bridge.log"),
                    "DIRGE_SESSION_ID": "test-session",
                    "OPENAI_API_KEY": "unit-test-key",
                    "PATH": f"{td}:{os.environ.get('PATH', '')}",
                }
            )
            subprocess.run(
                ["/bin/bash", WRAPPER, "exec", "--skip-git-repo-check", "echo", "hi"],
                check=True,
                env=env,
                cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
            )
            with open(capture_path, "r", encoding="utf-8") as f:
                argv = json.load(f)
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.gdb.enabled=true', joined)
        self.assertIn(f'-C\n{ROOT_DIR}', joined)

    # --- Ghidra / pyghidra runtime discovery tests ---
    def test_wrapper_uses_repo_launcher_for_pyghidra_runtime(self):
        argv = self._run_wrapper({"GHIDRA_MCP_BIN": ""})
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.pyghidra-mcp.enabled=true', joined)
        self.assertIn('/tmp/', joined)
        self.assertIn(
            os.path.join(ROOT_DIR, "scripts", "pyghidra_mcp_launcher.py"),
            joined,
        )
        self.assertNotIn('/home/zenduk/.venvs/pyghidra-mcp/bin/pyghidra-mcp', joined)

    def test_wrapper_repo_anchors_relative_ghidra_install_dir_from_non_root_cwd(self):
        argv = self._run_wrapper(
            {
                "GHIDRA_INSTALL_DIR": ".tools/ghidra/ghidra_11.4_PUBLIC",
            },
            cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
        )
        joined = "\n".join(argv)
        self.assertIn(
            f'GHIDRA_INSTALL_DIR="{os.path.join(ROOT_DIR, ".tools", "ghidra", "ghidra_11.4_PUBLIC")}"',
            joined,
        )

    def test_wrapper_auto_discovers_repo_local_ghidra_install_when_default_is_invalid(self):
        with tempfile.TemporaryDirectory(dir=ROOT_DIR) as td:
            fake_tools_root = os.path.join(td, ".tools", "ghidra", "ghidra_auto_PUBLIC")
            os.makedirs(os.path.join(fake_tools_root, "support"), exist_ok=True)
            self._make_exe(os.path.join(fake_tools_root, "support", "analyzeHeadless"), "#!/usr/bin/env bash\nexit 0\n")
            argv = self._run_wrapper(
                {
                    "GHIDRA_INSTALL_DIR": "/opt/ghidra/current",
                },
                cwd=td,
            )
        joined = "\n".join(argv)
        self.assertIn('mcp_servers.pyghidra-mcp.env={GHIDRA_INSTALL_DIR="', joined)
        self.assertNotIn('GHIDRA_INSTALL_DIR="/opt/ghidra/current"', joined)
        self.assertIn(f'GHIDRA_INSTALL_DIR="{os.path.join(ROOT_DIR, ".ghidra-current")}"', joined)

    def test_wrapper_prefers_repo_ghidra_current_before_stale_repo_tools_tree(self):
        argv = self._run_wrapper(
            {
                "GHIDRA_INSTALL_DIR": "/opt/ghidra/current",
            }
        )
        joined = "\n".join(argv)
        self.assertIn(
            f'GHIDRA_INSTALL_DIR="{os.path.join(ROOT_DIR, ".ghidra-current")}"',
            joined,
        )
        self.assertNotIn(
            f'GHIDRA_INSTALL_DIR="{os.path.join(ROOT_DIR, ".tools", "ghidra", "ghidra_11.4_PUBLIC")}"',
            joined,
        )

    # --- runtime env repo-anchoring tests ---
    def test_wrapper_repo_anchors_relative_runtime_envs_from_non_root_cwd(self):
        argv = self._run_wrapper(
            {
                "CODEX_HOME": ".codex-home-rel",
                "CODEX_RUNTIME_HOME": ".codex-runtime-rel",
                "GHIDRA_RUNTIME_ROOT": ".ghidra-runtime-rel",
                "GHIDRA_SESSION_ROOT": ".ghidra-session-rel",
                "GHIDRA_MCP_PROJECT_PATH": ".ghidra-project-rel",
                "GHIDRA_MCP_HOME": ".ghidra-home-rel",
                "GHIDRA_MCP_XDG_CONFIG_HOME": ".ghidra-config-rel",
                "GHIDRA_MCP_XDG_CACHE_HOME": ".ghidra-cache-rel",
                "GHIDRA_MCP_XDG_DATA_HOME": ".ghidra-data-rel",
                "MCP_JSONLINE_BRIDGE": "scripts/mcp_jsonline_bridge.py",
                "MCP_JSONLINE_BRIDGE_LOG": "artifacts/bridge-rel.log",
                "PYGHIDRA_HOTFIX_DIR": "scripts/pyghidra_hotfix",
                "PYTHON_BIN": "/usr/bin/python3",
            },
            cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
        )
        joined = "\n".join(argv)
        self.assertIn(f'--project-path","{os.path.join(ROOT_DIR, ".ghidra-project-rel")}"', joined)
        self.assertIn(f'HOME="{os.path.join(ROOT_DIR, ".ghidra-home-rel")}"', joined)
        self.assertIn(f'XDG_CONFIG_HOME="{os.path.join(ROOT_DIR, ".ghidra-config-rel")}"', joined)
        self.assertIn(f'XDG_CACHE_HOME="{os.path.join(ROOT_DIR, ".ghidra-cache-rel")}"', joined)
        self.assertIn(f'XDG_DATA_HOME="{os.path.join(ROOT_DIR, ".ghidra-data-rel")}"', joined)
        self.assertIn(f'MCP_JSONLINE_BRIDGE_LOG="{os.path.join(ROOT_DIR, "artifacts", "bridge-rel.log")}"', joined)
        self.assertIn(f'PYTHONPATH="{os.path.join(ROOT_DIR, "scripts", "pyghidra_hotfix")}', joined)
        self.assertIn(os.path.join(ROOT_DIR, "scripts", "mcp_jsonline_bridge.py"), joined)

    def test_wrapper_defaults_codex_home_to_repo_runtime_home_when_source_home_missing(self):
        env_capture = self._run_wrapper(
            {"CODEX_HOME": "", "CODEX_RUNTIME_HOME": "", "GHIDRA_MCP_HOME": ".ghidra-home-rel"},
            cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
            capture_env_keys=["CODEX_HOME", "HOME"],
        )
        assert isinstance(env_capture, dict)
        self.assertEqual(
            env_capture["CODEX_HOME"],
            os.path.join(ROOT_DIR, "artifacts", "codex", "runtime-home", "test-session"),
        )
        self.assertEqual(env_capture["HOME"], os.path.join(ROOT_DIR, ".ghidra-home-rel"))
        self.assertNotEqual(env_capture["CODEX_HOME"], env_capture["HOME"])
        self.assertNotIn("/tmp/project_dirge_ghidra", env_capture["CODEX_HOME"])

    def test_wrapper_exports_discovered_java_home_to_runtime_and_pyghidra_env(self):
        java_root = os.path.join(ROOT_DIR, ".tools", "jdk")
        os.makedirs(java_root, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=java_root) as td:
            fake_java_home = td
            os.makedirs(os.path.join(fake_java_home, "bin"), exist_ok=True)
            self._make_exe(
                os.path.join(fake_java_home, "bin", "java"),
                "#!/usr/bin/env bash\necho 'openjdk version \"21.0.99\"' >&2\n",
            )
            env_capture = self._run_wrapper(
                {"JAVA_HOME": "", "JDK_HOME": ""},
                cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
                capture_env_keys=["JAVA_HOME", "JDK_HOME"],
            )
            argv = self._run_wrapper(
                {"JAVA_HOME": "", "JDK_HOME": ""},
                cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
            )
        assert isinstance(env_capture, dict)
        self.assertEqual(env_capture["JAVA_HOME"], fake_java_home)
        self.assertEqual(env_capture["JDK_HOME"], fake_java_home)

        joined = "\n".join(argv)
        self.assertIn(f'JAVA_HOME="{fake_java_home}"', joined)
        self.assertIn(f'JDK_HOME="{fake_java_home}"', joined)

    def test_wrapper_bootstraps_repo_relative_python_bin_before_runtime_normalization(self):
        with tempfile.TemporaryDirectory(dir=ROOT_DIR) as td:
            repo_python_abs = os.path.join(td, "fake_python.sh")
            repo_python_rel = os.path.relpath(repo_python_abs, ROOT_DIR)
            self._make_exe(
                repo_python_abs,
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    exec /usr/bin/python3 "$@"
                    """
                ),
            )
            argv = self._run_wrapper(
                {
                    "PYTHON_BIN": repo_python_rel,
                    "MCP_JSONLINE_BRIDGE": "scripts/mcp_jsonline_bridge.py",
                },
                cwd=os.path.join(ROOT_DIR, "challenge", "bench_local_nonpie"),
            )
        joined = "\n".join(argv)
        self.assertIn(os.path.join(ROOT_DIR, "scripts", "mcp_jsonline_bridge.py"), joined)
        self.assertIn(
            f'mcp_servers.pyghidra-mcp.command="{os.path.join(ROOT_DIR, repo_python_rel)}"',
            joined,
        )


if __name__ == "__main__":
    unittest.main()
