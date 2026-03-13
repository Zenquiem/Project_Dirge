import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

from scripts import health_check_mcp as hm


class HealthCheckMcpTests(unittest.TestCase):
    def test_checked_in_codex_config_avoids_machine_private_paths(self):
        cfg_path = os.path.join(hm.ROOT_DIR, ".codex", "config.toml")
        with open(cfg_path, "r", encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("/mnt/Project_Dirge", text)
        self.assertNotIn("/home/zenduk", text)
        self.assertIn('GHIDRA_INSTALL_DIR = "./.ghidra-current"', text)
        self.assertIn('command = "/usr/bin/python3"', text)
        self.assertIn('./scripts/pyghidra_mcp_launcher.py', text)
        self.assertIn('./scripts/gdb_mcp_launcher.py', text)

    def test_configured_servers_keeps_startup_timeout_sec(self):
        cfg = hm._load_toml(os.path.join(hm.ROOT_DIR, ".codex", "config.toml"))
        servers = {item["name"]: item for item in hm._configured_servers(cfg)}
        self.assertIn("pyghidra-mcp", servers)
        self.assertEqual(servers["pyghidra-mcp"]["startup_timeout_sec"], 45.0)

    def test_parse_server_names_ignores_empty_registry_message(self):
        names, parsed_json = hm._parse_server_names(
            "No MCP servers configured yet. Try `codex mcp add my-tool -- my-command`.\n"
        )
        self.assertEqual(names, [])
        self.assertFalse(parsed_json)

    def test_parse_server_names_keeps_real_text_listing(self):
        names, parsed_json = hm._parse_server_names("- gdb\n- pyghidra\n")
        self.assertEqual(names, ["gdb", "pyghidra"])
        self.assertFalse(parsed_json)

    def test_resolve_command_accepts_repo_relative_executable_path(self):
        rel_dir = os.path.join("artifacts", "tmp")
        abs_dir = os.path.join(hm.ROOT_DIR, rel_dir)
        os.makedirs(abs_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", dir=abs_dir, prefix="healthcheck_exec_", delete=False) as tmp:
            tmp.write("#!/bin/sh\nexit 0\n")
            abs_path = tmp.name
        self.addCleanup(lambda: os.path.exists(abs_path) and os.unlink(abs_path))
        os.chmod(abs_path, os.stat(abs_path).st_mode | stat.S_IXUSR)
        rel_path = os.path.relpath(abs_path, hm.ROOT_DIR)
        ok, resolved = hm._resolve_command(rel_path)
        self.assertTrue(ok)
        self.assertEqual(resolved, abs_path)

    def test_resolve_command_rejects_repo_relative_non_executable_path(self):
        rel_dir = os.path.join("artifacts", "tmp")
        abs_dir = os.path.join(hm.ROOT_DIR, rel_dir)
        os.makedirs(abs_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", dir=abs_dir, prefix="healthcheck_noexec_", delete=False) as tmp:
            tmp.write("#!/bin/sh\nexit 0\n")
            abs_path = tmp.name
        self.addCleanup(lambda: os.path.exists(abs_path) and os.unlink(abs_path))
        os.chmod(abs_path, os.stat(abs_path).st_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)
        rel_path = os.path.relpath(abs_path, hm.ROOT_DIR)
        ok, resolved = hm._resolve_command(rel_path)
        self.assertFalse(ok)
        self.assertEqual(resolved, abs_path)

    def test_resolve_server_launcher_falls_back_to_path_gdb_mcp(self):
        ok, resolved = hm._resolve_server_launcher(
            "gdb",
            {"name": "gdb", "command": "/definitely/missing/gdb-python", "args": ["server.py"], "cwd": "/tmp"},
        )
        self.assertTrue(ok)
        self.assertTrue(resolved.endswith("gdb-mcp"), resolved)

    def test_resolve_server_launcher_rejects_missing_repo_relative_bridge_script(self):
        with tempfile.TemporaryDirectory(dir=hm.ROOT_DIR) as td:
            inner_cmd = os.path.join(td, "fake_pyghidra")
            with open(inner_cmd, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(inner_cmd, os.stat(inner_cmd).st_mode | stat.S_IXUSR)

            real_resolve = hm._resolve_command

            def fake_resolve(cmd: str):
                if cmd in {"pyghidra-mcp", os.path.expanduser("~/.local/bin/pyghidra-mcp")}:
                    return False, ""
                return real_resolve(cmd)

            with mock.patch.object(hm, "_resolve_command", side_effect=fake_resolve):
                ok, resolved = hm._resolve_server_launcher(
                    "pyghidra-mcp",
                    {
                        "name": "pyghidra-mcp",
                        "command": sys.executable,
                        "args": ["scripts/missing_bridge.py", "--", inner_cmd, "--project-path", "/tmp/demo"],
                        "cwd": hm.ROOT_DIR,
                    },
                )
        self.assertFalse(ok)
        self.assertEqual(resolved, sys.executable)

    def test_resolve_server_launcher_accepts_repo_relative_bridge_script(self):
        with tempfile.TemporaryDirectory(dir=hm.ROOT_DIR) as td:
            bridge_rel = os.path.relpath(os.path.join(td, "scripts", "mcp_jsonline_bridge.py"), hm.ROOT_DIR)
            os.makedirs(os.path.dirname(os.path.join(hm.ROOT_DIR, bridge_rel)), exist_ok=True)
            with open(os.path.join(hm.ROOT_DIR, bridge_rel), "w", encoding="utf-8") as f:
                f.write("print('ok')\n")
            inner_cmd = os.path.join(td, "fake_pyghidra")
            with open(inner_cmd, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(inner_cmd, os.stat(inner_cmd).st_mode | stat.S_IXUSR)
            ok, resolved = hm._resolve_server_launcher(
                "pyghidra-mcp",
                {
                    "name": "pyghidra-mcp",
                    "command": sys.executable,
                    "args": [bridge_rel, "--", inner_cmd, "--project-path", "/tmp/demo"],
                    "cwd": hm.ROOT_DIR,
                },
            )
        self.assertTrue(ok)
        self.assertEqual(resolved, sys.executable)

    def test_main_repo_anchors_relative_config_from_non_root_cwd(self):
        cmd = [
            sys.executable,
            os.path.join(hm.ROOT_DIR, "scripts", "health_check_mcp.py"),
            "--config",
            ".codex/config.toml",
            "--codex-bin",
            "/bin/true",
            "--no-functional-probe",
            "--json",
        ]
        proc = subprocess.run(
            cmd,
            cwd=os.path.join(hm.ROOT_DIR, "challenge", "bench_local_nonpie"),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["required_servers"], ["gdb", "pyghidra-mcp"])
        self.assertNotIn("required server launcher missing: gdb", data.get("reasons", []))

    def test_main_defaults_project_config_to_functional_probe_and_surfaces_failure(self):
        fake_servers = [
            {"name": "gdb", "enabled": True, "command": "/bin/true", "args": [], "cwd": hm.ROOT_DIR, "env": {}},
            {
                "name": "pyghidra-mcp",
                "enabled": True,
                "command": "/bin/true",
                "args": [],
                "cwd": hm.ROOT_DIR,
                "env": {},
            },
        ]
        argv = ["health_check_mcp.py", "--config", ".codex/config.toml", "--codex-bin", "/bin/true", "--json"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(hm, "_load_toml", return_value={}), \
             mock.patch.object(hm, "_configured_servers", return_value=fake_servers), \
             mock.patch.object(hm, "_resolve_command", return_value=(True, "/bin/true")), \
             mock.patch.object(hm, "_run_cmd", return_value={"rc": 0, "stdout": "[]", "stderr": ""}), \
             mock.patch.object(hm, "_run_gdb_cli_probe", return_value={"server": "gdb", "tool": "tools/list", "ok": True, "error": ""}), \
             mock.patch.object(hm, "_run_pyghidra_cli_probe", return_value={"server": "pyghidra-mcp", "tool": "list_project_binaries", "ok": False, "error": "boom"}):
            with mock.patch("builtins.print") as print_mock:
                rc = hm.main()
        self.assertEqual(rc, 1)
        printed = json.loads(print_mock.call_args.args[0])
        self.assertIn("functional probe failed: pyghidra-mcp.list_project_binaries: boom", printed["reasons"])
        self.assertEqual(printed["authority"], "project_config")

    def test_run_pyghidra_cli_probe_repo_anchors_relative_project_path_and_cwd(self):
        with tempfile.TemporaryDirectory(dir=hm.ROOT_DIR) as td:
            capture_path = os.path.join(td, "probe.json")
            fake_pyghidra = os.path.join(td, "fake_pyghidra.py")
            with open(fake_pyghidra, "w", encoding="utf-8") as f:
                f.write(
                    textwrap.dedent(
                        f"""\
                        #!/usr/bin/env python3
                        import json, os, sys
                        with open({capture_path!r}, 'w', encoding='utf-8') as out:
                            json.dump({{"argv": sys.argv[1:], "cwd": os.getcwd()}}, out)
                        sys.stdout.write('[]')
                        """
                    )
                )
            os.chmod(fake_pyghidra, os.stat(fake_pyghidra).st_mode | stat.S_IXUSR)

            project_rel = os.path.relpath(os.path.join(td, "project-dir"), hm.ROOT_DIR)
            cwd_rel = os.path.relpath(os.path.join(td, "probe-cwd"), hm.ROOT_DIR)
            os.makedirs(os.path.join(hm.ROOT_DIR, cwd_rel), exist_ok=True)
            server_cfg = {
                "command": fake_pyghidra,
                "args": ["--project-path", project_rel, "--project-name", "demo"],
                "cwd": cwd_rel,
                "env": {},
            }

            result = hm._run_pyghidra_cli_probe(server_cfg, probe_timeout_sec=3.0, probe_label="pyghidra-mcp")
            self.assertTrue(result["ok"], result)
            with open(capture_path, "r", encoding="utf-8") as f:
                captured = json.load(f)

            self.assertEqual(captured["cwd"], os.path.join(hm.ROOT_DIR, cwd_rel))
            self.assertIn("--project-path", captured["argv"])
            proj_idx = captured["argv"].index("--project-path")
            self.assertEqual(captured["argv"][proj_idx + 1], os.path.join(hm.ROOT_DIR, project_rel))

    def test_run_pyghidra_cli_probe_repo_anchors_relative_env_paths(self):
        with tempfile.TemporaryDirectory(dir=hm.ROOT_DIR) as td:
            capture_path = os.path.join(td, "probe_env_paths.json")
            fake_pyghidra = os.path.join(td, "fake_pyghidra_env_paths.py")
            with open(fake_pyghidra, "w", encoding="utf-8") as f:
                f.write(
                    textwrap.dedent(
                        f"""\
                        #!/usr/bin/env python3
                        import json, os, sys
                        with open({capture_path!r}, 'w', encoding='utf-8') as out:
                            json.dump({{
                                "codex_bin": os.environ.get("CODEX_BIN", ""),
                                "codex_bin_real": os.environ.get("CODEX_BIN_REAL", ""),
                                "codex_home": os.environ.get("CODEX_HOME", ""),
                                "codex_runtime_home": os.environ.get("CODEX_RUNTIME_HOME", ""),
                                "home": os.environ.get("HOME", ""),
                                "pwn_loader": os.environ.get("PWN_LOADER", ""),
                                "pwn_libc_path": os.environ.get("PWN_LIBC_PATH", ""),
                                "pwn_ld_library_path": os.environ.get("PWN_LD_LIBRARY_PATH", ""),
                                "xdg_config_home": os.environ.get("XDG_CONFIG_HOME", ""),
                                "xdg_cache_home": os.environ.get("XDG_CACHE_HOME", ""),
                                "ghidra_mcp_home": os.environ.get("GHIDRA_MCP_HOME", ""),
                                "ghidra_mcp_xdg_config_home": os.environ.get("GHIDRA_MCP_XDG_CONFIG_HOME", ""),
                                "ghidra_mcp_xdg_cache_home": os.environ.get("GHIDRA_MCP_XDG_CACHE_HOME", ""),
                                "ghidra_mcp_xdg_data_home": os.environ.get("GHIDRA_MCP_XDG_DATA_HOME", ""),
                                "gdb_launcher_script": os.environ.get("GDB_LAUNCHER_SCRIPT", ""),
                                "pyghidra_launcher_script": os.environ.get("PYGHIDRA_LAUNCHER_SCRIPT", ""),
                                "dirge_gdb_extra_site": os.environ.get("DIRGE_GDB_EXTRA_SITE", ""),
                                "dirge_pyghidra_extra_site": os.environ.get("DIRGE_PYGHIDRA_EXTRA_SITE", ""),
                            }}, out)
                        sys.stdout.write('[]')
                        """
                    )
                )
            os.chmod(fake_pyghidra, os.stat(fake_pyghidra).st_mode | stat.S_IXUSR)

            server_cfg = {
                "command": fake_pyghidra,
                "args": [],
                "cwd": ".",
                "env": {
                    "CODEX_BIN": "scripts/codex_with_mcp.sh",
                    "CODEX_BIN_REAL": "./.codex/bin/codex-real",
                    "CODEX_HOME": "artifacts/codex/home",
                    "CODEX_RUNTIME_HOME": "artifacts/codex/runtime-home",
                    "HOME": ".codex/runtime/ghidra/home",
                    "PWN_LOADER": "challenge/bench_local_nonpie/ld-linux-x86-64.so.2",
                    "PWN_LIBC_PATH": "challenge/bench_local_nonpie/libc.so.6",
                    "PWN_LD_LIBRARY_PATH": "challenge/bench_local_nonpie/lib:plain-libdir",
                    "XDG_CONFIG_HOME": ".codex/runtime/ghidra/home/.config",
                    "XDG_CACHE_HOME": ".codex/runtime/ghidra/home/.cache",
                    "GHIDRA_MCP_HOME": "artifacts/ghidra/demo-home",
                    "GHIDRA_MCP_XDG_CONFIG_HOME": "artifacts/ghidra/demo-home/.config",
                    "GHIDRA_MCP_XDG_CACHE_HOME": "artifacts/ghidra/demo-home/.cache",
                    "GHIDRA_MCP_XDG_DATA_HOME": "artifacts/ghidra/demo-home/.local/share",
                    "GDB_LAUNCHER_SCRIPT": "scripts/gdb_mcp_launcher.py",
                    "PYGHIDRA_LAUNCHER_SCRIPT": "scripts/pyghidra_mcp_launcher.py",
                    "DIRGE_GDB_EXTRA_SITE": "scripts",
                    "DIRGE_PYGHIDRA_EXTRA_SITE": "scripts/pyghidra_hotfix",
                    "JAVA_HOME": ".tools/jdk/jdk-21",
                    "JDK_HOME": ".tools/java/current",
                },
            }
            result = hm._run_pyghidra_cli_probe(server_cfg, probe_timeout_sec=3.0, probe_label="pyghidra-mcp")
            self.assertTrue(result["ok"], result)
            with open(capture_path, "r", encoding="utf-8") as f:
                captured = json.load(f)
            self.assertEqual(captured["codex_bin"], os.path.join(hm.ROOT_DIR, "scripts", "codex_with_mcp.sh"))
            self.assertEqual(captured["codex_bin_real"], os.path.join(hm.ROOT_DIR, ".codex", "bin", "codex-real"))
            self.assertEqual(captured["codex_home"], os.path.join(hm.ROOT_DIR, "artifacts", "codex", "home"))
            self.assertEqual(captured["codex_runtime_home"], os.path.join(hm.ROOT_DIR, "artifacts", "codex", "runtime-home"))
            self.assertEqual(captured["home"], os.path.join(hm.ROOT_DIR, ".codex", "runtime", "ghidra", "home"))
            self.assertEqual(captured["pwn_loader"], os.path.join(hm.ROOT_DIR, "challenge", "bench_local_nonpie", "ld-linux-x86-64.so.2"))
            self.assertEqual(captured["pwn_libc_path"], os.path.join(hm.ROOT_DIR, "challenge", "bench_local_nonpie", "libc.so.6"))
            self.assertEqual(
                captured["pwn_ld_library_path"],
                os.path.join(hm.ROOT_DIR, "challenge", "bench_local_nonpie", "lib") + os.pathsep + "plain-libdir",
            )
            self.assertEqual(captured["xdg_config_home"], os.path.join(hm.ROOT_DIR, ".codex", "runtime", "ghidra", "home", ".config"))
            self.assertEqual(captured["xdg_cache_home"], os.path.join(hm.ROOT_DIR, ".codex", "runtime", "ghidra", "home", ".cache"))
            self.assertEqual(captured["ghidra_mcp_home"], os.path.join(hm.ROOT_DIR, "artifacts", "ghidra", "demo-home"))
            self.assertEqual(captured["ghidra_mcp_xdg_config_home"], os.path.join(hm.ROOT_DIR, "artifacts", "ghidra", "demo-home", ".config"))
            self.assertEqual(captured["ghidra_mcp_xdg_cache_home"], os.path.join(hm.ROOT_DIR, "artifacts", "ghidra", "demo-home", ".cache"))
            self.assertEqual(captured["ghidra_mcp_xdg_data_home"], os.path.join(hm.ROOT_DIR, "artifacts", "ghidra", "demo-home", ".local", "share"))
            self.assertEqual(captured["gdb_launcher_script"], os.path.join(hm.ROOT_DIR, "scripts", "gdb_mcp_launcher.py"))
            self.assertEqual(captured["pyghidra_launcher_script"], os.path.join(hm.ROOT_DIR, "scripts", "pyghidra_mcp_launcher.py"))
            self.assertEqual(captured["dirge_gdb_extra_site"], os.path.join(hm.ROOT_DIR, "scripts"))
            self.assertEqual(captured["dirge_pyghidra_extra_site"], os.path.join(hm.ROOT_DIR, "scripts", "pyghidra_hotfix"))

    def test_normalize_repo_relative_env_value_repo_anchors_extended_runtime_keys(self):
        self.assertEqual(
            hm._normalize_repo_relative_env_value("JAVA_HOME", ".tools/jdk/jdk-21"),
            os.path.join(hm.ROOT_DIR, ".tools", "jdk", "jdk-21"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("JDK_HOME", ".tools/java/current"),
            os.path.join(hm.ROOT_DIR, ".tools", "java", "current"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("CODEX_BIN", "scripts/codex_with_mcp.sh"),
            os.path.join(hm.ROOT_DIR, "scripts", "codex_with_mcp.sh"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("CODEX_BIN_REAL", "./.codex/bin/codex-real"),
            os.path.join(hm.ROOT_DIR, ".codex", "bin", "codex-real"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("CODEX_RUNTIME_HOME", "artifacts/codex/runtime-home"),
            os.path.join(hm.ROOT_DIR, "artifacts", "codex", "runtime-home"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("GHIDRA_MCP_BIN", "./.venv/bin/pyghidra-mcp"),
            os.path.join(hm.ROOT_DIR, ".venv", "bin", "pyghidra-mcp"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("GHIDRA_RUNTIME_ROOT", "artifacts/ghidra/runtime-root"),
            os.path.join(hm.ROOT_DIR, "artifacts", "ghidra", "runtime-root"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("GHIDRA_SESSION_ROOT", "artifacts/ghidra/session-root"),
            os.path.join(hm.ROOT_DIR, "artifacts", "ghidra", "session-root"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("GHIDRA_MCP_XDG_DATA_HOME", "artifacts/ghidra/demo-home/.local/share"),
            os.path.join(hm.ROOT_DIR, "artifacts", "ghidra", "demo-home", ".local", "share"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("GHIDRA_MCP_HOME", "artifacts/ghidra/demo-home"),
            os.path.join(hm.ROOT_DIR, "artifacts", "ghidra", "demo-home"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("GDB_LAUNCHER_SCRIPT", "scripts/gdb_mcp_launcher.py"),
            os.path.join(hm.ROOT_DIR, "scripts", "gdb_mcp_launcher.py"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("PYGHIDRA_LAUNCHER_SCRIPT", "scripts/pyghidra_mcp_launcher.py"),
            os.path.join(hm.ROOT_DIR, "scripts", "pyghidra_mcp_launcher.py"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("DIRGE_GDB_EXTRA_SITE", "scripts"),
            os.path.join(hm.ROOT_DIR, "scripts"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("DIRGE_PYGHIDRA_EXTRA_SITE", "scripts/pyghidra_hotfix"),
            os.path.join(hm.ROOT_DIR, "scripts", "pyghidra_hotfix"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("MCP_JSONLINE_BRIDGE", "scripts/mcp_jsonline_bridge.py"),
            os.path.join(hm.ROOT_DIR, "scripts", "mcp_jsonline_bridge.py"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("PYGHIDRA_HOTFIX_DIR", "scripts/pyghidra_hotfix"),
            os.path.join(hm.ROOT_DIR, "scripts", "pyghidra_hotfix"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("PYTHON_BIN", "./.venv/bin/python3"),
            os.path.join(hm.ROOT_DIR, ".venv", "bin", "python3"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("PWN_LOADER", "challenge/bench_local_nonpie/ld-linux-x86-64.so.2"),
            os.path.join(hm.ROOT_DIR, "challenge", "bench_local_nonpie", "ld-linux-x86-64.so.2"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("PWN_LIBC_PATH", "challenge/bench_local_nonpie/libc.so.6"),
            os.path.join(hm.ROOT_DIR, "challenge", "bench_local_nonpie", "libc.so.6"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("LD_LIBRARY_PATH", "./artifacts/lib" + os.pathsep + "plain-libdir"),
            os.path.join(hm.ROOT_DIR, "artifacts", "lib") + os.pathsep + "plain-libdir",
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("PWN_LD_LIBRARY_PATH", "challenge/bench_local_nonpie/lib" + os.pathsep + "plain-libdir"),
            os.path.join(hm.ROOT_DIR, "challenge", "bench_local_nonpie", "lib") + os.pathsep + "plain-libdir",
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("PATH", "./.local/bin" + os.pathsep + "plain-bin"),
            os.path.join(hm.ROOT_DIR, ".local", "bin") + os.pathsep + "plain-bin",
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value("PYGHIDRA_MCP_PYTHONPATH", "./scripts/pyghidra_hotfix" + os.pathsep + "./scripts"),
            os.path.join(hm.ROOT_DIR, "scripts", "pyghidra_hotfix") + os.pathsep + os.path.join(hm.ROOT_DIR, "scripts"),
        )
        self.assertEqual(
            hm._normalize_repo_relative_env_value(
                "DIRGE_GDB_MCP_CMD",
                "/usr/bin/env python3 -u ./scripts/fake_gdb_mcp.py",
            ),
            "/usr/bin/env python3 -u " + os.path.join(hm.ROOT_DIR, "scripts", "fake_gdb_mcp.py"),
        )
        split_string_cmd = hm._normalize_repo_relative_env_value(
            "DIRGE_GDB_MCP_CMD",
            'env -S "python3 -u ./scripts/fake_gdb_mcp.py"',
        )
        self.assertIn("env -S", split_string_cmd)
        self.assertIn(os.path.join(hm.ROOT_DIR, "scripts", "fake_gdb_mcp.py"), split_string_cmd)
        self.assertEqual(
            hm._normalize_repo_relative_env_value(
                "DIRGE_GDB_MCP_CMD",
                'python3 -W ignore -X dev ./scripts/fake_gdb_mcp.py',
            ),
            'python3 -W ignore -X dev ' + os.path.join(hm.ROOT_DIR, 'scripts', 'fake_gdb_mcp.py'),
        )

    def test_run_pyghidra_cli_probe_discovers_java_21_home_and_exports_it(self):
        java_root = os.path.join(hm.ROOT_DIR, ".tools", "jdk")
        os.makedirs(java_root, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=java_root) as td:
            fake_java_home = td
            os.makedirs(os.path.join(fake_java_home, "bin"), exist_ok=True)
            fake_java = os.path.join(fake_java_home, "bin", "java")
            with open(fake_java, "w", encoding="utf-8") as f:
                f.write("#!/usr/bin/env bash\necho 'openjdk version \"21.0.77\"' >&2\n")
            os.chmod(fake_java, os.stat(fake_java).st_mode | stat.S_IXUSR)

            capture_path = os.path.join(hm.ROOT_DIR, "artifacts", "tmp", "java_probe.json")
            os.makedirs(os.path.dirname(capture_path), exist_ok=True)
            fake_pyghidra = os.path.join(hm.ROOT_DIR, "artifacts", "tmp", "fake_pyghidra_java.py")
            with open(fake_pyghidra, "w", encoding="utf-8") as f:
                f.write(
                    textwrap.dedent(
                        f"""\
                        #!/usr/bin/env python3
                        import json, os, sys
                        with open({capture_path!r}, 'w', encoding='utf-8') as out:
                            json.dump({{"java_home": os.environ.get("JAVA_HOME", ""), "jdk_home": os.environ.get("JDK_HOME", "")}}, out)
                        sys.stdout.write('[]')
                        """
                    )
                )
            os.chmod(fake_pyghidra, os.stat(fake_pyghidra).st_mode | stat.S_IXUSR)
            self.addCleanup(lambda: os.path.exists(fake_pyghidra) and os.unlink(fake_pyghidra))
            self.addCleanup(lambda: os.path.exists(capture_path) and os.unlink(capture_path))

            result = hm._run_pyghidra_cli_probe(
                {"command": fake_pyghidra, "args": [], "cwd": hm.ROOT_DIR, "env": {"JAVA_HOME": "", "JDK_HOME": ""}},
                probe_timeout_sec=3.0,
                probe_label="pyghidra-mcp",
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["java"]["path"], fake_java_home)
            self.assertTrue(result["java"]["meets_min"])
            with open(capture_path, "r", encoding="utf-8") as f:
                captured = json.load(f)
            self.assertEqual(captured["java_home"], fake_java_home)
            self.assertEqual(captured["jdk_home"], fake_java_home)

    def test_run_pyghidra_cli_probe_respects_server_startup_timeout(self):
        with tempfile.TemporaryDirectory(dir=hm.ROOT_DIR) as td:
            capture_path = os.path.join(td, "probe_timeout.json")
            fake_pyghidra = os.path.join(td, "fake_pyghidra_timeout.py")
            with open(fake_pyghidra, "w", encoding="utf-8") as f:
                f.write(
                    textwrap.dedent(
                        f"""\
                        #!/usr/bin/env python3
                        import json, os, sys, time
                        time.sleep(1.2)
                        with open({capture_path!r}, 'w', encoding='utf-8') as out:
                            json.dump({{"ok": True}}, out)
                        sys.stdout.write('[]')
                        """
                    )
                )
            os.chmod(fake_pyghidra, os.stat(fake_pyghidra).st_mode | stat.S_IXUSR)
            result = hm._run_pyghidra_cli_probe(
                {"command": fake_pyghidra, "args": [], "cwd": hm.ROOT_DIR, "env": {}, "startup_timeout_sec": 2.0},
                probe_timeout_sec=0.5,
                probe_label="pyghidra-mcp",
            )
            self.assertTrue(result["ok"], result)
            self.assertTrue(os.path.exists(capture_path))

    def test_run_pyghidra_cli_probe_repo_anchors_env_project_path_override(self):
        with tempfile.TemporaryDirectory(dir=hm.ROOT_DIR) as td:
            capture_path = os.path.join(td, "probe_env.json")
            fake_pyghidra = os.path.join(td, "fake_pyghidra_env.py")
            with open(fake_pyghidra, "w", encoding="utf-8") as f:
                f.write(
                    textwrap.dedent(
                        f"""\
                        #!/usr/bin/env python3
                        import json, sys
                        with open({capture_path!r}, 'w', encoding='utf-8') as out:
                            json.dump(sys.argv[1:], out)
                        sys.stdout.write('[]')
                        """
                    )
                )
            os.chmod(fake_pyghidra, os.stat(fake_pyghidra).st_mode | stat.S_IXUSR)

            env_project_rel = os.path.relpath(os.path.join(td, "env-project-dir"), hm.ROOT_DIR)
            old_env = os.environ.get("GHIDRA_MCP_PROJECT_PATH")
            os.environ["GHIDRA_MCP_PROJECT_PATH"] = env_project_rel
            try:
                server_cfg = {
                    "command": fake_pyghidra,
                    "args": ["--project-path", "/tmp/ignored-project", "--project-name", "demo"],
                    "cwd": hm.ROOT_DIR,
                    "env": {},
                }
                result = hm._run_pyghidra_cli_probe(server_cfg, probe_timeout_sec=3.0, probe_label="pyghidra-mcp")
                self.assertTrue(result["ok"], result)
            finally:
                if old_env is None:
                    os.environ.pop("GHIDRA_MCP_PROJECT_PATH", None)
                else:
                    os.environ["GHIDRA_MCP_PROJECT_PATH"] = old_env

            with open(capture_path, "r", encoding="utf-8") as f:
                argv = json.load(f)
            proj_idx = argv.index("--project-path")
            self.assertEqual(argv[proj_idx + 1], os.path.join(hm.ROOT_DIR, env_project_rel))

    def test_run_gdb_cli_probe_completes_stdio_initialize_and_tools_list(self):
        with tempfile.TemporaryDirectory(dir=hm.ROOT_DIR) as td:
            fake_gdb = os.path.join(td, "fake_gdb_mcp.py")
            with open(fake_gdb, "w", encoding="utf-8") as f:
                f.write(
                    "#!/usr/bin/env python3\n"
                    "import json, sys\n"
                    "for raw in sys.stdin:\n"
                    "    msg = json.loads(raw)\n"
                    "    method = msg.get('method')\n"
                    "    if method == 'initialize':\n"
                    "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'protocolVersion': '2024-11-05', 'capabilities': {}}}) + '\\n')\n"
                    "        sys.stdout.flush()\n"
                    "    elif method == 'tools/list':\n"
                    "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'tools': [{'name': 'start_binary'}]}}) + '\\n')\n"
                    "        sys.stdout.flush()\n"
                )
            os.chmod(fake_gdb, os.stat(fake_gdb).st_mode | stat.S_IXUSR)
            result = hm._run_gdb_cli_probe(
                {"name": "gdb", "command": sys.executable, "args": [fake_gdb], "cwd": hm.ROOT_DIR, "env": {}},
                probe_timeout_sec=3.0,
                probe_label="gdb",
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tool"], "tools/list")
        self.assertIn("start_binary", result["stdout_tail"])

    def test_run_gdb_cli_probe_reports_initialize_handshake_failure(self):
        with tempfile.TemporaryDirectory(dir=hm.ROOT_DIR) as td:
            fake_gdb = os.path.join(td, "fake_gdb_broken.py")
            with open(fake_gdb, "w", encoding="utf-8") as f:
                f.write("#!/usr/bin/env python3\nimport sys\nsys.stderr.write('boom on init\\n')\nsys.exit(1)\n")
            os.chmod(fake_gdb, os.stat(fake_gdb).st_mode | stat.S_IXUSR)
            result = hm._run_gdb_cli_probe(
                {"name": "gdb", "command": sys.executable, "args": [fake_gdb], "cwd": hm.ROOT_DIR, "env": {}},
                probe_timeout_sec=3.0,
                probe_label="gdb",
            )
        self.assertFalse(result["ok"], result)
        self.assertIn("mcp process exited unexpectedly", result["error"])


if __name__ == "__main__":
    unittest.main()
