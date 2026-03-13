import os
import unittest

from scripts import mcp_jsonline_bridge as bridge


class McpJsonlineBridgeTests(unittest.TestCase):
    def test_normalize_child_env_repo_anchors_relative_runtime_paths(self):
        env = {
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
            "GHIDRA_INSTALL_DIR": "./.ghidra-current",
            "GHIDRA_MCP_BIN": "./.venv/bin/pyghidra-mcp",
            "GHIDRA_RUNTIME_ROOT": "artifacts/ghidra/runtime-root",
            "GHIDRA_SESSION_ROOT": "artifacts/ghidra/session-root",
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
            "MCP_JSONLINE_BRIDGE": "scripts/mcp_jsonline_bridge.py",
            "MCP_JSONLINE_BRIDGE_LOG": "artifacts/bridge.log",
            "PYTHON_BIN": "./.venv/bin/python3",
            "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 -u ./scripts/fake_gdb_mcp.py",
            "LD_LIBRARY_PATH": "./artifacts/lib:plain-libdir",
            "PATH": "./.local/bin:plain-bin",
            "PYTHONPATH": "./scripts/pyghidra_hotfix:plain-token",
            "PYGHIDRA_MCP_PYTHONPATH": "./scripts/pyghidra_hotfix:./scripts",
        }
        normalized = bridge._normalize_child_env(env)
        self.assertEqual(normalized["CODEX_BIN"], os.path.join(bridge.ROOT_DIR, "scripts", "codex_with_mcp.sh"))
        self.assertEqual(normalized["CODEX_BIN_REAL"], os.path.join(bridge.ROOT_DIR, ".codex", "bin", "codex-real"))
        self.assertEqual(normalized["CODEX_HOME"], os.path.join(bridge.ROOT_DIR, "artifacts", "codex", "home"))
        self.assertEqual(normalized["CODEX_RUNTIME_HOME"], os.path.join(bridge.ROOT_DIR, "artifacts", "codex", "runtime-home"))
        self.assertEqual(normalized["HOME"], os.path.join(bridge.ROOT_DIR, ".codex", "runtime", "ghidra", "home"))
        self.assertEqual(normalized["PWN_LOADER"], os.path.join(bridge.ROOT_DIR, "challenge", "bench_local_nonpie", "ld-linux-x86-64.so.2"))
        self.assertEqual(normalized["PWN_LIBC_PATH"], os.path.join(bridge.ROOT_DIR, "challenge", "bench_local_nonpie", "libc.so.6"))
        self.assertEqual(
            normalized["PWN_LD_LIBRARY_PATH"],
            os.path.join(bridge.ROOT_DIR, "challenge", "bench_local_nonpie", "lib") + os.pathsep + "plain-libdir",
        )
        self.assertEqual(normalized["XDG_CONFIG_HOME"], os.path.join(bridge.ROOT_DIR, ".codex", "runtime", "ghidra", "home", ".config"))
        self.assertEqual(normalized["XDG_CACHE_HOME"], os.path.join(bridge.ROOT_DIR, ".codex", "runtime", "ghidra", "home", ".cache"))
        self.assertEqual(normalized["GHIDRA_INSTALL_DIR"], os.path.join(bridge.ROOT_DIR, ".ghidra-current"))
        self.assertEqual(normalized["GHIDRA_MCP_BIN"], os.path.join(bridge.ROOT_DIR, ".venv", "bin", "pyghidra-mcp"))
        self.assertEqual(normalized["GHIDRA_RUNTIME_ROOT"], os.path.join(bridge.ROOT_DIR, "artifacts", "ghidra", "runtime-root"))
        self.assertEqual(normalized["GHIDRA_SESSION_ROOT"], os.path.join(bridge.ROOT_DIR, "artifacts", "ghidra", "session-root"))
        self.assertEqual(normalized["GHIDRA_MCP_HOME"], os.path.join(bridge.ROOT_DIR, "artifacts", "ghidra", "demo-home"))
        self.assertEqual(normalized["GHIDRA_MCP_XDG_CONFIG_HOME"], os.path.join(bridge.ROOT_DIR, "artifacts", "ghidra", "demo-home", ".config"))
        self.assertEqual(normalized["GHIDRA_MCP_XDG_CACHE_HOME"], os.path.join(bridge.ROOT_DIR, "artifacts", "ghidra", "demo-home", ".cache"))
        self.assertEqual(normalized["GHIDRA_MCP_XDG_DATA_HOME"], os.path.join(bridge.ROOT_DIR, "artifacts", "ghidra", "demo-home", ".local", "share"))
        self.assertEqual(normalized["GDB_LAUNCHER_SCRIPT"], os.path.join(bridge.ROOT_DIR, "scripts", "gdb_mcp_launcher.py"))
        self.assertEqual(normalized["PYGHIDRA_LAUNCHER_SCRIPT"], os.path.join(bridge.ROOT_DIR, "scripts", "pyghidra_mcp_launcher.py"))
        self.assertEqual(normalized["DIRGE_GDB_EXTRA_SITE"], os.path.join(bridge.ROOT_DIR, "scripts"))
        self.assertEqual(normalized["DIRGE_PYGHIDRA_EXTRA_SITE"], os.path.join(bridge.ROOT_DIR, "scripts", "pyghidra_hotfix"))
        self.assertEqual(normalized["JAVA_HOME"], os.path.join(bridge.ROOT_DIR, ".tools", "jdk", "jdk-21"))
        self.assertEqual(normalized["JDK_HOME"], os.path.join(bridge.ROOT_DIR, ".tools", "java", "current"))
        self.assertEqual(normalized["MCP_JSONLINE_BRIDGE"], os.path.join(bridge.ROOT_DIR, "scripts", "mcp_jsonline_bridge.py"))
        self.assertEqual(normalized["MCP_JSONLINE_BRIDGE_LOG"], os.path.join(bridge.ROOT_DIR, "artifacts", "bridge.log"))
        self.assertEqual(normalized["PYTHON_BIN"], os.path.join(bridge.ROOT_DIR, ".venv", "bin", "python3"))
        self.assertEqual(
            normalized["DIRGE_GDB_MCP_CMD"],
            "/usr/bin/env python3 -u " + os.path.join(bridge.ROOT_DIR, "scripts", "fake_gdb_mcp.py"),
        )
        self.assertEqual(
            normalized["LD_LIBRARY_PATH"],
            os.path.join(bridge.ROOT_DIR, "artifacts", "lib") + os.pathsep + "plain-libdir",
        )
        self.assertEqual(
            normalized["PATH"],
            os.path.join(bridge.ROOT_DIR, ".local", "bin") + os.pathsep + "plain-bin",
        )
        self.assertEqual(
            normalized["PYTHONPATH"],
            os.path.join(bridge.ROOT_DIR, "scripts", "pyghidra_hotfix") + os.pathsep + "plain-token",
        )
        self.assertEqual(
            normalized["PYGHIDRA_MCP_PYTHONPATH"],
            os.path.join(bridge.ROOT_DIR, "scripts", "pyghidra_hotfix") + os.pathsep + os.path.join(bridge.ROOT_DIR, "scripts"),
        )

    def test_normalize_child_env_handles_env_split_string_and_interpreter_flags(self):
        normalized = bridge._normalize_child_env(
            {
                "DIRGE_GDB_MCP_CMD": 'env -S "python3 -W ignore -X dev ./scripts/fake_gdb_mcp.py"',
            }
        )
        self.assertIn("env -S", normalized["DIRGE_GDB_MCP_CMD"])
        self.assertIn(
            os.path.join(bridge.ROOT_DIR, 'scripts', 'fake_gdb_mcp.py'),
            normalized["DIRGE_GDB_MCP_CMD"],
        )


if __name__ == "__main__":
    unittest.main()
