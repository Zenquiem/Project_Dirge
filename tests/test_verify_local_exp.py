import unittest

from scripts import verify_local_exp


class VerifyLocalExpPathResolutionTests(unittest.TestCase):
    def test_prefers_canonical_session_exp_when_state_points_to_other_session(self):
        state = {
            "session": {
                "session_id": "other_session",
                "exp": {"path": "sessions/other_session/exp/exp.py"},
            }
        }

        raw, abs_path = verify_local_exp._resolve_exp_path(state, "", "wanted_session")

        self.assertEqual("sessions/wanted_session/exp/exp.py", raw)
        self.assertTrue(abs_path.endswith("/sessions/wanted_session/exp/exp.py"))

    def test_keeps_matching_session_exp_path_from_state(self):
        state = {
            "session": {
                "session_id": "sess_a",
                "exp": {"path": "sessions/sess_a/exp/exp.py"},
            }
        }

        raw, abs_path = verify_local_exp._resolve_exp_path(state, "", "sess_a")

        self.assertEqual("sessions/sess_a/exp/exp.py", raw)
        self.assertTrue(abs_path.endswith("/sessions/sess_a/exp/exp.py"))

    def test_explicit_cli_exp_path_still_wins(self):
        state = {
            "session": {
                "session_id": "sess_a",
                "exp": {"path": "sessions/sess_a/exp/exp.py"},
            }
        }

        raw, abs_path = verify_local_exp._resolve_exp_path(state, "artifacts/custom_exp.py", "sess_b")

        self.assertEqual("artifacts/custom_exp.py", raw)
        self.assertTrue(abs_path.endswith("/artifacts/custom_exp.py"))


if __name__ == "__main__":
    unittest.main()
