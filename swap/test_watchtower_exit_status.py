import contextlib
import io
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import veld_watchtowerd as watchtower


class WatchtowerExitStatusTests(unittest.TestCase):
    def cycle(self, outcome):
        with tempfile.TemporaryDirectory() as directory:
            worker = SimpleNamespace(state_dir=directory, margin=0, ttl=600,
                reads_before_halt=2, ssh_target="fixture", _alert=mock.Mock(),
                tick=mock.Mock(side_effect=outcome if isinstance(outcome, Exception) else None,
                               return_value=outcome))
            with mock.patch.object(watchtower, "load_bounded_json_file", return_value={}), \
                    mock.patch.object(watchtower, "Watchtower", return_value=worker), \
                    mock.patch.object(watchtower.sys, "argv", ["watchtower", "fixture.json", "--once"]), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    watchtower.main()
                    return 0
                except SystemExit as error:
                    return error.code

    def test_completed_observations_succeed(self):
        for outcome in ("SOLVENT", "EMPTY"):
            with self.subTest(outcome=outcome): self.assertEqual(self.cycle(outcome), 0)

    def test_failed_read_delivery_or_insolvency_is_not_success(self):
        for outcome in ("READ_FAIL", "PUSH_FAIL", "INSOLVENT", RuntimeError("fixture failure")):
            with self.subTest(outcome=str(outcome)): self.assertEqual(self.cycle(outcome), 69)


if __name__ == "__main__":
    unittest.main()
