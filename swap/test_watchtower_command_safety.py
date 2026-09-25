#!/usr/bin/env python3
import subprocess
import unittest
from unittest import mock

import veld_watchtowerd as wd


class WatchtowerCommandSafetyTests(unittest.TestCase):
    def test_alert_argv_array_is_preserved(self):
        self.assertEqual(
            wd._validated_alert_argv(["/usr/bin/logger", "--tag", "veld-wt"]),
            ("/usr/bin/logger", "--tag", "veld-wt"),
        )

    def test_legacy_simple_alert_string_is_split_without_a_shell(self):
        self.assertEqual(
            wd._validated_alert_argv('/usr/bin/logger --tag "veld watchtower"'),
            ("/usr/bin/logger", "--tag", "veld watchtower"),
        )

    def test_alert_rejects_malformed_argv(self):
        for value in (
            {"command": "logger"},
            [],
            ["logger", "bad\narg"],
            ["-logger"],
            ["logger", "bad\x00arg"],
        ):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    wd._validated_alert_argv(value)

    def test_alert_executes_exact_argv_with_shell_disabled(self):
        watchtower = wd.Watchtower.__new__(wd.Watchtower)
        watchtower.alert_cmd = ("/usr/bin/logger", "--tag", "veld-wt")
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(wd, "warn"),
            mock.patch.object(wd, "run_bounded_subprocess", return_value=completed) as run,
        ):
            watchtower._alert("hostile; $(touch /tmp/not-executed)")
        run.assert_called_once_with(
            ["/usr/bin/logger", "--tag", "veld-wt"],
            input_text="hostile; $(touch /tmp/not-executed)",
            timeout=20,
            stdout_max=64 * 1024,
            stderr_max=64 * 1024,
            description="watchtower alert hook",
        )

    def test_remote_command_allows_literal_name_or_path_only(self):
        self.assertEqual(wd._validated_remote_command("veld_wt_recv"), "veld_wt_recv")
        self.assertEqual(
            wd._validated_remote_command("/opt/veld/veld_wt_recv.py"), "/opt/veld/veld_wt_recv.py"
        )
        for value in (
            "veld_wt_recv --unsafe",
            "veld_wt_recv;id",
            "$(id)",
            "../veld_wt_recv",
            "",
            None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    wd._validated_remote_command(value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
