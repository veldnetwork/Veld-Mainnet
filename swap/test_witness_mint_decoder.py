import json
import subprocess
import unittest
from unittest import mock

import veld_wt_reserve as witness


class WitnessMintDecoderTests(unittest.TestCase):
    cfg = {"issuer_p2pkh_hex": "00" * 25, "keygen": "/fixture/keygen"}

    def run_decoder(self, response):
        completed = subprocess.CompletedProcess([], 0, response, "")
        with mock.patch.object(witness, "run_bounded_subprocess", return_value=completed):
            return witness._decode_mint_template("00", self.cfg)

    def test_normal_exact_fields(self):
        expected = {"from": "Vissuer", "to": "Vrecipient", "sats": 250000,
                    "memo": "MNP1;fixture", "total_out_sats": 5000, "num_inputs": 2}
        self.assertEqual(self.run_decoder(json.dumps(expected)), expected)

    def test_response_requires_object(self):
        for value in ([], None, "text", 12):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                self.run_decoder(json.dumps(value))

    def test_amount_requires_exact_positive_integer(self):
        for value in (True, 1.5, "1", 0, -1):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                self.run_decoder(json.dumps({"from": "Vissuer", "to": "Vrecipient",
                                             "sats": value, "memo": ""}))

    def test_duplicate_response_fields_refused(self):
        with self.assertRaises(SystemExit):
            self.run_decoder('{"from":"Vissuer","to":"Vrecipient","sats":1,"sats":2}')

    def test_child_failure_refused(self):
        with mock.patch.object(witness, "run_bounded_subprocess",
                return_value=subprocess.CompletedProcess([], 2, "", "refused")), \
                self.assertRaises(SystemExit):
            witness._decode_mint_template("00", self.cfg)

    def test_bounded_command_contract(self):
        response = json.dumps({"from": "Vissuer", "to": "Vrecipient", "sats": 1, "memo": ""})
        with mock.patch.object(witness, "run_bounded_subprocess",
                return_value=subprocess.CompletedProcess([], 0, response, "")) as run:
            witness._decode_mint_template("00", self.cfg)
        self.assertEqual(run.call_args.args[0], ["/fixture/keygen", "decode-mint", "00" * 25, "00"])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertEqual(run.call_args.kwargs["stdout_max"], 256 * 1024)
        self.assertEqual(run.call_args.kwargs["stderr_max"], 64 * 1024)


if __name__ == "__main__":
    unittest.main()
