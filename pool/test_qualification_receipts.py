import unittest
from .qualification.run import validate_receipt


class QualificationReceiptTests(unittest.TestCase):
    def prepared(self):
        return dict(
            status='PREPARED',
            processes_stopped=True,
            required_gate_complete=False,
            height=140,
            fixture_path='/disposable/fixture.json',
        )

    def test_prepared_funding_is_allowed_only_for_the_funding_stage(self):
        validate_receipt('pool.qualification.payment_fixture', self.prepared())
        for module in ('pool.qualification.payment_matrix', 'pool.qualification.comining'):
            with self.assertRaises(RuntimeError):
                validate_receipt(module, self.prepared())

    def test_preparation_never_claims_full_payment_success(self):
        for key, value in [
            ('status', 'PASS'),
            ('processes_stopped', False),
            ('required_gate_complete', True),
            ('height', 119),
            ('height', True),
            ('fixture_path', ''),
        ]:
            with self.subTest(key=key, value=value):
                receipt = self.prepared()
                receipt[key] = value
                with self.assertRaises(RuntimeError):
                    validate_receipt('pool.qualification.payment_fixture', receipt)

    def test_generic_pass_prefix_and_live_fixture_are_rejected(self):
        for receipt in (
            None,
            [],
            dict(status='PASS_INVENTED'),
            dict(status='PASS', processes_stopped=False),
        ):
            with self.assertRaises(RuntimeError):
                validate_receipt('pool.qualification.payment_matrix', receipt)
        validate_receipt(
            'pool.qualification.payment_matrix', dict(status='PASS', processes_stopped=True)
        )

    def test_scoped_lifecycle_receipt_has_only_its_specific_stage(self):
        receipt = dict(status='PASS_SCOPED_NATIVE_BOND_LIFECYCLE', processes_stopped=True)
        validate_receipt('pool.qualification.validator_lifecycle', receipt)
        with self.assertRaises(RuntimeError):
            validate_receipt('pool.qualification.payment_matrix', receipt)


if __name__ == '__main__':
    unittest.main()
