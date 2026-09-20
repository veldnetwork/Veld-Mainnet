import unittest
from .qualification.role_install import identity_lease_seconds

class IdentityLeaseTests(unittest.TestCase):
    def test_full_real_clock_maturity_and_upgrade_budget(self):
        for seconds in (3600,21600,43200):
            self.assertGreaterEqual(identity_lease_seconds(seconds),seconds+1800+7200)
        self.assertGreater(identity_lease_seconds(21600),14400)

    def test_invalid_budget_does_not_create_unbounded_identity(self):
        for seconds in (0,3599,43201,-1,True,21600.0,'21600'):
            with self.assertRaises(ValueError):identity_lease_seconds(seconds)
