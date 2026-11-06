from copy import deepcopy
import unittest
from assessment_facts import check_prose
from test_direct_gemma import job


class ProseContradictionTests(unittest.TestCase):
    def test_success_count_cannot_be_relabelled_from_failures(self):
        _,value=job('unapproved_activity')
        with self.assertRaisesRegex(ValueError,'successful-login'):
            check_prose('The evidence contains 16 successful logins.',value)
        check_prose('The logs contain 16 failed logins and 0 successful logins.',value)

    def test_identical_ips_cannot_be_called_different(self):
        _,value=job()
        with self.assertRaisesRegex(ValueError,'IP-address mismatch'):
            check_prose('A different IP address (192.0.2.10) than expected (192.0.2.10) was targeted.',value)

    def test_permitted_account_cannot_be_called_outside_plan(self):
        _,value=job()
        with self.assertRaisesRegex(ValueError,'explicitly permitted'):
            check_prose("The account 'soc_test' is outside the approved plan.",value)
        check_prose('The observed soc_test failures fit the recorded plan; further review is still reasonable.',value)

    def test_no_plan_does_not_supply_an_unexpected_account_allowlist(self):
        _,value=job('unapproved_activity')
        for reason in ["The account 'root' is outside the approved plan.",'The presence of an unexpected account warrants review.']:
            with self.assertRaisesRegex(ValueError,'without a matching plan'):check_prose(reason,value)
        check_prose('No matching plan was found; observed root attempts warrant review.',value)

    def test_real_scope_violation_remains_a_fact_and_verdict_stays_free(self):
        _,value=job('scope_violation')
        check_prose("The account 'root' is outside the approved plan.",value)
        check_prose('Observed root attempts are outside permitted scope; assessed low risk.',value)
