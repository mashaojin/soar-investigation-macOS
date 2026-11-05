from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from dashboard import database_snapshot
from report_language import plain_text,present_report
from response import message_for


class ReadableReportTests(unittest.TestCase):
    def test_reference_names_and_parenthetical_citations(self):
        text="E2 shows 12 failures against 'soc_test' (E2, P1). E3 sets a limit of 10 (E3)."
        shown=plain_text(text)
        self.assertEqual(shown,"The SSH log summary shows 12 failures against 'soc_test'. The test-plan lookup sets a limit of 10.")

    def test_sources_in_middle_of_sentence_are_readable(self):
        self.assertEqual(plain_text('See E2 and P1.'),'See the SSH log summary and the scope comparison.')

    def test_quoted_account_or_literal_ids_are_not_rewritten(self):
        self.assertEqual(plain_text("E2 shows a failure for 'E2' and `P1`."),"The SSH log summary shows a failure for 'E2' and `P1`.")

    def test_no_plan_citation_removed_without_inventing_context(self):
        self.assertEqual(plain_text('No matching plan was found (E3.plan=null).'),'No matching plan was found.')

    def test_existing_natural_text_is_unchanged(self):
        text='There were 10 failed logins from 192.168.64.8. The approved limit was 10.'
        self.assertEqual(plain_text(text),text)

    def test_dvwa_source_names_do_not_invent_ssh_evidence(self):
        self.assertEqual(plain_text('E2 provides application context (P1).','dvwa_sqli'),'The lab application context provides application context.')

    def test_verdict_claims_and_original_report_are_untouched(self):
        report=dict(verdict='SUSPICIOUS',reason='E2 shows 12 failed logins (E2).',recommendations=['Review E3.','Check P1.'],
                    claims={'failed_password_count':12},recommended_action='REQUEST_BLOCK_APPROVAL')
        before=deepcopy(report);shown=present_report(report)
        self.assertEqual(report,before);self.assertEqual(shown['claims'],report['claims']);self.assertEqual(shown['verdict'],'SUSPICIOUS')
        self.assertNotIn('REQUEST_BLOCK_APPROVAL',shown['next_step']);self.assertIn('approval',shown['next_step'])

    def test_report_only_telegram_is_self_contained(self):
        report=dict(verdict='SUSPICIOUS',reason="E2 shows 6 failures against 'soc_test' (E2). E3 shows no matching plan (E3).",
            recommendations=['Review E2.','Review the source.'],recommended_action='REQUEST_BLOCK_APPROVAL')
        row=dict(report=json.dumps(report),plan=None,expires_at=0,incident_id='test-incident',revision=1,request_id='test',status='notified',chat_id=1)
        payload=message_for(row)
        self.assertIn('The SSH log summary shows 6 failures',payload['text']);self.assertNotIn('(E2)',payload['text'])
        self.assertNotIn('REQUEST_BLOCK_APPROVAL',payload['text']);self.assertNotIn('reply_markup',payload)

    def test_dashboard_has_display_copy_and_preserves_database(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'state.db';report=dict(verdict='BENIGN',reason='E2 shows permitted testing (E3).',recommendations=[])
            with closing(sqlite3.connect(path)) as db,db:
                db.executescript('CREATE TABLE incidents(incident_id TEXT,revision INTEGER,evidence TEXT,status TEXT); CREATE TABLE analyses(incident_id TEXT,revision INTEGER,status TEXT,report TEXT,metadata TEXT,error TEXT);')
                db.execute("INSERT INTO incidents VALUES('i',1,'{}','complete')")
                db.execute("INSERT INTO analyses VALUES('i',1,'complete',?,'{}',NULL)",(json.dumps(report),))
            before=path.read_bytes();row=database_snapshot(path)['incidents'][0]
            self.assertEqual(row['report'],report);self.assertNotEqual(row['display_report']['reason'],report['reason'])
            self.assertEqual(before,path.read_bytes())


if __name__=='__main__':unittest.main()
