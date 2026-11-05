from contextlib import closing
import json
import sqlite3
import unittest
from unittest.mock import patch

from response import (deliver_one, execute_dry_run, handle_update, message_for,
                      queue_reports, update_terminal_messages, tick)
from telegram_client import TelegramError
from test_response import IDENTITY, REPORT
import test_response


class RecordingTelegram:
    def __init__(self): self.calls=[]
    def call(self,method,payload):
        self.calls.append((method,payload))
        return {'message_id':42,'chat':{'id':100}}


class TelegramDecisionTests(unittest.TestCase):
    pending=test_response.ResponseTests.pending
    callback=test_response.ResponseTests.callback

    def setUp(self):
        test_response.ResponseTests.setUp(self)
        with closing(sqlite3.connect(self.db)) as db, db:
            evidence=json.loads(db.execute('SELECT evidence FROM incidents').fetchone()[0])
            auth={'source_ip':evidence['source_ip'],'target_ip':evidence['destination_ip'],
                  'failed_password_count':6,'failed_accounts':{'soc_rehearsal_invalid':6},
                  'successful_login_count':0,'coverage':'observed_window'}
            metadata={'tool_trace':[{'tool':'get_ssh_auth_summary','result':auth},
                                    {'tool':'get_approved_test_plan','result':{'plan':None}}]}
            db.execute('UPDATE analyses SET report=?,metadata=?',
                       (json.dumps(dict(REPORT,scenario='ssh_investigation')),json.dumps(metadata)))

    def row(self):
        with closing(sqlite3.connect(self.db)) as db:
            db.row_factory=sqlite3.Row
            return db.execute('SELECT * FROM approval_requests').fetchone()

    def test_prompt_uses_verified_counts_and_incident_bound_buttons(self):
        request=self.pending()
        payload=message_for(self.row())
        self.assertEqual(payload['parse_mode'],'HTML')
        self.assertIn('Unapproved SSH activity detected',payload['text'])
        self.assertIn('6 failed logins; 0 successful logins; no matching approved test plan',payload['text'])
        self.assertIn('10 minutes',payload['text'])
        self.assertIn('DRY RUN',payload['text'])
        buttons=payload['reply_markup']['inline_keyboard']
        self.assertEqual(buttons[0][0]['callback_data'],'soc5:a:'+request)
        self.assertEqual(buttons[1][0]['callback_data'],'soc5:d:'+request)
        self.assertIn('YES',buttons[0][0]['text'])
        self.assertEqual(buttons[1][0]['text'],'NO — Deny block / report only')
        self.assertLessEqual(len(buttons[0][0]['callback_data'].encode()),64)

    def test_yes_executes_only_configured_dry_run_and_closes_buttons(self):
        request=self.pending();client=RecordingTelegram()
        self.assertEqual(handle_update(self.db,self.callback(request),IDENTITY,now=1010),'approved')
        self.assertEqual(execute_dry_run(self.db,self.policy,now=1011),1)
        self.assertEqual(update_terminal_messages(self.db,client,IDENTITY,now=1012),1)
        method,payload=client.calls[0]
        self.assertEqual(method,'editMessageText')
        self.assertEqual(payload['message_id'],42)
        self.assertEqual(payload['reply_markup'],{'inline_keyboard':[]})
        self.assertIn('no firewall command executed',payload['text'])
        self.assertEqual(update_terminal_messages(self.db,client,IDENTITY,now=1013),0)
        self.assertEqual(execute_dry_run(self.db,self.policy,now=1013),0)

    def test_no_retains_report_records_rejection_and_never_executes(self):
        request=self.pending();client=RecordingTelegram()
        report=self.row()['report']
        self.assertEqual(handle_update(self.db,self.callback(request,decision='d'),IDENTITY,now=1010),'denied')
        self.assertEqual(execute_dry_run(self.db,self.policy,now=1011),0)
        self.assertEqual(self.row()['report'],report)
        self.assertEqual(update_terminal_messages(self.db,client,IDENTITY,now=1012),1)
        self.assertIn('NO selected. Report retained',client.calls[0][1]['text'])
        self.assertEqual(client.calls[0][1]['reply_markup'],{'inline_keyboard':[]})

    def test_no_response_expires_audits_once_and_cannot_later_approve(self):
        request=self.pending();client=RecordingTelegram()
        self.assertEqual(deliver_one(self.db,client,IDENTITY,now=1600),'idle')
        self.assertEqual(self.row()['status'],'expired')
        self.assertEqual(execute_dry_run(self.db,self.policy,now=1600),0)
        self.assertEqual(update_terminal_messages(self.db,client,IDENTITY,now=1600),1)
        self.assertIn('Request expired without response execution',client.calls[0][1]['text'])
        self.assertEqual(handle_update(self.db,self.callback(request),IDENTITY,now=1601),'not_pending')
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM response_audit WHERE kind='expired'").fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM dry_run_actions').fetchone()[0],0)

    def test_absent_or_misattributed_auth_never_claims_six_failures(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE analyses SET metadata=?',(json.dumps({'tool_trace':[
                {'tool':'get_ssh_auth_summary','result':{'source_ip':'192.168.64.99',
                'target_ip':'192.168.64.6','failed_password_count':6,'failed_accounts':{'root':6},
                'successful_login_count':0}}]}),))
        self.pending();payload=message_for(self.row())
        self.assertIn('authentication counts unavailable',payload['text'])
        self.assertNotIn('6 failed logins',payload['text'])
        self.assertNotIn('no matching approved test plan',payload['text'])

    def test_message_escapes_evidence_and_does_not_repeat_model_prose(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE analyses SET report=?',(json.dumps(dict(REPORT,scenario='ssh_investigation',reason='<b>Untrusted & text</b>')),))
            metadata=json.loads(db.execute('SELECT metadata FROM analyses').fetchone()[0])
            metadata['tool_trace'][0]['result']['failed_accounts']={'<b>root</b>':6}
            db.execute('UPDATE analyses SET metadata=?',(json.dumps(metadata),))
        self.pending();payload=message_for(self.row())
        self.assertIn('&lt;b&gt;root&lt;/b&gt;',payload['text'])
        self.assertNotIn('Untrusted',payload['text'])

    def test_uncertain_status_edit_never_reexecutes_or_retries(self):
        request=self.pending()
        handle_update(self.db,self.callback(request),IDENTITY,now=1010)
        execute_dry_run(self.db,self.policy,now=1011)
        class Broken:
            def call(self,*args): raise TelegramError('timeout')
        self.assertEqual(update_terminal_messages(self.db,Broken(),IDENTITY,now=1012),0)
        self.assertEqual(self.row()['status'],'dry_run_complete')
        self.assertEqual(self.row()['status_notified'],'unknown')
        self.assertEqual(update_terminal_messages(self.db,Broken(),IDENTITY,now=1013),0)
        self.assertEqual(execute_dry_run(self.db,self.policy,now=1013),0)

    def test_historical_completed_messages_are_not_rewritten(self):
        self.pending();client=RecordingTelegram()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE approval_requests SET status='dry_run_complete',status_notified='legacy'")
        self.assertEqual(update_terminal_messages(self.db,client,IDENTITY,now=1010),0)
        self.assertEqual(client.calls,[])

    def test_changed_incident_closes_request_without_action(self):
        request=self.pending();client=RecordingTelegram()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('UPDATE incidents SET revision=revision+1')
        self.assertEqual(handle_update(self.db,self.callback(request),IDENTITY,now=1010),'not_pending')
        self.assertEqual(execute_dry_run(self.db,self.policy,now=1011),0)
        self.assertEqual(update_terminal_messages(self.db,client,IDENTITY,now=1012),1)
        self.assertIn('Incident changed',client.calls[0][1]['text'])

    def test_buttons_cannot_approve_another_pending_message(self):
        first=self.pending()
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("INSERT INTO incidents SELECT 'second-incident',evidence,alert_count,revision,status FROM incidents LIMIT 1")
            db.execute("""INSERT INTO analyses (incident_id,revision,status,report,prompt_hash,metadata)
                          SELECT 'second-incident',revision,status,report,prompt_hash,metadata FROM analyses LIMIT 1""")
        self.assertEqual(queue_reports(self.db,self.policy,IDENTITY,now=1001),1)
        class SecondMessage:
            def call(self,*args): return {'message_id':43,'chat':{'id':100}}
        self.assertEqual(deliver_one(self.db,SecondMessage(),IDENTITY,now=1001),'sent')
        with closing(sqlite3.connect(self.db)) as db:
            second=db.execute("SELECT request_id FROM approval_requests WHERE incident_id='second-incident'").fetchone()[0]
        self.assertEqual(handle_update(self.db,self.callback(second,message=42,update_id=20),IDENTITY,now=1010),'unauthorized')
        self.assertEqual(handle_update(self.db,self.callback(first,message=43,update_id=21),IDENTITY,now=1010),'unauthorized')
        self.assertEqual(execute_dry_run(self.db,self.policy,now=1011),0)
        self.assertEqual(handle_update(self.db,self.callback(second,message=43,update_id=22),IDENTITY,now=1012),'approved')
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT status FROM approval_requests WHERE request_id=?',(first,)).fetchone()[0],'pending')

    def test_plain_yes_and_no_are_not_decisions(self):
        self.pending()
        for update_id,text in enumerate(('YES','NO'),30):
            self.assertEqual(handle_update(self.db,{'update_id':update_id,'message':{'text':text}},IDENTITY,now=1010),'ignored')
        self.assertEqual(self.row()['status'],'pending')
        self.assertEqual(execute_dry_run(self.db,self.policy,now=1011),0)

    def test_monitor_tick_handles_yes_acknowledgement_and_final_message_once(self):
        request=self.pending()
        update=self.callback(request)
        class ScriptedTelegram(RecordingTelegram):
            polls=0
            def call(inner,method,payload):
                inner.calls.append((method,payload))
                if method=='getUpdates':
                    inner.polls+=1
                    return [] if inner.polls==1 else [update]
                return {'message_id':42,'chat':{'id':100}}
        client=ScriptedTelegram()
        with patch('response.time.time',return_value=1010):
            result=tick(self.db,self.policy,client,IDENTITY)
            repeated=tick(self.db,self.policy,client,IDENTITY)
        self.assertEqual(result['decisions'],['approved'])
        self.assertEqual(result['dry_run_actions'],1)
        self.assertEqual(result['telegram_status_updates'],1)
        self.assertEqual(repeated['dry_run_actions'],0)
        self.assertEqual(repeated['telegram_status_updates'],0)
        self.assertEqual(len([c for c in client.calls if c[0]=='editMessageText']),1)
        self.assertTrue(any(c[0]=='answerCallbackQuery' and 'YES recorded' in c[1]['text'] for c in client.calls))
