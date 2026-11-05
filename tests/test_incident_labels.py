from contextlib import closing
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from incident_labels import initialize,assign,backfill,attach,header
from incidents import group_events

class IncidentLabelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'test.sqlite3'

    def test_number_survives_reopen_and_revision_and_local_day(self):
        with closing(sqlite3.connect(self.path)) as db,db:
            initialize(db)
            self.assertEqual(assign(db,'a','2026-11-05T02:00:00Z'),'INC-20261104-001')
            self.assertEqual(assign(db,'b','2026-11-05T03:00:00Z'),'INC-20261104-002')
            self.assertEqual(assign(db,'c','2026-11-05T09:00:00Z'),'INC-20261105-001')
        with closing(sqlite3.connect(self.path)) as db,db:
            self.assertEqual(assign(db,'a','2026-11-06T02:00:00Z'),'INC-20261104-001')
            value=attach(db,dict(incident_id='a',revision=9))
            text=header(value)
            self.assertIn('revision 9',text);self.assertIn(datetime.fromisoformat('2026-11-05T02:00:00+00:00').astimezone(ZoneInfo('America/Vancouver')).strftime('%Y-%m-%d %H:%M:%S'),text);self.assertIn('America/Vancouver',text)

    def test_backfill_orders_by_actual_alert_not_plan_window(self):
        with closing(sqlite3.connect(self.path)) as db,db:
            db.executescript('CREATE TABLE incidents(incident_id TEXT,evidence TEXT); CREATE TABLE events(event_id TEXT,payload TEXT); CREATE TABLE grouped_events(event_id TEXT,incident_id TEXT);')
            for ident,stamp in [('later','2026-11-05T03:00:00Z'),('earlier','2026-11-05T02:00:00Z')]:
                db.execute('INSERT INTO incidents VALUES(?,?)',(ident,json.dumps({'window_start':'2026-11-01T00:00:00Z'})))
                db.execute('INSERT INTO events VALUES(?,?)',(ident,json.dumps({'timestamp':stamp})))
                db.execute('INSERT INTO grouped_events VALUES(?,?)',(ident,ident))
            self.assertEqual(backfill(db),2);self.assertEqual(backfill(db),0)
            self.assertEqual(attach(db,{'incident_id':'earlier'})['incident_number'],'INC-20261104-001')
            self.assertEqual(attach(db,{'incident_id':'later'})['incident_number'],'INC-20261104-002')

    def test_missing_alert_fallback_is_explicit(self):
        with closing(sqlite3.connect(self.path)) as db,db:
            db.execute('CREATE TABLE incidents(incident_id TEXT,evidence TEXT)')
            db.execute('INSERT INTO incidents VALUES(?,?)',('a',json.dumps({'window_start':'2026-11-04T23:00:00Z'})))
            backfill(db)
            text=header(dict(attach(db,{'incident_id':'a'}),revision=1))
            self.assertIn('retained window start',text)

    def test_new_incidents_receive_labels_once(self):
        from collector import collect
        collect('fixtures/eve.json',self.path);group_events(self.path)
        with closing(sqlite3.connect(self.path)) as db:
            rows=db.execute('SELECT incident_number FROM incident_numbers').fetchall()
            count=db.execute('SELECT count(*) FROM incidents').fetchone()[0]
            self.assertEqual(len(rows),count);self.assertTrue(count)
        group_events(self.path)
        with closing(sqlite3.connect(self.path)) as db:self.assertEqual(db.execute('SELECT incident_number FROM incident_numbers').fetchall(),rows)

    def test_notifications_and_firewall_requests_show_label_and_time(self):
        from human_review import notification_message
        from response import message_for
        value=dict(incident_id='a'*64,incident_number='INC-20261104-007',incident_occurred_at='2026-11-04T23:00:00Z',revision=2,evidence={},error='No authentication outcomes')
        notice=notification_message(value,{'chat_id':1})
        self.assertIn('INC-20261104-007',notice['text']);self.assertIn(datetime.fromisoformat(value['incident_occurred_at'].replace('Z','+00:00')).astimezone(ZoneInfo('America/Vancouver')).strftime('%Y-%m-%d %H:%M:%S'),notice['text'])
        report=dict(verdict='SUSPICIOUS',reason='Check evidence.',recommendations=['Check source.','Check logs.'])
        row=dict(value,report=json.dumps(report),plan=None,expires_at=9999999999,request_id='r',status='notified',chat_id=1)
        self.assertIn('INC-20261104-007',message_for(row)['text'])
        row.update(plan=json.dumps(dict(mode='live',source_ip='192.168.64.4',destination_ip='192.168.64.6',port=22,duration_seconds=60)),context='{}')
        payload=message_for(row)
        self.assertIn('INC-20261104-007',payload['text']);self.assertIn(datetime.fromisoformat(value['incident_occurred_at'].replace('Z','+00:00')).astimezone(ZoneInfo('America/Vancouver')).strftime('%Y-%m-%d %H:%M:%S'),payload['text'])
        self.assertIn('soc5:a:',payload['reply_markup']['inline_keyboard'][0][0]['callback_data'])
