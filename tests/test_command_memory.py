"""Per-command association, missing data, grouped comparisons and persistence."""
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'main'))
from web_server import create_app, Store, STATUS_TOPIC
from command_memory_web import FIELDS, parse_memory


def sample(aes=True, peak=64, stack_peak=180):
    return dict(v=2, valid=True, heap_before=150000, heap_after=150000,
                heap_peak=peak, heap_retained=0, allocations=int(peak > 0),
                stack_free_min=1800, context_bytes=400 if aes else 0,
                stack_peak=stack_peak)


class CommandMemoryTests(unittest.TestCase):
    def setUp(self):
        self.app=create_app(':memory:')
        self.d=self.app.extensions['dashboard']
        self.client=self.app.test_client()

    def tearDown(self):
        self.d.store.close()

    def pending(self, number=1, aes=True, command='ON', peak=64, stack_peak=180):
        ident=f'{number:016x}'
        self.d.store.record_measurement(dict(ts=time.time(), mode='on' if aes else 'off',
            source='command', outcome='pending', command_id=ident, command=command))
        self.d.pending_commands[ident]=dict(command=command, encrypted=aes, start_ns=time.perf_counter_ns())
        return dict(command_id=ident, command=command, phase='applied',
                    status='UNLOCKED' if command=='ON' else 'LOCKED', aes_enabled=aes,
                    memory=sample(aes,peak,stack_peak), execution_us=100)

    def receive(self, ack):
        self.d._receive_command_ack(ack, time.perf_counter_ns(), time.time())

    def test_peak_survives_release_and_zero_is_valid(self):
        self.receive(self.pending(1,True,peak=64))
        self.receive(self.pending(2,False,peak=0))
        data=self.client.get('/api/command-memory').get_json()
        self.assertEqual(data['valid'],2)
        self.assertEqual(data['latest']['heap_peak'],0)
        groups={(g['command'],g['mode']):g for g in data['groups']}
        self.assertEqual(groups['ON','on']['peak_mean'],64)
        self.assertEqual(groups['ON','off']['peak_mean'],0)
        self.assertEqual(groups['OFF','on']['n'],0)
        csv_text=self.client.get('/api/command-memory.csv').get_data(as_text=True).lstrip('\ufeff')
        rows=list(csv.DictReader(io.StringIO(csv_text)))
        self.assertEqual(rows[0]['heap_retained'],'0')
        self.assertEqual(rows[0]['heap_peak'],'64')
        self.assertEqual(rows[0]['stack_peak'],'180')
        self.assertEqual(rows[1]['heap_peak'],'0')

    def test_stack_peak_groups_and_legacy_rows(self):
        self.receive(self.pending(1,True,'ON',peak=0,stack_peak=900))
        self.receive(self.pending(2,True,'ON',peak=0,stack_peak=940))
        self.receive(self.pending(3,True,'OFF',peak=0,stack_peak=500))
        legacy=self.pending(4,True,'OFF',peak=0)
        legacy['memory']={k:v for k,v in legacy['memory'].items() if k!='stack_peak'}|{'v':1}
        self.receive(legacy)
        data=self.client.get('/api/command-memory').get_json()
        self.assertEqual(data['valid'],4)
        self.assertEqual(data['legacy'],1)
        groups={(g['command'],g['mode']):g for g in data['groups']}
        self.assertEqual(groups['ON','on']['stack_n'],2)
        self.assertEqual(groups['ON','on']['stack_mean'],920)
        self.assertEqual(groups['ON','on']['stack_max'],940)
        self.assertEqual(groups['OFF','on']['stack_n'],1)
        self.assertEqual(groups['OFF','on']['stack_mean'],500)
        self.assertIsNone(groups['ON','off']['stack_mean'])

    def test_wrong_mode_id_duplicate_and_rejected_are_excluded(self):
        ack=self.pending()
        self.receive(dict(ack,aes_enabled=False))
        self.receive(dict(ack,command_id='f'*16))
        self.receive(dict(ack,command='OFF'))
        self.assertEqual(self.client.get('/api/command-memory').get_json()['valid'],0)
        self.receive(ack)
        self.receive(dict(ack,memory=sample(peak=999)))
        self.assertEqual(self.client.get('/api/command-memory').get_json()['latest']['heap_peak'],64)
        rejected=self.pending(2)
        self.receive(dict(rejected,phase='rejected',status='BUSY'))
        self.assertEqual(self.client.get('/api/command-memory').get_json()['valid'],1)

    def test_missing_and_invalid_samples_never_become_zero(self):
        ack=self.pending()
        ack.pop('memory')
        self.receive(ack)
        ack=self.pending(2)
        ack['memory']['valid']=False
        self.receive(ack)
        data=self.client.get('/api/command-memory').get_json()
        self.assertEqual(data['valid'],0)
        self.assertEqual(data['unavailable'],2)
        self.assertNotIn('heap_peak',data['latest'])
        for field in FIELDS:
            for value in (True,-1,'64',None,float('nan'),float('inf'),17000000):
                with self.subTest(field=field,value=value):
                    m=sample();m[field]=value
                    self.assertEqual(parse_memory(dict(memory=m,aes_enabled=True),True)['status'],'invalid')
        for changes in ({'heap_retained':65},{'allocations':0},{'context_bytes':0},
                        {'stack_peak':0},{'stack_peak':65537},{'v':3}):
            self.assertEqual(parse_memory(dict(memory=sample()|changes,aes_enabled=True),True)['status'],'invalid')
        legacy={k:v for k,v in sample().items() if k!='stack_peak'}|{'v':1}
        self.assertEqual(parse_memory(dict(memory=legacy,aes_enabled=True),True)['status'],'valid')

    def test_on_off_and_modes_stay_separate(self):
        for i,(cmd,aes,peak) in enumerate([('ON',True,64),('ON',True,128),('OFF',True,256),('ON',False,0),('OFF',False,16)],1):
            self.receive(self.pending(i,aes,cmd,peak))
        data=self.client.get('/api/command-memory').get_json()
        means={(g['command'],g['mode']):g['peak_mean'] for g in data['groups']}
        self.assertEqual(means,{('ON','on'):96,('OFF','on'):256,('ON','off'):0,('OFF','off'):16})
        self.assertEqual(self.client.get('/api/command-memory?date=bad').status_code,400)
        self.assertEqual(self.client.get('/api/command-memory.csv?date=bad').status_code,400)

    def test_ingest_rejects_retained_and_preserves_real_zero(self):
        ack=self.pending(aes=False,peak=0)
        self.d.ingest(STATUS_TOPIC,json.dumps(ack).encode(),retained=True)
        self.assertEqual(self.client.get('/api/command-memory').get_json()['valid'],0)
        self.d.ingest(STATUS_TOPIC,json.dumps(ack).encode())
        self.assertEqual(self.client.get('/api/command-memory').get_json()['latest']['heap_peak'],0)

    def test_old_schema_migration_and_new_data_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'memory.sqlite3'
            store=Store(path)
            store.record_measurement(dict(ts=time.time(),mode='on',source='command',outcome='applied',command_id='old',command='ON'))
            store.db.execute('ALTER TABLE measurements DROP COLUMN command_memory_json')
            store.db.commit();store.close()
            store=Store(path)
            self.assertIsNone(store.db.execute('SELECT command_memory_json FROM measurements').fetchone()[0])
            store.record_measurement(dict(ts=time.time(),mode='on',source='command',outcome='pending',command_id='new',command='ON'))
            memory=parse_memory(dict(memory=sample(),aes_enabled=True),True)
            store.finish_measurement('new','applied',memory=memory)
            store.close()
            store=Store(path)
            row=store.db.execute("SELECT command_memory_json FROM measurements WHERE command_id='new'").fetchone()
            self.assertEqual(json.loads(row[0])['heap_peak'],64)
            store.close()


if __name__=='__main__':
    unittest.main()
