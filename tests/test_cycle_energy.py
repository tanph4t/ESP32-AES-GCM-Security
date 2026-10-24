import csv,io,json,sys,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'main'))
import web_server as web
import cycle_energy_web as cycle

def energy_report(ident,cycles,enabled,ids,**extra):
    duration=10000000;energy=6.0 if enabled else 5.0
    r=dict(event='done',protocol=1,id=ident,aes=enabled,valid=True,aborted=False,interference=False,network_bad=False,
        target_commands=cycles*2,applied=len(ids),duration_us=duration,samples=500,errors=0,max_gap_us=20000,
        covered_us=9980000,energy_j=energy,mean_power_w=energy/10,mean_voltage_v=5,
        mean_current_ma=energy*20,cpu_mhz=160,wifi_ps=1,command_ids=ids)
    r.update(extra);return r

class FormulaTests(unittest.TestCase):
    def test_workload_denominators_and_signed_difference(self):
        ids=[f'{i:016x}' for i in range(200)]
        a=cycle.evaluate(energy_report('a'*16,100,True,ids),100,True,ids,200)
        b=cycle.evaluate(energy_report('b'*16,100,False,ids),100,False,ids,200)
        self.assertAlmostEqual(a['joule_per_cycle'],.06);self.assertAlmostEqual(a['joule_per_command'],.03)
        result=cycle.compare([dict(pair_no=1,mode='on',report=a),dict(pair_no=1,mode='off',report=b)])
        self.assertAlmostEqual(result['delta'],.01);self.assertAlmostEqual(result['percent'],20)
        a['joule_per_cycle']=.04
        self.assertLess(cycle.compare([dict(pair_no=1,mode='on',report=a),dict(pair_no=1,mode='off',report=b)])['delta'],0)
    def test_partial_errors_wrong_ids_and_missing_samples_never_normalized(self):
        ids=['a'*16,'b'*16]
        for changes in ({'errors':1},{'command_ids':list(reversed(ids))},{'interference':True},
                        {'network_bad':True},{'aborted':True},{'duration_us':500000},{'valid':False}):
            result=cycle.evaluate(energy_report('f'*16,1,True,ids,**changes),1,True,ids,2)
            self.assertFalse(result['valid']);self.assertIsNone(result['joule_per_cycle'])
        result=cycle.evaluate(energy_report('f'*16,100,True,ids),100,True,ids,2)
        self.assertIsNone(result['joule_per_command'])
        report=energy_report('f'*16,1,True,[],samples=0,energy_j=None,mean_power_w=None,mean_voltage_v=None,mean_current_ma=None,valid=False)
        self.assertIsNone(cycle.evaluate(report,1,True,[],0)['joule_per_cycle'])
    def test_protocol_authentication_and_bounds(self):
        for action in ('START','ABORT'):
            wire=bytes.fromhex(cycle.packet(web.AES_KEY,action,'a'*16,'BC'*16,100))
            text=AESGCM(web.AES_KEY).decrypt(wire[:12],wire[36:]+wire[12:28],wire[28:36]+cycle.REQUEST.encode()).decode()
            self.assertTrue(text.startswith(action+':'));self.assertIn('BC'*16,text)
            bad=bytearray(wire);bad[-1]^=1
            with self.assertRaises(InvalidTag):AESGCM(web.AES_KEY).decrypt(bytes(bad[:12]),bytes(bad[36:]+bad[12:28]),wire[28:36]+cycle.REQUEST.encode())
        for cfg in ({},{'confirmed':True,'cycles':0},{'confirmed':True,'cycles':101},{'confirmed':True,'pairs':6}):
            with self.assertRaises(ValueError):cycle.config(cfg)
    def test_repeated_pairs_ci_and_invalid_exclusion(self):
        blocks=[]
        for i,delta in enumerate((-.01,0,.01)):
            blocks.extend([dict(pair_no=i,mode='off',report=dict(valid=True,joule_per_cycle=.1)),
                dict(pair_no=i,mode='on',report=dict(valid=True,joule_per_cycle=.1+delta))])
        r=cycle.compare(blocks);self.assertEqual(r['n'],3);self.assertLess(r['ci'][0],0);self.assertGreater(r['ci'][1],0)
        blocks[0]['report']['valid']=False
        self.assertEqual(cycle.compare(blocks)['n'],2)

class FakeDevice:
    def __init__(self,d):self.d=d;self.challenge='AB'*16;self.counter=0;self.capture=None;self.blocks=[];self.mode_order=[]
    def rotate(self):self.counter+=1;self.challenge=f'{self.counter:032X}';return self.challenge
    def outer(self,payload,topic):
        raw=bytes.fromhex(payload)
        return AESGCM(web.AES_KEY).decrypt(raw[:12],raw[36:]+raw[12:28],raw[28:36]+(topic.encode() if topic!=web.TOPIC else b'')).decode()
    def emit(self,data):self.d.cycle_energy.ingest(json.dumps(data).encode())
    def finish(self,abort=False):
        c=self.capture
        r=energy_report(c['id'],c['cycles'],self.d.aes_enabled,list(c['ids']),aborted=abort,valid=not abort,challenge=self.challenge)
        self.blocks.append(r);self.capture=None;self.emit(r)
    def publish(self,topic,payload,**kw):
        if topic==web.MODE_TOPIC:
            if payload=='GET':
                self.d.ingest(web.STATUS_TOPIC,json.dumps(dict(status='MODE_STATE',aes_enabled=self.d.aes_enabled,
                    mode_challenge=self.challenge,relay_on=self.d.last_state)).encode())
            else:
                text=self.outer(payload,topic);parts=text.split(':');enabled=parts[0]=='AES=1'
                if parts[2]!=self.challenge:return SimpleNamespace(rc=1)
                self.mode_order.append(enabled)
                self.d.ingest(web.STATUS_TOPIC,json.dumps(dict(status='MODE_CHANGED',aes_enabled=enabled,
                    mode_challenge=self.rotate(),request_id=parts[1],relay_on=self.d.last_state)).encode())
        elif topic==cycle.REQUEST:
            parts=self.outer(payload,topic).split(':');action,ident=parts[:2]
            if parts[-1]!=self.challenge:return SimpleNamespace(rc=1)
            self.rotate()
            if action=='START':
                self.capture=dict(id=ident,cycles=int(parts[2]),ids=[])
                self.emit(dict(event='ready',protocol=1,id=ident,challenge=self.challenge))
            elif self.capture:self.finish(True)
            else:self.emit(dict(event='idle',protocol=1,id=ident,challenge=self.challenge))
        elif topic==web.TOPIC:
            plain=self.outer(payload,topic) if self.d.aes_enabled else payload
            command,ident=plain.split(':')
            self.d.ingest(web.STATUS_TOPIC,json.dumps(dict(status='UNLOCKED' if command=='ON' else 'LOCKED',
                command_id=ident,command=command,phase='applied',aes_enabled=self.d.aes_enabled,decrypt_us=250,
                execution_us=2000)).encode())
            if self.capture:
                self.capture['ids'].append(ident)
                if len(self.capture['ids'])==2*self.capture['cycles']:self.finish()
        return SimpleNamespace(rc=0)

class BatchTests(unittest.TestCase):
    def setUp(self):
        self.app=web.create_app(':memory:');self.d=self.app.extensions['dashboard'];self.m=self.d.cycle_energy
        self.d.connected=True;self.d.aes_enabled=self.d.firmware_aes=True
        self.d.firmware_mode_ts=self.d.last_seen=self.d.last_state_ts=self.d.sensor_ts=time.time()
        self.d.last_state=False;self.d.sensor_ok=True;self.d.metrics['voltage_v']=dict(value=5,ts=time.time())
        self.d.mode_challenge='AB'*16;self.m.supported=True
        self.device=FakeDevice(self.d);self.d.client=self.device
    def tearDown(self):
        self.m.cancel.set()
        if self.m.thread:self.m.thread.join(3)
        self.d.store.close()
    def run_batch(self,**options):
        ident=self.m.start(dict(confirmed=True,**options));self.m.thread.join(5)
        self.assertFalse(self.m.thread.is_alive())
        return ident,self.m.snapshot(ident)
    def test_100_cycles_both_modes_fresh_ids_ack_and_csv(self):
        ident,s=self.run_batch(cycles=100,pairs=1)
        self.assertEqual(s['session']['status'],'completed',s['session']['message'])
        self.assertEqual([b['status'] for b in s['blocks']],['valid','valid'])
        self.assertEqual([len(b['command_ids']) for b in self.device.blocks],[200,200])
        self.assertEqual(len(set(self.device.blocks[0]['command_ids']+self.device.blocks[1]['command_ids'])),400)
        self.assertAlmostEqual(s['comparison']['delta'],.01)
        rows=list(csv.DictReader(io.StringIO(self.m.csv(ident,True).lstrip('\ufeff'))))
        self.assertEqual(len(rows),402);self.assertEqual(sum(r['seq']=='0' for r in rows),2)
        self.assertTrue(self.d.aes_enabled)
        self.assertEqual(self.app.test_client().get('/api/cycle-energy.csv?session='+ident).status_code,200)
    def test_alternating_order_multiple_pairs(self):
        _,s=self.run_batch(cycles=2,pairs=2,first='off')
        self.assertEqual(s['comparison']['n'],2)
        self.assertEqual([b['mode'] for b in s['blocks']],['off','on','on','off'])
    def test_control_guards_and_csrf_and_readiness(self):
        self.m.active='a'*16
        with self.assertRaises(ConnectionError):self.d.send('control','ON')
        with self.assertRaises(ConnectionError):self.d.change_mode(False)
        self.m.active=None
        self.assertEqual(self.app.test_client().post('/api/cycle-energy/start',json={}).status_code,403)
        self.d.metrics['voltage_v']['value']=12
        with self.assertRaises(ValueError):self.m.start(dict(confirmed=True))
    def test_unknown_retained_duplicate_results_ignored(self):
        self.m.expected='a'*16
        r=dict(event='ready',id='a'*16,protocol=1,challenge='AB'*16)
        self.m.ingest(json.dumps(r).encode(),True);self.assertFalse(self.m.messages)
        self.m.ingest(json.dumps(dict(r,id='b'*16)).encode());self.assertFalse(self.m.messages)
        self.m.ingest(json.dumps(r).encode());self.m.ingest(json.dumps(dict(r,challenge='CD'*16)).encode())
        self.assertEqual(self.m.messages['ready']['challenge'],'AB'*16)
    def test_stop_after_complete_cycle_partial_not_divided(self):
        original=self.device.publish
        def publish(topic,payload,**kw):
            result=original(topic,payload,**kw)
            if self.device.capture and len(self.device.capture['ids'])==1:self.m.cancel.set()
            return result
        self.d.client=SimpleNamespace(publish=publish)
        _,s=self.run_batch(cycles=100)
        self.assertEqual(s['session']['status'],'stopped')
        r=s['blocks'][0]['report'];self.assertFalse(r['valid']);self.assertIsNone(r['joule_per_cycle'])
        self.assertEqual(r['raw']['applied'],2);self.assertFalse(self.d.last_state)
    def test_missing_result_produces_failed_record_not_fake_energy(self):
        original=self.m.wait_message
        def wait(kind,timeout=8):
            if kind=='ready':raise ValueError('Hết hạn ready')
            return original(kind,timeout)
        with patch.object(self.m,'wait_message',side_effect=wait):_,s=self.run_batch(cycles=2)
        self.assertEqual(s['session']['status'],'failed');self.assertIsNone(s['blocks'][0]['report']['joule_per_cycle'])
    def test_device_finishes_early_stops_sequence_and_recovers_off(self):
        original=self.device.publish
        def publish(topic,payload,**kw):
            result=original(topic,payload,**kw)
            if self.device.capture and len(self.device.capture['ids'])==1:self.device.finish(True)
            return result
        self.d.client=SimpleNamespace(publish=publish)
        _,s=self.run_batch(cycles=100)
        self.assertEqual(s['session']['status'],'failed')
        self.assertEqual(self.device.blocks[0]['applied'],1)
        self.assertFalse(self.d.last_state)
        self.assertIsNone(s['blocks'][0]['report']['joule_per_cycle'])
    def test_missing_abort_confirmation_does_not_restore_using_old_challenge(self):
        original_command=self.m.command
        original_wait=self.m.wait_message
        def command(block,action,seq):
            if seq==1:raise ValueError('ACK timeout')
            return original_command(block,action,seq)
        def wait(kind,timeout=8):
            if kind=='done':raise ValueError('Abort reply lost')
            return original_wait(kind,timeout)
        with patch.object(self.m,'command',side_effect=command),patch.object(self.m,'wait_message',side_effect=wait):
            _,s=self.run_batch(cycles=2,first='off')
        self.assertEqual(s['session']['status'],'failed')
        self.assertTrue(s['firmware_busy'])
        self.assertEqual(self.device.mode_order,[False])
        self.assertIn('chưa khôi phục AES',s['session']['message'])
        self.assertIsNone(s['blocks'][0]['report']['joule_per_cycle'])
    def test_restart_and_firmware_busy_recovery_guards(self):
        self.m.firmware_busy=True
        with self.assertRaises(ConnectionError):self.d.send('control','ON')
        with self.assertRaises(ConnectionError):self.d.change_mode(False)
        with self.d.store.lock,self.d.store.db:
            self.d.store.db.execute('INSERT INTO cycle_sessions VALUES(?,?,?,?,?)',('f'*16,time.time(),'running','{}',''))
            self.d.store.db.execute('INSERT INTO cycle_blocks VALUES(?,?,?,?,?,?)',('e'*16,'f'*16,1,'on','running',None))
        cycle.CycleEnergy(self.d,web.AES_KEY)
        with self.d.store.lock:
            self.assertEqual(self.d.store.db.execute('SELECT status FROM cycle_sessions WHERE id=?',('f'*16,)).fetchone()[0],'interrupted')
            self.assertEqual(self.d.store.db.execute('SELECT status FROM cycle_blocks WHERE id=?',('e'*16,)).fetchone()[0],'interrupted')

if __name__=='__main__':unittest.main()
