"""Compare energy for equal ON/OFF workloads; never normalize incomplete blocks."""
import csv,io,json,math,secrets,statistics,struct,threading,time,re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
REQUEST='device/esp32/cycle-energy/request'
RESULT='device/esp32/cycle-energy/result'

def config(data):
    if not isinstance(data,dict) or data.get('confirmed') is not True:
        raise ValueError('Xác nhận nguồn đo 5 V và việc chạy ON/OFF thực tế trước khi bắt đầu.')
    cycles=data.get('cycles',100);pairs=data.get('pairs',1);first=data.get('first','on')
    if type(cycles) is not int or not 1<=cycles<=100:raise ValueError('Chọn 1–100 chu kỳ mỗi đợt.')
    if type(pairs) is not int or not 1<=pairs<=5:raise ValueError('Chọn 1–5 cặp đợt.')
    if first not in ('on','off'):raise ValueError('Chọn chế độ thử trước.')
    return dict(cycles=cycles,pairs=pairs,first=first,confirmed=True,protocol=1)

def packet(key,action,ident,challenge,cycles=100):
    if action not in ('START','ABORT') or not re.fullmatch('[0-9a-f]{16}',ident) or not re.fullmatch('[0-9A-Fa-f]{32}',str(challenge)):
        raise ValueError('Thiếu mã đợt/challenge hợp lệ.')
    text=f'{action}:{ident}:'+ (str(cycles)+':' if action=='START' else '')+challenge
    nonce=secrets.token_bytes(12);ts=struct.pack('<Q',int(time.time()))
    sealed=AESGCM(key).encrypt(nonce,text.encode(),ts+REQUEST.encode())
    return (nonce+sealed[-16:]+ts+sealed[:-16]).hex().upper()

def evaluate(report,cycles,enabled,command_ids,acked):
    if type(report.get('protocol')) is not int or report['protocol']!=1 or report.get('event')!='done':raise ValueError('Sai giao thức kết quả.')
    if type(report.get('aes')) is not bool or report['aes']!=enabled:raise ValueError('Sai chế độ AES.')
    for f in ('valid','aborted','interference','network_bad'):
        if type(report.get(f)) is not bool:raise ValueError('Thiếu trạng thái '+f)
    for f in ('target_commands','applied','duration_us','samples','errors','max_gap_us','covered_us','cpu_mhz'):
        if type(report.get(f)) is not int or not 0<=report[f]<=1e12:raise ValueError('Bộ đếm không hợp lệ: '+f)
    if report['target_commands']!=cycles*2:raise ValueError('Sai số lệnh mục tiêu.')
    ids=report.get('command_ids')
    if not isinstance(ids,list) or len(ids)>200 or any(not isinstance(i,str) or not re.fullmatch('[0-9a-f]{16}',i) for i in ids):raise ValueError('Danh sách mã lệnh không hợp lệ.')
    reasons=[]
    if ids!=command_ids or len(ids)!=len(set(ids)) or report['applied']!=len(ids):reasons.append('Mã/thứ tự lệnh trên ESP32 không khớp máy chủ')
    if acked!=cycles*2 or len(command_ids)!=cycles*2 or report['applied']!=cycles*2:reasons.append('Chưa hoàn tất đủ số lệnh có ACK')
    duration=report['duration_us']
    if duration<1000000:reasons.append('Đợt đo dưới 1 giây; tăng số chu kỳ')
    if report['samples']<30 or report['errors'] or report['max_gap_us']>100000 or report['covered_us']<duration*.9:reasons.append('Thiếu mẫu/lỗi cảm biến/khoảng trống >100 ms/độ phủ <90%')
    for f in ('energy_j','mean_power_w','mean_voltage_v','mean_current_ma'):
        value=report.get(f)
        if report['samples']==0 and value is None:continue
        if type(value) not in (int,float) or not math.isfinite(value) or abs(value)>1e9:raise ValueError('Số đo không hợp lệ: '+f)
    if report.get('mean_voltage_v') is None or not 4<=report['mean_voltage_v']<=5.5 or report.get('mean_power_w') is None or report['mean_power_w']<=0:reasons.append('Kiểm tra nhánh 5 V/chiều dòng INA219')
    if duration>0 and report['samples'] and not math.isclose(report['mean_power_w'],report['energy_j']*1e6/duration,rel_tol=1e-5,abs_tol=1e-6):reasons.append('Năng lượng không khớp công suất và thời lượng')
    if report['aborted'] or report['interference'] or report['network_bad'] or not report['valid']:reasons.append('Firmware báo dừng/can thiệp/mất mạng hoặc chất lượng không hợp lệ')
    valid=not reasons
    return dict(raw=report,valid=valid,reasons=reasons,energy_j=report.get('energy_j'),acknowledged=acked,
        joule_per_cycle=report['energy_j']/cycles if valid else None,
        joule_per_command=report['energy_j']/(2*cycles) if valid else None)

def compare(rows):
    pairs={}
    for row in rows:
        if row['report'] and row['report'].get('valid'):pairs.setdefault(row['pair_no'],{})[row['mode']]=row['report']
    complete=[p for p in pairs.values() if 'on' in p and 'off' in p]
    if not complete:return dict(n=0,on=None,off=None,delta=None,percent=None,sd=None,ci=None)
    on=statistics.mean(p['on']['joule_per_cycle'] for p in complete);off=statistics.mean(p['off']['joule_per_cycle'] for p in complete)
    differences=[p['on']['joule_per_cycle']-p['off']['joule_per_cycle'] for p in complete]
    sd=statistics.stdev(differences) if len(differences)>1 else None
    ts={2:12.706,3:4.303,4:3.182,5:2.776};delta=statistics.mean(differences)
    margin=ts[len(differences)]*sd/math.sqrt(len(differences)) if sd is not None else None
    return dict(n=len(complete),on=on,off=off,delta=delta,percent=delta/off*100 if off else None,
                sd=sd,ci=[delta-margin,delta+margin] if margin is not None else None)

class CycleEnergy:
    def __init__(self,d,key):
        self.d,self.key=d,key;self.lock=threading.RLock();self.condition=threading.Condition(self.lock)
        self.active=None;self.token=object();self.cancel=threading.Event();self.thread=None
        self.expected=None;self.messages={};self.acks={};self.progress='';self.current=None
        self.supported=False;self.firmware_id='';self.firmware_busy=False
        with d.store.lock,d.store.db:
            d.store.db.execute('CREATE TABLE IF NOT EXISTS cycle_sessions(id TEXT PRIMARY KEY,created REAL,status TEXT,config TEXT,message TEXT)')
            d.store.db.execute('CREATE TABLE IF NOT EXISTS cycle_blocks(id TEXT PRIMARY KEY,session TEXT,pair_no INTEGER,mode TEXT,status TEXT,report TEXT)')
            d.store.db.execute('CREATE TABLE IF NOT EXISTS cycle_commands(command_id TEXT PRIMARY KEY,block_id TEXT,seq INTEGER,command TEXT,outcome TEXT)')
            d.store.db.execute("UPDATE cycle_sessions SET status='interrupted',message='Web khởi động lại; không tự tiếp tục điều khiển.' WHERE status='running'")
            d.store.db.execute("UPDATE cycle_blocks SET status='interrupted' WHERE status='running'")
    def running(self):
        with self.lock:return self.active is not None
    def authorized(self,token):return token is self.token
    def blocked(self):
        d=self.d
        if d.offline or not d.connected or not d.client:return 'Cần MQTT/TLS.'
        if not self.supported:return 'Cần nạp firmware hỗ trợ đo năng lượng theo đợt.'
        if self.firmware_busy:return 'ESP32 còn đợt đo; dùng Dừng/khôi phục trước khi chạy mới.'
        if d.pending_commands or d.pending_mode:return 'Chờ phép thử/lệnh đang chạy hoàn tất.'
        if not d.last_seen or time.time()-d.last_seen>30 or not d.mode_challenge:return 'Chờ trạng thái và challenge mới.'
        if type(d.last_state) is not bool or not d.last_state_ts or time.time()-d.last_state_ts>30:return 'Chờ trạng thái đầu ra mới từ ESP32.'
        if d.sensor_ok is not True or not d.sensor_ts or time.time()-d.sensor_ts>5:return 'Chờ số đo INA219 hợp lệ mới.'
        v=d.metrics.get('voltage_v',{}).get('value')
        if type(v) not in (int,float) or not 4<=v<=5.5:return 'INA219 cần đo nhánh nguồn ESP32 5 V.'
        return None
    def start(self,data):
        cfg=config(data)
        with self.d.send_lock,self.d.lock,self.lock:
            if self.active:raise ValueError('Đang chạy đợt đo.')
            reason=self.blocked()
            if reason:raise ValueError(reason)
            ident=secrets.token_hex(8)
            with self.d.store.lock,self.d.store.db:self.d.store.db.execute('INSERT INTO cycle_sessions VALUES(?,?,?,?,?)',(ident,time.time(),'running',json.dumps(cfg),'Đang chuẩn bị.'))
            self.active=ident;self.cancel.clear();self.acks={};self.messages={}
            self.thread=threading.Thread(target=self.run,args=(ident,cfg),daemon=True);self.thread.start();return ident
    def stop(self):
        self.cancel.set()
        if not self.running() and self.firmware_busy and re.fullmatch('[0-9a-f]{16}',self.firmware_id):
            self.control('ABORT',self.firmware_id)
            self.d.last_mode_query=0
    def ingest(self,payload,retained=False):
        if retained or len(payload)>12000:return
        data=json.loads(payload)
        if not isinstance(data,dict):return
        with self.condition:
            if data.get('id')!=self.expected or data.get('event') not in ('ready','done','idle','error'):return
            key=data['event']
            if key not in self.messages:self.messages[key]=data;self.condition.notify_all()
    def ack(self,data):
        with self.condition:
            if self.active:
                self.acks[data['command_id']]=dict(data);self.condition.notify_all()
    def disconnected(self):
        with self.condition:self.condition.notify_all()
    def control(self,action,ident,cycles=100):
        with self.d.lock:
            if not self.d.connected or not self.d.client:raise ValueError('Không có kết nối MQTT để gửi yêu cầu đo.')
            wire=packet(self.key,action,ident,self.d.mode_challenge,cycles)
        if self.d.client.publish(REQUEST,wire,qos=0,retain=False).rc!=0:raise ValueError('Không gửi được yêu cầu đo.')
    def wait_message(self,kind,timeout=8):
        with self.condition:
            ok=self.condition.wait_for(lambda:kind in self.messages or (kind=='done' and 'idle' in self.messages) or 'error' in self.messages or not self.d.connected,timeout)
            if not ok or not self.d.connected:raise ValueError('Mất kết nối/hết hạn kết quả đo.')
            if 'error' in self.messages:raise ValueError(self.messages['error'].get('reason','ESP32 từ chối.'))
            msg=self.messages.get(kind) or self.messages['idle']
        if type(msg.get('protocol')) is not int or msg['protocol']!=1:raise ValueError('Sai phiên bản phản hồi đo.')
        challenge=msg.get('challenge')
        if challenge is not None or kind=='ready':
            if not re.fullmatch('[0-9A-Fa-f]{32}',str(challenge)):raise ValueError('Challenge phản hồi không hợp lệ.')
            with self.d.lock:self.d.mode_challenge=challenge
        if msg.get('event') in ('done','idle'):
            with self.lock:self.firmware_busy=False;self.firmware_id=''
        return msg
    def command(self,block_id,command,seq):
        packet_sent=self.d.send('control',command,batch_token=self.token);ident=packet_sent['command_id']
        with self.d.store.lock,self.d.store.db:self.d.store.db.execute('INSERT INTO cycle_commands VALUES(?,?,?,?,?)',(ident,block_id,seq,command,'pending'))
        with self.condition:
            ok=self.condition.wait_for(lambda:ident in self.acks or not self.d.connected,8)
            ack=self.acks.pop(ident,None)
        valid=ok and ack is not None and ack.get('phase')=='applied' and ack.get('command')==command and ack.get('aes_enabled') is self.d.aes_enabled
        with self.d.store.lock,self.d.store.db:self.d.store.db.execute('UPDATE cycle_commands SET outcome=? WHERE command_id=?',('applied' if valid else 'failed',ident))
        if not valid:
            reason=('Mất kết nối MQTT với máy chủ.' if not self.d.connected else
                    'Không nhận ACK trong 8 giây.' if ack is None else 'ACK không khớp lệnh/chế độ hoặc GPIO bị từ chối.')
            raise ValueError(f'Lệnh {command}, ID {ident}: {reason} Đợt đo không hợp lệ.')
        return ident
    def save_block(self,ident,status,report):
        with self.d.store.lock,self.d.store.db:self.d.store.db.execute('UPDATE cycle_blocks SET status=?,report=? WHERE id=?',(status,json.dumps(report),ident))
    def run(self,session,cfg):
        original=self.d.aes_enabled;status='completed';message='Hoàn tất; xem các đợt hợp lệ và chênh lệch.'
        epoch=self.d.mqtt_connection_epoch
        try:
            for pair_no in range(1,cfg['pairs']+1):
                first=(cfg['first']=='on') if pair_no%2 else (cfg['first']!='on')
                for enabled in (first,not first):
                    if self.cancel.is_set():break
                    block=secrets.token_hex(8);ids=[];acked=0
                    with self.d.store.lock,self.d.store.db:self.d.store.db.execute('INSERT INTO cycle_blocks VALUES(?,?,?,?,?,?)',(block,session,pair_no,'on' if enabled else 'off','running',None))
                    with self.lock:self.current=dict(id=block,pair_no=pair_no,mode=enabled,acked=0,target=cfg['cycles']*2);self.progress='Chuẩn bị ngoài cửa sổ đo.'
                    started=False
                    try:
                        self.d.change_mode(enabled,batch_token=self.token)
                        # Bring both modes to the same OFF state, outside the measurement.
                        self.command(block,'OFF',0)
                        with self.lock:self.expected=block;self.messages={}
                        self.control('START',block,cfg['cycles']);started=True
                        # START may be accepted even if its reply is lost. Keep the
                        # device unresolved until done/idle or a fresh MODE_STATE.
                        with self.lock:self.firmware_busy=True;self.firmware_id=block
                        self.wait_message('ready')
                        with self.lock:self.firmware_busy=True;self.firmware_id=block
                        for i in range(0 if self.cancel.is_set() else cfg['cycles']):
                            for command in ('ON','OFF'):
                                if self.d.mqtt_connection_epoch!=epoch:raise ValueError('Kết nối MQTT thay đổi trong lượt thử.')
                                with self.lock:early=self.messages.get('done')
                                if early is not None:raise ValueError('ESP32 kết thúc đợt trước khi đủ ACK; dừng gửi lệnh.')
                                ident=self.command(block,command,acked+1);ids.append(ident);acked+=1
                                with self.lock:self.current['acked']=acked;self.progress=f'Đã ACK {acked}/{cfg["cycles"]*2} lệnh.'
                            if self.cancel.is_set():break
                        if acked!=cfg['cycles']*2:
                            self.control('ABORT',block)
                        raw=self.wait_message('done')
                        checked=evaluate(raw,cfg['cycles'],enabled,ids,acked)
                        self.save_block(block,'valid' if checked['valid'] else 'invalid',checked)
                        with self.lock:self.firmware_busy=False;self.firmware_id=''
                    except Exception as exc:
                        raw=None
                        if started and self.d.connected:
                            try:
                                with self.lock:done=self.messages.get('done')
                                if done is None:self.control('ABORT',block)
                                raw=self.wait_message('done',3)
                            except Exception:pass
                        self.save_block(block,'failed',dict(valid=False,reasons=[str(exc)],raw=raw,acknowledged=acked,joule_per_cycle=None,joule_per_command=None))
                        raise
                if self.cancel.is_set():break
            if self.cancel.is_set():status,message='stopped','Đã dừng; đợt thiếu lệnh không tính trung bình.'
        except Exception as exc:status,message='failed',str(exc)
        finally:
            # Settings restoration is outside all energy windows. Never silently claim success.
            if self.firmware_busy:
                message+=' Chưa nhận xác nhận kết thúc/hủy đợt từ ESP32; chưa khôi phục AES. Chờ ESP32 kết nối lại và cập nhật trạng thái trước khi thử lại.'
            elif self.d.connected:
                try:
                    with self.d.lock:self.d._expire_commands()
                    if self.current and self.d.last_state is not False:
                        self.command(self.current['id'],'OFF',999)
                    self.d.request_mode_state(batch_token=self.token)
                    self.d.change_mode(original,batch_token=self.token)
                except Exception as exc:message+=' Không xác nhận được khôi phục AES: '+str(exc)
            with self.d.store.lock,self.d.store.db:self.d.store.db.execute('UPDATE cycle_sessions SET status=?,message=? WHERE id=?',(status,message,session))
            with self.lock:self.active=None;self.expected=None;self.current=None;self.progress=message
    def snapshot(self,ident=None):
        with self.d.lock:reason=self.blocked()
        with self.d.store.lock:
            session=(self.d.store.db.execute('SELECT * FROM cycle_sessions WHERE id=?',(ident,)).fetchone() if ident else self.d.store.db.execute('SELECT * FROM cycle_sessions ORDER BY created DESC LIMIT 1').fetchone())
            history=[dict(r) for r in self.d.store.db.execute('SELECT id,created,status FROM cycle_sessions ORDER BY created DESC LIMIT 20')]
            blocks=[dict(r,report=json.loads(r['report']) if r['report'] else None) for r in self.d.store.db.execute('SELECT * FROM cycle_blocks WHERE session=? ORDER BY rowid',(session['id'],))] if session else []
        selected=dict(session,config=json.loads(session['config'])) if session else None
        with self.lock:return dict(running=self.active,current=self.current,progress=self.progress,blocked_reason=reason,firmware_busy=self.firmware_busy,history=history,session=selected,blocks=blocks,comparison=compare(blocks))
    def csv(self,ident,commands=False):
        snap=self.snapshot(ident)
        if not snap['session']:raise ValueError('Không tìm thấy lượt thử.')
        buf=io.StringIO();buf.write('\ufeff')
        fields=(['session','block_id','pair_no','mode','seq','command_id','command','outcome','encrypt_us','decrypt_us','execution_ms','e2e_ms'] if commands else
            ['session','id','pair_no','mode','status','cycles_target','energy_j','joule_per_cycle','joule_per_command','duration_us','acknowledged','applied','samples','errors','max_gap_us','covered_us','mean_power_w','mean_voltage_v','mean_current_ma','cpu_mhz','wifi_ps','idf_version','hardware_aes','reasons'])
        writer=csv.DictWriter(buf,fieldnames=fields,extrasaction='ignore');writer.writeheader()
        for b in snap['blocks']:
            if commands:
                with self.d.store.lock:rows=self.d.store.db.execute('SELECT c.*,m.encrypt_us,m.decrypt_us,m.execution_ms,m.e2e_ms FROM cycle_commands c LEFT JOIN measurements m ON c.command_id=m.command_id WHERE c.block_id=? ORDER BY c.seq',(b['id'],)).fetchall()
                for row in rows:writer.writerow(dict(row,session=ident,pair_no=b['pair_no'],mode=b['mode']))
            else:
                r=b['report'] or {};raw=r.get('raw') or {};out={**raw,**b,**r};out.update(session=ident,cycles_target=snap['session']['config']['cycles'],reasons='; '.join(r.get('reasons',[])))
                writer.writerow(out)
        return buf.getvalue()
