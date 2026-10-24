(() => {
  const el = id => document.getElementById(id);
  const number = value => value == null ? '—' : new Intl.NumberFormat('vi-VN', {maximumFractionDigits: 1}).format(value);
  const mode = value => value === 'on' ? 'Bật' : 'Tắt';
  const labels = {valid: 'Hợp lệ', missing: 'Chưa có số đo', invalid: 'Số đo không hợp lệ'};
  let busy = false;
  el('memoryDate').value = new Intl.DateTimeFormat('en-CA', {timeZone:'Asia/Ho_Chi_Minh',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
  function row(body, cells) {
    const tr = document.createElement('tr');
    for (const value of cells) { const td=document.createElement('td');td.textContent=value;tr.append(td); }
    body.append(tr);return tr;
  }
  async function refreshMemory() {
    if (busy || !el('memoryDate').value) return;
    busy = true;
    const day = el('memoryDate').value;
    el('memoryCsv').href = '/api/command-memory.csv?date='+encodeURIComponent(day);
    try {
      const r=await fetch('/api/command-memory?date='+encodeURIComponent(day));
      if (!r.ok) throw new Error('Không tải được số đo bộ nhớ.');
      const data=await r.json();if(day !== el('memoryDate').value)return;
      const latest=data.latest, good=latest?.status==='valid';
      el('memoryLatest').textContent=latest ? `${latest.command} · AES ${mode(latest.mode)} · ${latest.command_id} · ${new Date(latest.ts*1000).toLocaleTimeString('vi-VN')} · ${labels[latest.status]}${latest.v===2?'':' · v1, không có stack đỉnh'}` : 'Chờ lệnh ON/OFF và số đo từ firmware mới.';
      for(const [id,key] of [['memoryStackPeak','stack_peak'],['memoryPeak','heap_peak'],['memoryContext','context_bytes'],['memoryRetained','heap_retained']])el(id).textContent=number(good?latest[key]:null);
      el('memorySummary').textContent=`${data.valid} mẫu hợp lệ · ${data.unavailable} lệnh chưa có số đo hợp lệ · ${data.legacy} mẫu v1 không có stack đỉnh. Xét tối đa ${data.limit.toLocaleString('vi-VN')} bản ghi gần nhất trong ngày; CSV xuất tối đa 100.000 bản ghi.`;
      el('memoryGroups').replaceChildren();
      for(const g of data.groups){
        const counterpart=data.groups.find(x=>x.command===g.command&&x.mode==='off');
        const delta=g.mode==='on'&&g.stack_n&&counterpart?.stack_n?g.stack_mean-counterpart.stack_mean:null;
        row(el('memoryGroups'),[g.command,g.mode==='on'?'AES bật':'AES tắt',g.n,number(g.stack_mean),number(g.stack_max),number(delta),number(g.peak_mean),number(g.peak_max)]);
      }
      el('memoryRows').replaceChildren();
      for(const s of data.samples){
        const ok=s.status==='valid', stack=ok&&s.v===2;
        const tr=row(el('memoryRows'),[new Date(s.ts*1000).toLocaleTimeString('vi-VN'),`${s.command} / ${mode(s.mode)}`,number(stack?s.stack_peak:null),number(ok?s.heap_peak:null),number(ok?s.heap_retained:null),ok?`${number(s.heap_before)} → ${number(s.heap_after)}`:'—',number(ok?s.allocations:null),labels[s.status]]);
        const id=document.createElement('span');id.className='memory-id';id.textContent=s.command_id;tr.children[0].append(id);
      }
      if(!data.samples.length){const tr=row(el('memoryRows'),['Chưa có số đo bộ nhớ từng lệnh.']);tr.children[0].colSpan=8;}
    } catch(e){el('memoryLatest').textContent=e.message;for(const id of ['memoryStackPeak','memoryPeak','memoryContext','memoryRetained'])el(id).textContent='—';}
    finally{busy=false;}
  }
  el('memoryDate').addEventListener('change',refreshMemory);
  (async function poll(){if(!document.hidden&&!el('controlPage').hidden)await refreshMemory();setTimeout(poll,2000);})();
})();
