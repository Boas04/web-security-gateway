'use strict';
const el = id => document.getElementById(id);
const number = value => new Intl.NumberFormat('id-ID').format(value);
const time = seconds => new Date(seconds * 1000).toLocaleString('id-ID', {day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit'});
const shortTime = seconds => new Date(seconds * 1000).toLocaleTimeString('id-ID', {hour:'2-digit', minute:'2-digit'});
const labels = {allowed:'Diizinkan', blocked:'Ditolak', error:'Gagal diproses'};
const reasonLabels = {waf_rule:'Aturan WAF', rate_limit:'Batas permintaan', origin_not_allowed:'Origin ditolak', body_too_large:'Body terlalu besar', compressed_request_not_supported:'Encoding tidak didukung', admin_not_on_public_listener:'Akses admin di port publik', waf_unavailable:'Pemeriksaan keamanan tidak tersedia (WAF)', origin_unavailable:'Aplikasi tujuan tidak dapat dihubungi', ml_review:'Blokir setelah tinjauan admin', forwarded:'Diteruskan'};
const titles = {'machine-learning':'Analisis ML', notifications:'Notifikasi', overview:'Ringkasan', traffic:'Event keamanan', blocks:'Daftar blokir', settings:'Pengaturan proteksi', history:'Riwayat pengaturan'};
const palette = {primary:'#0B64DD', allowed:'#017D73', blocked:'#BD271E', error:'#F5A700', grid:'#EDF0F5', muted:'#69707D'};
const reasonColors = [palette.blocked, palette.error, palette.primary];
const charts = new Map();
let csrf = '', authenticated = false, settingsLoaded = false;
let page = 1, lastStats = null, refreshController = null, refreshSequence = 0, searchTimer;
let expanded = new Set();
let mlSelected = new Set(), mlOrigin = null;

function message(text, error = false) {
  el('message').textContent = text;
  el('message').className = text ? 'notification' + (error ? ' error' : '') : '';
}
async function api(path, data, signal) {
  const options = {signal, credentials:'same-origin'};
  if (data !== undefined) Object.assign(options, {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:JSON.stringify(data)});
  const response = await fetch('/admin/api/' + path, options);
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== 'login') showLogin();
    throw new Error(result.error || 'Permintaan gagal.');
  }
  return result;
}
function setAuthenticated(value) {
  authenticated = value;
  el('workspace').hidden = !value;
  el('login-panel').hidden = value;
  el('user-menu').hidden = !value;
  el('global-search-form').hidden = !value;
  document.body.classList.toggle('authenticated', value);
}
function showLogin() {
  setAuthenticated(false);
  settingsLoaded = false;
  csrf = '';
  lastStats = null;
  expanded.clear();
  mlSelected.clear(); mlOrigin=null;
  refreshSequence++;
  if (refreshController) refreshController.abort();
  for (const chart of charts.values()) chart.destroy();
  charts.clear();
  for (const id of ['events','block-list','audit','sources-table','reasons-legend','notifications-list','ml-models','ml-findings','ml-windows','offense-list']) el(id).replaceChildren();
  el('password').value = '';
}
function selectedView() { const key = location.hash.slice(1); return Object.hasOwn(titles,key) ? key : 'overview'; }
function syncSidebar() {
  const mobile = matchMedia('(max-width: 700px)').matches;
  const open = mobile ? document.body.classList.contains('sidebar-open') : !document.body.classList.contains('sidebar-collapsed');
  el('sidebar-toggle').setAttribute('aria-expanded',String(open));
  el('sidebar-toggle').setAttribute('aria-label',open?'Ciutkan navigasi':'Buka navigasi');
}
function showView() {
  const view = selectedView();
  el('offense-history').hidden=view!=='blocks';
  for (const id of Object.keys(titles)) el(id).hidden = !(id === view || (view === 'overview' && id === 'traffic'));
  el('filter-form').hidden = !['overview','traffic'].includes(view);
  el('filter-help').hidden = el('filter-form').hidden;
  el('health-strip').hidden = !['overview','traffic'].includes(view);
  el('page-title').textContent = titles[view];
  document.title = 'Ruang Guard · ' + titles[view];
  for (const link of document.querySelectorAll('.nav')) {
    const active = link.dataset.view === view;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current');
  }
  document.body.classList.remove('sidebar-open');
  syncSidebar();
  if (view === 'overview' && lastStats) requestAnimationFrame(() => renderCharts(lastStats));
}
function cell(row, text, className = '') {
  const td = document.createElement('td');
  td.textContent = text;
  td.className = className;
  row.append(td);
  return td;
}
function emptyRow(parent, columns, text = 'Belum ada data') {
  const row = document.createElement('tr');
  cell(row, text, 'empty-cell').colSpan = columns;
  parent.append(row);
}
function badge(decision) {
  const span = document.createElement('span');
  span.className = 'badge ' + (Object.hasOwn(labels,decision) ? decision : '');
  span.textContent = labels[decision] || decision;
  return span;
}
function detailItem(list, label, value) {
  const term = document.createElement('dt'), definition = document.createElement('dd');
  term.textContent = label; definition.textContent = value; definition.className = 'mono';
  list.append(term, definition);
}
function renderEvents(stats) {
  const body = el('events');
  const focusedRow = document.activeElement && document.activeElement.dataset.eventId;
  body.replaceChildren();
  for (const event of stats.events) {
    const row = document.createElement('tr'); row.className = 'event-row';
    const button = document.createElement('button'); button.type = 'button'; button.className = 'icon-button row-toggle';
    button.textContent = expanded.has(event.id) ? '−' : '+';
    button.dataset.eventId = String(event.id);
    button.setAttribute('aria-label','Detail event ' + event.id);
    button.setAttribute('aria-expanded', String(expanded.has(event.id)));
    button.setAttribute('aria-controls','event-detail-' + event.id);
    cell(row,'','expand-column').append(button);
    cell(row,time(event.at),'mono');
    const source = cell(row,event.client,'mono truncate source-cell'); source.title = event.client;
    cell(row,event.method,'mono');
    cell(row,event.route,'mono truncate route-cell').title = event.route;
    cell(row,'').append(badge(event.decision));
    cell(row,event.status,'mono');
    const ruleText = event.rules.length ? event.rules.join(', ') + ' · ' + event.reason : event.reason;
    cell(row,ruleText,'mono truncate reason-cell').title = ruleText;
    cell(row,number(event.ms) + ' ms','numeric mono');
    const detail = document.createElement('tr'); detail.id = 'event-detail-' + event.id; detail.className = 'event-detail'; detail.hidden = !expanded.has(event.id);
    const content = cell(detail,''); content.colSpan = 9;
    const list = document.createElement('dl'); list.className = 'detail-grid';
    for (const [key,value] of [['ID event',event.id],['Waktu',time(event.at)],['ID sumber',event.client],['Permintaan',event.method + ' ' + event.route],['Keputusan',labels[event.decision] || event.decision],['HTTP',event.status],['Alasan',event.reason],['ID aturan',event.rules.join(', ') || '—'],['Latensi',number(event.ms) + ' ms']]) detailItem(list,key,value);
    const note = document.createElement('p'); note.className = 'fine'; note.textContent = 'Payload dan isi pengaduan tidak direkam.';
    content.append(list,note);
    button.onclick = () => {
      if (expanded.has(event.id)) expanded.delete(event.id); else expanded.add(event.id);
      detail.hidden = !expanded.has(event.id);
      button.setAttribute('aria-expanded', String(!detail.hidden)); button.textContent = detail.hidden ? '+' : '−';
    };
    body.append(row,detail);
  }
  if (!stats.events.length) emptyRow(body,9);
  if (focusedRow) body.querySelector('[data-event-id="' + focusedRow.replace(/[^0-9]/g,'') + '"]')?.focus({preventScroll:true});
  const pagination = stats.pagination;
  page = pagination.page;
  el('event-count').textContent = number(pagination.total) + ' event';
  el('page-label').textContent = page + ' / ' + Math.max(1,pagination.pages);
  const start = pagination.total ? (page - 1) * pagination.page_size + 1 : 0;
  const end = Math.min(page * pagination.page_size, pagination.total);
  el('page-summary').textContent = number(start) + '–' + number(end) + ' dari ' + number(pagination.total) + ' event';
  el('previous-page').disabled = page <= 1;
  el('next-page').disabled = page >= pagination.pages;
}
function rangeLabel() { return el('time-range').selectedOptions[0].textContent; }
function bucketTitle(stats, index) {
  const at = stats.buckets[index].at;
  return time(at) + ' – ' + time(Math.min(at + stats.bucket_seconds,stats.to));
}
function chartOptions() {
  return {responsive:true, maintainAspectRatio:false, animation:{duration:200},
    plugins:{legend:{display:false}, tooltip:{displayColors:true}},
    scales:{x:{grid:{display:false},border:{display:false},ticks:{color:palette.muted,font:{size:11},maxRotation:0,autoSkip:true,maxTicksLimit:6}},
      y:{beginAtZero:true,border:{display:false},grid:{color:palette.grid},ticks:{color:palette.muted,font:{size:11},precision:0,maxTicksLimit:5}}}};
}
function chart(id, config, hasData, label) {
  const canvas = el(id), parent = canvas.parentElement;
  const empty = parent.querySelector('.chart-empty, .spark-empty');
  canvas.hidden = !hasData;
  empty.hidden = hasData;
  if (!hasData) {
    charts.get(id)?.destroy(); charts.delete(id);
    return;
  }
  canvas.setAttribute('aria-label',label);
  if (charts.has(id)) {
    const current = charts.get(id); current.data = config.data; current.options = config.options;
    current.update('none');
  } else charts.set(id,new Chart(canvas,config));
}
function renderCharts(stats) {
  if (typeof Chart === 'undefined') {
    document.querySelectorAll('canvas').forEach(canvas => {canvas.hidden = true; const empty = canvas.parentElement.querySelector('.chart-empty,.spark-empty'); if(empty){empty.hidden=false;empty.textContent='Grafik tidak dapat dimuat';}});
    return;
  }
  Chart.defaults.font.family = 'Inter, system-ui, -apple-system, Segoe UI, sans-serif';
  Chart.defaults.font.size = 11; Chart.defaults.color = palette.muted;
  const names = stats.buckets.map(bucket => stats.range === '7d' ? new Date(bucket.at*1000).toLocaleString('id-ID',{day:'2-digit',month:'short',hour:'2-digit'}) : shortTime(bucket.at));
  const definitions = [['total','total','Total permintaan',palette.primary],['allowed','allowed','Diizinkan',palette.allowed],['blocked','blocked','Ditolak',palette.blocked],['active-sources','active_sources','Sumber aktif',palette.primary]];
  for (const [id,key,label,color] of definitions) {
    const options = chartOptions(); options.scales = {x:{display:false},y:{display:false,beginAtZero:true}};
    options.interaction = {intersect:false,mode:'index'};
    options.plugins.tooltip.callbacks = {title:items => bucketTitle(stats,items[0].dataIndex), label:item => label + ': ' + number(item.raw)};
    options.animation = false;
    chart('spark-' + id, {type:'line',data:{labels:names,datasets:[{label,data:stats.buckets.map(b=>b[key]),borderColor:color,borderWidth:1.5,pointRadius:0,pointHitRadius:6,tension:0,fill:false}]},options},stats.totals[key] > 0,label + ': ' + number(stats.totals[key]) + ', ' + rangeLabel());
  }
  const options = chartOptions(); options.scales.x.stacked = true; options.scales.y.stacked = true;
  options.interaction = {intersect:false,mode:'index'};
  options.plugins.tooltip.callbacks = {title:items => bucketTitle(stats,items[0].dataIndex),label:item=>item.dataset.label + ': ' + number(item.raw)};
  chart('events-chart',{type:'bar',data:{labels:names,datasets:[['allowed','Diizinkan'],['blocked','Ditolak'],['errors','Gagal diproses']].map(([key,label])=>({label,data:stats.buckets.map(b=>b[key]),backgroundColor:palette[key === 'errors' ? 'error' : key],borderWidth:0,maxBarThickness:28,categoryPercentage:.8,barPercentage:.95}))},options},stats.totals.total > 0,'Event per interval. ' + stats.totals.allowed + ' diizinkan; ' + stats.totals.blocked + ' ditolak; ' + stats.totals.errors + ' gagal diproses.');
  el('events-chart-summary').textContent = stats.buckets.map((bucket,index)=>bucketTitle(stats,index) + ': ' + bucket.allowed + ' diizinkan, ' + bucket.blocked + ' ditolak, ' + bucket.errors + ' gagal diproses.').join(' ');
  const reasonOptions = {responsive:true,maintainAspectRatio:false,animation:{duration:200},cutout:'70%',plugins:{legend:{display:false},tooltip:{callbacks:{title:()=>time(stats.from)+' – '+time(stats.to),label:item=>(reasonLabels[stats.reasons[item.dataIndex].reason] || item.label)+': '+number(item.raw)+' ('+number(Math.round(item.raw/stats.totals.blocked*1000)/10)+'%)'}}}};
  chart('reasons-chart',{type:'doughnut',data:{labels:stats.reasons.map(r=>r.reason),datasets:[{data:stats.reasons.map(r=>r.count),backgroundColor:stats.reasons.map((_,i)=>reasonColors[i%reasonColors.length]),borderColor:'#FFFFFF',borderWidth:2,hoverOffset:2}]},options:reasonOptions},stats.reasons.length>0,'Alasan pemblokiran: '+stats.reasons.map(r=>r.reason+' '+r.count).join(', '));
  el('reasons-legend').replaceChildren();
  stats.reasons.forEach((reason,index)=>{
    const item = document.createElement('li'); item.className='legend-item';
    const marker = document.createElement('i'); marker.className = 'legend-color reason-' + index%reasonColors.length; marker.setAttribute('aria-hidden','true');
    const label = document.createElement('span'); label.className='legend-label'; label.textContent=reasonLabels[reason.reason] || reason.reason; label.title=reason.reason;
    const value=document.createElement('span');value.className='legend-value';value.textContent=number(reason.count)+' · '+number(Math.round(reason.count/stats.totals.blocked*1000)/10)+'%';
    item.append(marker,label,value);el('reasons-legend').append(item);
  });
  const sourceOptions=chartOptions();sourceOptions.indexAxis='y';
  sourceOptions.scales.x={beginAtZero:true,border:{display:false},grid:{color:palette.grid},ticks:{precision:0,color:palette.muted,font:{size:11},maxTicksLimit:5}};
  sourceOptions.scales.y={border:{display:false},grid:{display:false},ticks:{color:palette.muted,font:{size:11,family:'ui-monospace, SFMono-Regular, Consolas, monospace'},autoSkip:false}};
  sourceOptions.plugins.tooltip.callbacks={title:items=>stats.sources[items[0].dataIndex].client,label:item=>'Total: '+number(item.raw),afterLabel:()=>time(stats.from)+' – '+time(stats.to)};
  chart('sources-chart',{type:'bar',data:{labels:stats.sources.map(s=>s.client.slice(0,12)+'…'),datasets:[{label:'Permintaan',data:stats.sources.map(s=>s.total),backgroundColor:palette.primary,maxBarThickness:18}]},options:sourceOptions},stats.sources.length>0,stats.sources.map(s=>s.client+': '+s.total+' permintaan').join('; '));
}
function renderStatistics(stats) {
  lastStats=stats;
  for(const key of ['total','allowed','blocked','errors'])el('metric-'+key).textContent=number(stats.totals[key]);
  el('metric-active-sources').textContent=number(stats.totals.active_sources);
  document.querySelectorAll('.range-label').forEach(label=>label.textContent=rangeLabel());
  el('data-window').textContent=time(stats.from)+' – '+time(stats.to)+' · Waktu lokal browser';
  el('sources-table').replaceChildren();
  for(const source of stats.sources){const row=document.createElement('tr');cell(row,source.client,'mono truncate source-cell').title=source.client;for(const key of ['total','allowed','blocked'])cell(row,number(source[key]),'numeric mono');el('sources-table').append(row);}
  if(!stats.sources.length)emptyRow(el('sources-table'),4);
  renderEvents(stats);
  if(selectedView()==='overview')renderCharts(stats);
}
function renderOverview(state) {
  el('origin-name').textContent=state.settings.origin;
  const health=state.health[0],stale=!health || Date.now()/1000-health.at>45;
  el('health-dot').className='status-dot '+(stale?'neutral':health.available?'allowed':'blocked');
  el('health-text').textContent=stale?'Pemeriksaan belum diperbarui':health.available?'Tersedia':'Tidak tersedia';
  el('health-latency').textContent=health?number(health.ms)+' ms':'—';
  el('last-update').textContent=health?'Diperiksa '+time(health.at):'Belum ada pemeriksaan';
  el('block-count').textContent=number(state.blocks.length);el('blocks-total').textContent=number(state.blocks.length)+' sumber';
  el('block-list').replaceChildren();
  for(const block of state.blocks){
    const row=document.createElement('tr');cell(row,block.client,'mono');cell(row,(reasonLabels[block.reason]||block.reason)+(block.level?' · tingkat '+block.level:' · tinjauan admin'));cell(row,time(block.expires),'mono');
    const button=document.createElement('button');button.className='secondary small';button.type='button';button.textContent='Buka blokir';
    button.onclick=async()=>{button.disabled=true;try{await api('unblock',{client:block.client});message('Blokir dibuka.');await refresh();}catch(error){message(error.message,true);}finally{button.disabled=false;}};
    cell(row,'','numeric').append(button);el('block-list').append(row);
  }
  if(!state.blocks.length)emptyRow(el('block-list'),4,'Tidak ada blokir aktif.');
  el('offense-list').replaceChildren();
  for(const item of state.offenses || []){const row=document.createElement('tr');cell(row,item.client,'mono');cell(row,item.level,'mono');cell(row,item.duration+' detik','mono');cell(row,time(item.last),'mono');const action=cell(row,'');const button=document.createElement('button');button.className='secondary small';button.textContent='Buka / reset tingkat';button.onclick=async()=>{try{await api('unblock',{client:item.client});await refresh();}catch(error){message(error.message,true);}};action.append(button);el('offense-list').append(row);}
  if(!(state.offenses || []).length)emptyRow(el('offense-list'),5,'Belum ada pelanggaran berulang.');
  if(!settingsLoaded){el('origin').replaceChildren();for(const origin of state.origins){const option=document.createElement('option');option.value=origin;option.textContent=origin;el('origin').append(option);}for(const field of ['origin','rate','window','duration'])el(field).value=state.settings[field];settingsLoaded=true;}
  el('audit').replaceChildren();
  const actions={login:'Masuk',update_settings:'Ubah pengaturan',unblock:'Buka blokir'};
  for(const item of state.audit){const row=document.createElement('tr');cell(row,time(item.at),'mono');cell(row,'—').title='Identitas pengguna tidak direkam';cell(row,actions[item.action]||item.action);cell(row,item.target,'mono truncate');el('audit').append(row);}
  if(!state.audit.length)emptyRow(el('audit'),4);
}
async function refresh(background=false) {
  if(!authenticated || (background && refreshController))return;
  if(refreshController)refreshController.abort();
  const controller=new AbortController(); refreshController=controller;
  const sequence=++refreshSequence;
  el('refresh').disabled=true;el('workspace').setAttribute('aria-busy','true');
  const params=new URLSearchParams({range:el('time-range').value,q:el('event-query').value.trim(),page:String(page),page_size:el('page-size').value});
  try{
    const [overview,stats,notifications,machineLearning]=await Promise.all([api('overview',undefined,controller.signal),api('statistics?'+params,undefined,controller.signal),api('alerts',undefined,controller.signal),api('ml',undefined,controller.signal).catch(error=>{if(error.name==='AbortError')throw error;return null;})]);
    if(sequence!==refreshSequence || !authenticated)return;
    renderOverview(overview);renderStatistics(stats);renderNotifications(notifications);renderMachineLearning(machineLearning);
    el('last-refresh').textContent='Diperbarui '+shortTime(stats.to);el('last-refresh').classList.remove('stale');
  }catch(error){if(error.name!=='AbortError' && sequence===refreshSequence){message(error.message,true);el('last-refresh').textContent='Pembaruan gagal · data terakhir';el('last-refresh').classList.add('stale');}}
  finally{if(sequence===refreshSequence){refreshController=null;el('refresh').disabled=false;el('workspace').removeAttribute('aria-busy');}}
}
function applyFilter() {
  clearTimeout(searchTimer);page=1;expanded.clear();el('global-search').value=el('event-query').value;
  el('clear-query').hidden=!el('event-query').value;refresh();
}
el('event-query').addEventListener('input',()=>{el('clear-query').hidden=!el('event-query').value;clearTimeout(searchTimer);searchTimer=setTimeout(applyFilter,300);});
el('filter-form').onsubmit=event=>{event.preventDefault();applyFilter();};
el('time-range').onchange=applyFilter;
el('clear-query').onclick=()=>{el('event-query').value='';applyFilter();el('event-query').focus();};
el('global-search-form').onsubmit=event=>{event.preventDefault();el('event-query').value=el('global-search').value;location.hash='traffic';applyFilter();};
el('refresh').onclick=()=>refresh();
el('page-size').onchange=()=>{page=1;expanded.clear();refresh();};
el('previous-page').onclick=()=>{page=Math.max(1,page-1);expanded.clear();refresh();};
el('next-page').onclick=()=>{page++;expanded.clear();refresh();};
el('sidebar-toggle').onclick=()=>{
  const mobile=matchMedia('(max-width: 700px)').matches;
  if(mobile)document.body.classList.toggle('sidebar-open');else document.body.classList.toggle('sidebar-collapsed');
  syncSidebar();
};
window.addEventListener('resize',syncSidebar);
window.addEventListener('hashchange',showView);
el('login-form').onsubmit=async event=>{
  event.preventDefault();const button=event.target.querySelector('button');button.disabled=true;
  try{const session=await api('session');csrf=session.csrf;const result=await api('login',{password:el('password').value});csrf=result.csrf;el('password').value='';setAuthenticated(true);message('');showView();await refresh();}
  catch(error){message(error.message,true);}finally{button.disabled=false;}
};
el('logout').onclick=async()=>{try{await api('logout',{});showLogin();el('user-menu').open=false;message('Anda sudah keluar.');}catch(error){message(error.message,true);}};
el('settings-form').onsubmit=async event=>{
  event.preventDefault();const button=event.target.querySelector('button');button.disabled=true;
  try{await api('settings',{origin:el('origin').value,rate:Number(el('rate').value),window:Number(el('window').value),duration:Number(el('duration').value)});message('Konfigurasi disimpan.');settingsLoaded=false;await refresh();}
  catch(error){message(error.message,true);}finally{button.disabled=false;}
};
showView();
(async()=>{try{const session=await api('session');csrf=session.csrf;setAuthenticated(session.authenticated);if(authenticated)await refresh();}catch(error){message(error.message,true);}})();
setInterval(()=>{if(!document.hidden)refresh(true);},5000);

for (const format of ["json", "csv"]) el("export-"+format).onclick=()=>{const params=new URLSearchParams({range:el("time-range").value,q:el("event-query").value.trim(),format});window.location.assign("/admin/api/reports?"+params);};

function renderNotifications(state) {
 el('notification-count').textContent=number(state.unacknowledged_count);
 el('notification-summary').textContent=state.active_count+' aktif · '+(state.monitor.stale?'Monitor belum diperbarui':'Monitor aktif');
 el('notification-policy').textContent='Ambang: '+state.policy.threshold+' blokir / '+state.policy.window+' detik; gangguan setelah '+state.policy.failures+' pemeriksaan gagal berurutan.';
 el('notifications-list').replaceChildren();
 for(const item of state.alerts){
  const row=document.createElement('tr');cell(row,time(item.opened_at),'mono');cell(row,item.title);cell(row,item.target,'mono');cell(row,item.count+' '+(item.kind==='blocked_spike'?'permintaan / jendela':'pemeriksaan'),'mono');
  cell(row,item.resolved_at?(item.resolution==='origin_changed'?'Origin diganti':item.resolution==='below_threshold'?'Di bawah ambang':'Pulih'):(item.acknowledged_at?'Aktif · dibaca':'Aktif'));
  const action=cell(row,'');if(!item.acknowledged_at){const button=document.createElement('button');button.className='secondary small';button.textContent='Tandai dibaca';button.onclick=async()=>{button.disabled=true;try{await api('alerts/ack',{id:item.id});await refresh();}catch(error){message(error.message,true);}finally{button.disabled=false;}};action.append(button);}else action.textContent='Sudah dibaca';
  el('notifications-list').append(row);
 }
 if(!state.alerts.length)emptyRow(el('notifications-list'),6,'Belum ada notifikasi.');
}

async function mlAction(action, data) {
  try { await api('ml/'+action,data); message('Perubahan ML disimpan.'); await refresh(); }
  catch(error) { message(error.message,true); }
}
el('ml-approve').onclick=()=>mlAction('approve',{ids:[...mlSelected]});
el('ml-train').onclick=()=>mlAction('train',{origin:mlOrigin});
function renderMachineLearning(state) {
  if(!state){el('ml-status').textContent='Data ML belum tersedia';el('ml-worker').textContent='Pembaruan analisis gagal. Data terakhir mungkin kedaluwarsa.';for(const button of document.querySelectorAll('#machine-learning button'))button.disabled=true;return;}
  if(mlOrigin!==state.origin){mlSelected.clear();mlOrigin=state.origin;}
  const active=state.models.find(m=>m.state==='active');
  el('ml-count').textContent=number(state.coordination.pending);
  el('ml-status').textContent=active?'Aktif · model #'+active.id:'Belum ada model aktif';
  el('ml-summary').textContent='Origin: '+state.origin+'. '+(active?'Model mendeteksi penyimpangan dari baseline yang telah disetujui.':'Kumpulkan dan setujui data normal, latih kandidat, lalu evaluasi sebelum aktivasi.');
  el('ml-worker').textContent=state.worker.stale?'Pekerja ML belum diperbarui; skor terakhir mungkin kedaluwarsa.':state.worker.error?'Pekerja ML mengalami masalah.':'Pekerja ML aktif · '+time(state.worker.last_checked);
  el('ml-baseline-count').textContent=number(state.approved)+' jendela normal disetujui; minimal '+state.minimum+' untuk percobaan lab, dengan variasi dan pemisahan waktu yang cukup.';
  el('ml-train').disabled=state.approved<state.minimum || state.models.some(m=>['queued','training'].includes(m.state));
  el('ml-models').replaceChildren();
  const states={queued:'Antre',training:'Dilatih',candidate:'Kandidat',active:'Aktif',superseded:'Versi sebelumnya',failed:'Gagal',rejected:'Ditolak',quarantined:'Dikarantina'};
  for(const model of state.models){
    const row=document.createElement('tr');cell(row,'#'+model.id,'mono');cell(row,time(model.created_at),'mono');cell(row,(states[model.state]||model.state)+(model.health_error?' · validasi bermasalah':''));
    const metrics=model.metrics;cell(row,metrics?metrics.train_count+' / '+metrics.holdout_count:'—','mono');cell(row,metrics?number(Math.round(metrics.holdout_outlier_rate*1000)/10)+'%':'—','mono');
    const action=cell(row,'');if(['candidate','superseded'].includes(model.state) && metrics && metrics.holdout_outlier_rate<=.25){const button=document.createElement('button');button.className='secondary small';button.textContent=model.state==='superseded'?'Kembalikan versi':'Aktifkan';button.onclick=()=>mlAction('activate',{id:model.id});action.append(button);}else if(model.state==='active'){const button=document.createElement('button');button.className='secondary small';button.textContent='Nonaktifkan';button.onclick=()=>mlAction('deactivate',{id:model.id});action.append(button);}else action.textContent=model.error||'—';el('ml-models').append(row);
  }
  if(!state.models.length)emptyRow(el('ml-models'),6,'Belum ada model yang dilatih.');
  el('ml-findings').replaceChildren();
  const wafStates={available:'Tersedia',unavailable:'Tidak tersedia',unknown:'Belum terverifikasi'};
  el('coordination-health').textContent='Pemeriksaan layanan WAF: '+(wafStates[state.coordination.waf_status]||'Belum terverifikasi')+'. Korelasi memakai bukti sumber dan menit yang sama; permintaan blokir lanjutan dihitung terpisah.';
  for(const finding of state.coordination.cases){
    const row=document.createElement('tr');cell(row,time(finding.start),'mono');cell(row,finding.client,'mono');
    const proof=finding.evidence;cell(row,proof?proof.waf_hits+' deteksi / '+proof.repeat_waf_blocks+' blokir lanjutan / '+proof.policy_rejections+' kebijakan':'Bukti tidak lengkap','mono');
    cell(row,finding.ml_available?(finding.ml_anomaly?'Anomali':'Tidak ditandai')+' · #'+finding.model_id+' · '+Number(finding.score).toFixed(4):'Belum tervalidasi');
    const status=cell(row,finding.title);const note=document.createElement('div');note.className='fine';note.textContent=(finding.review==='normal'?'Normal menurut admin':finding.review==='suspicious'?'Mencurigakan menurut admin':finding.needs_review?'Perlu ditinjau':'Informasi')+'. '+finding.recommendation;status.append(note);
    const action=cell(row,'');if(finding.needs_review){for(const [verdict,label] of [['normal','Normal'],['suspicious','Mencurigakan']]){const button=document.createElement('button');button.className='secondary small';button.textContent=label;button.disabled=finding.review===verdict;button.onclick=()=>mlAction('review',{id:finding.id,verdict});action.append(button);}}
    if(finding.can_respond){const button=document.createElement('button');button.className='secondary small';button.textContent='Blokir sementara';button.onclick=()=>mlAction('respond',{id:finding.id});action.append(button);}else if(finding.response_applied){const note=document.createElement('div');note.className='fine';note.textContent='Respons sudah diterapkan';action.append(note);}
    el('ml-findings').append(row);
  }
  if(!state.coordination.cases.length)emptyRow(el('ml-findings'),6,'Belum ada temuan yang perlu dikorelasikan.');
  el('ml-windows').replaceChildren();
  const validIds=new Set(state.windows.filter(w=>w.eligible && !w.approved_at && w.review!=='suspicious').map(w=>w.id));
  mlSelected=new Set([...mlSelected].filter(id=>validIds.has(id)));
  for(const window of state.windows){const row=document.createElement('tr'),selection=cell(row,'');if(validIds.has(window.id)){const checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.checked=mlSelected.has(window.id);checkbox.setAttribute('aria-label','Pilih jendela '+window.id);checkbox.onchange=()=>{if(checkbox.checked)mlSelected.add(window.id);else mlSelected.delete(window.id);el('ml-approve').disabled=!mlSelected.size;};selection.append(checkbox);}else if(window.approved_at){const button=document.createElement('button');button.className='secondary small';button.textContent='Cabut baseline';button.onclick=()=>mlAction('revoke',{id:window.id});selection.append(button);}else selection.textContent='—';cell(row,time(window.start),'mono');cell(row,window.client,'mono');cell(row,number(window.requests),'mono');cell(row,number(Math.round(window.features.post_ratio*100))+'% / '+number(Math.round(window.features.http_error_ratio*100))+'%','mono');cell(row,window.approved_at?'Disetujui':window.eligible && window.review!=='suspicious'?'Belum disetujui':'Tidak memenuhi syarat');el('ml-windows').append(row);}
  el('ml-approve').disabled=!mlSelected.size;
  if(!state.windows.length)emptyRow(el('ml-windows'),6,'Belum ada jendela lengkap. Data mulai tersedia setelah satu menit trafik baru.');
}
