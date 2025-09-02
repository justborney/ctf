const state = {
  sources: [],
  activeSource: null,
  prices: [],
  stats: null,
  chart: null,
  refreshTimer: null,
  analyzer: {
    activeSource: null,
    activeFile: null,
    chart: null,
  }
};

function $(q){return document.querySelector(q)}
function $all(q){return Array.from(document.querySelectorAll(q))}

async function api(path, opts){
  const res = await fetch(path, opts);
  if(!res.ok) throw new Error(await res.text());
  const type = res.headers.get('content-type')||'';
  if(type.includes('application/json')) return res.json();
  return res.text();
}

function setView(id){
  $all('.view').forEach(v=>v.classList.add('hidden'));
  $(id).classList.remove('hidden');
  $all('.nav-btn').forEach(b=>b.classList.remove('active'));
  const btn = id==='#view-dashboard'?'#nav-dashboard':id==="#view-sources"?'#nav-sources':'#nav-uploads';
  $(btn).classList.add('active');
}

function neonValue(value, unit=''){ return `<span style="color:#00e6ff">${value}${unit}</span>` }
function accentValue(value, unit=''){ return `<span style="color:#39ff14">${value}${unit}</span>` }
function dangerValue(value, unit=''){ return `<span style="color:#ff3366">${value}${unit}</span>` }

function formatNumber(n){
  return Number(n).toLocaleString(undefined, {maximumFractionDigits: 4});
}

function formatShort(n, digits=2){
  return Number(n).toLocaleString(undefined, {maximumFractionDigits: digits});
}

function renderIndicators(stats){
  const el = $('#indicators');
  el.innerHTML = '';
  if(!stats){ el.innerHTML = '<li>No stats available</li>'; return; }
  const items = [
    ['Trend', stats.trend],
    ['Volatility', formatNumber(stats.volatility)],
    ['RSI', formatNumber(stats.rsi)],
    ['Support', formatNumber(stats.support_level)],
    ['Resistance', formatNumber(stats.resistance_level)],
    ['Sentiment', formatNumber(stats.sentiment_score)],
  ];
  for(const [k,v] of items){
    const color = k==='Trend' ? (v==='bullish'? '#39ff14' : v==='bearish' ? '#ff3366' : '#00e6ff') : '#00e6ff';
    const li = document.createElement('li');
    li.innerHTML = `<span>${k}</span><span style="color:${color}">${v}</span>`;
    el.appendChild(li);
  }
}

function renderSnapshot(prices){
  const el = $('#snapshot');
  el.innerHTML = '';
  if(!prices || prices.length===0){ el.textContent='No price data'; return; }
  const sorted = [...prices].sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
  const first = sorted[0].price;
  const last = sorted[sorted.length-1].price;
  const min = Math.min(...sorted.map(p=>p.price));
  const max = Math.max(...sorted.map(p=>p.price));
  const change = last-first;
  const changePct = first ? (change/first)*100 : 0;
  const cells = [
    ['Open', formatNumber(first)],
    ['Last', formatNumber(last)],
    ['Change', `${change>=0?'+':''}${formatShort(change, 2)} (${formatShort(changePct, 2)}%)`],
    ['Low', formatNumber(min)],
    ['High', formatNumber(max)],
    ['Count', formatNumber(sorted.length)],
  ];
  for(const [k,v] of cells){
    const d = document.createElement('div');
    d.className='kv';
    d.innerHTML = `<div style="color:#7aa0b1;font-size:12px">${k}</div><div class="kv-value" style="font-size:16px">${v}</div>`;
    el.appendChild(d);
  }
}

async function loadResults(){
  try{
    const el = document.getElementById('results');
    if(!el) return;
    const data = await api('/results');
    el.innerHTML='';
    const sources = Object.keys(data).sort();
    for(const src of sources){
      const div = document.createElement('div');
      div.className='item';
      const files = data[src]||[];
      const chips = files.map(f=>`<a class="chip" href="/download/${encodeURIComponent(f)}?source=${encodeURIComponent(src)}">${f}</a>`).join('');
      div.innerHTML = `<div class="title">${src}</div><div class="files">${chips||'<span class="status">No files</span>'}</div>`;
      el.appendChild(div);
    }
  }catch(e){
    const el = document.getElementById('results');
    if(el) el.innerHTML = '<span class="status">No results</span>';
  }
}

function ensureChart(){
  if(state.chart) return state.chart;
  const ctx = document.getElementById('priceChart');
  state.chart = new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets: [{
      label: 'Price',
      data: [],
      tension: .2,
      borderColor: '#00e6ff',
      backgroundColor: '#00e6ff22',
      pointRadius: 0,
      borderWidth: 2,
      fill: true,
    }]},
    options: {
      responsive: true,
      maintainAspectRatio: false,
      resizeDelay: 100,
      scales: {
        x: { ticks: { color: '#7aa0b1' }, grid: { color: '#1b2a38' } },
        y: { ticks: { color: '#7aa0b1' }, grid: { color: '#1b2a38' } },
      },
      plugins: {
        legend: { display: false },
        tooltip: { mode: 'index', intersect: false }
      }
    }
  });
  return state.chart;
}
function ensureAnalyzerChart(){
  const ctx = document.getElementById('analyzerChart');
  if(!ctx) return null;
  if(state.analyzer.chart) return state.analyzer.chart;
  state.analyzer.chart = new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets: [{
      label: 'Price',
      data: [],
      tension: .2,
      borderColor: '#ff8bd6',
      backgroundColor: '#ff8bd622',
      pointRadius: 0,
      borderWidth: 2,
      fill: true,
    }]},
    options: {
      responsive: true,
      maintainAspectRatio: false,
      resizeDelay: 100,
      scales: {
        x: { ticks: { color: '#7aa0b1' }, grid: { color: '#1b2a38' } },
        y: { ticks: { color: '#7aa0b1' }, grid: { color: '#1b2a38' } },
      },
      plugins: {
        legend: { display: false },
        tooltip: { mode: 'index', intersect: false }
      }
    }
  });
  return state.analyzer.chart;
}

function updateAnalyzerChart(prices){
  const chart = ensureAnalyzerChart();
  if(!chart) return;
  const sorted = [...prices].sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
  chart.data.labels = sorted.map(p=>new Date(p.timestamp).toLocaleTimeString());
  chart.data.datasets[0].data = sorted.map(p=>p.price);
  chart.update();
}

function renderAnalyzerIndicators(stats){
  const el = document.getElementById('analyzerIndicators');
  if(!el){ return; }
  el.innerHTML = '';
  if(!stats){ el.innerHTML = '<li>No stats available</li>'; return; }
  const items = [
    ['Trend', stats.trend],
    ['Volatility', formatNumber(stats.volatility)],
    ['RSI', formatNumber(stats.rsi)],
    ['Support', formatNumber(stats.support_level)],
    ['Resistance', formatNumber(stats.resistance_level)],
    ['Sentiment', formatNumber(stats.sentiment_score)],
  ];
  for(const [k,v] of items){
    const color = k==='Trend' ? (v==='bullish'? '#39ff14' : v==='bearish' ? '#ff3366' : '#00e6ff') : '#00e6ff';
    const li = document.createElement('li');
    li.innerHTML = `<span>${k}</span><span style="color:${color}">${v}</span>`;
    el.appendChild(li);
  }
}

function renderAnalyzerSnapshot(prices){
  const el = document.getElementById('analyzerSnapshot');
  if(!el){ return; }
  el.innerHTML = '';
  if(!prices || prices.length===0){ el.textContent='No price data'; return; }
  const sorted = [...prices].sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
  const first = sorted[0].price;
  const last = sorted[sorted.length-1].price;
  const min = Math.min(...sorted.map(p=>p.price));
  const max = Math.max(...sorted.map(p=>p.price));
  const change = last-first;
  const changePct = first ? (change/first)*100 : 0;
  const cells = [
    ['Open', formatNumber(first)],
    ['Last', formatNumber(last)],
    ['Change', `${change>=0?'+':''}${formatShort(change, 2)} (${formatShort(changePct, 2)}%)`],
    ['Low', formatNumber(min)],
    ['High', formatNumber(max)],
    ['Count', formatNumber(sorted.length)],
  ];
  for(const [k,v] of cells){
    const d = document.createElement('div');
    d.className='kv';
    d.innerHTML = `<div style="color:#7aa0b1;font-size:12px">${k}</div><div class="kv-value" style="font-size:16px">${v}</div>`;
    el.appendChild(d);
  }
}

async function loadAnalyzerFromResults(){
  const keySel = document.getElementById('analyzerKeySelect');
  const keyDisplay = document.getElementById('analyzerKeyDisplay');
  const keyDropdown = document.getElementById('analyzerKeyDropdown');
  const tabs = document.getElementById('analyzerTabs');
  if(!keySel || !tabs || !keyDisplay || !keyDropdown) return;
  keySel.innerHTML = '';
  keyDropdown.innerHTML = '';
  tabs.innerHTML = '';
  try{
    const data = await api('/results');
    const keys = Object.keys(data).sort();
    for(const k of keys){
      const opt = document.createElement('option');
      opt.value = k; opt.textContent = k;
      keySel.appendChild(opt);
      const div = document.createElement('div');
      div.className = 'select-option';
      div.textContent = k;
      div.addEventListener('click', async ()=>{
        state.analyzer.activeSource = k;
        state.analyzer.activeFile = null;
        keyDropdown.classList.add('hidden');
        await loadAnalyzerFromResults();
      });
      keyDropdown.appendChild(div);
    }
    if(keys.length){
      if(!state.analyzer.activeSource){ state.analyzer.activeSource = keys[0]; }
      keySel.value = state.analyzer.activeSource;
      keyDisplay.textContent = state.analyzer.activeSource;
      const files = data[state.analyzer.activeSource]||[];
      tabs.innerHTML = '';
      for(const f of files){
        const t = document.createElement('div');
        t.className = 'tab';
        t.textContent = f;
        if(f===state.analyzer.activeFile){ t.classList.add('active'); }
        t.addEventListener('click', async ()=>{
          state.analyzer.activeFile = f;
          highlightAnalyzerTab();
          await loadAnalyzerStats(f);
        });
        tabs.appendChild(t);
      }
      if(!state.analyzer.activeFile && files.length){
        state.analyzer.activeFile = files[0];
        highlightAnalyzerTab();
        await loadAnalyzerStats(files[0]);
      }
    }
  }catch(e){
    // ignore
  }
}

function highlightAnalyzerTab(){
  const tabs = Array.from(document.querySelectorAll('#analyzerTabs .tab'));
  for(const el of tabs){
    if(el.textContent === state.analyzer.activeFile){ el.classList.add('active'); } else { el.classList.remove('active'); }
  }
}

async function loadAnalyzerResultsList(){
  const container = document.getElementById('analyzerFiles');
  if(!container) return;
  container.innerHTML = '';
  try{
    const data = await api('/results');
    const files = (data[state.analyzer.activeSource]||[]);
    for(const f of files){
      const a = document.createElement('a');
      a.className = 'chip';
      a.textContent = f;
      a.href = `/download/${encodeURIComponent(f)}?source=${encodeURIComponent(state.analyzer.activeSource)}`;
      a.addEventListener('click', async (e)=>{
        e.preventDefault();
        await loadAnalyzerStats(f);
      });
      container.appendChild(a);
    }
  }catch(e){
    container.textContent = 'No results';
  }
}

async function loadAnalyzerStats(filename){
  try{
    const res = await api(`/download/${encodeURIComponent(filename||'price_data.json')}?source=${encodeURIComponent(state.analyzer.activeSource)}`);
    const json = typeof res === 'string' ? JSON.parse(res) : res;
    updateAnalyzerChart(json.prices||[]);
    renderAnalyzerIndicators(json.stats||null);
    renderAnalyzerSnapshot(json.prices||[]);
  }catch(e){
    updateAnalyzerChart([]);
    renderAnalyzerIndicators(null);
    renderAnalyzerSnapshot([]);
  }
}

function updateChart(prices){
  const chart = ensureChart();
  const sorted = [...prices].sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
  chart.data.labels = sorted.map(p=>new Date(p.timestamp).toLocaleTimeString());
  chart.data.datasets[0].data = sorted.map(p=>p.price);
  chart.update();
}

async function loadSources(){
  try{
    const data = await api('/sources');
    state.sources = data.sources||[];
    const tbody = document.querySelector('#sourcesTable tbody');
    if(tbody){
      tbody.innerHTML='';
      for(const s of state.sources){
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${s.name}</td><td>${s.url}</td>`;
        tbody.appendChild(tr);
      }
    }
    const tabs = $('#sourceTabs');
    if(tabs){ tabs.innerHTML = ''; }
    for(const s of state.sources){
      if(tabs){
        const t = document.createElement('div');
        t.className = 'tab';
        t.textContent = s.name;
        if(s.name === state.activeSource){ t.classList.add('active'); }
        t.addEventListener('click', async ()=>{
          state.activeSource = s.name;
          highlightActiveTab();
          await loadSourceStats(state.activeSource);
          restartAutoRefresh();
        });
        tabs.appendChild(t);
      }
    }
    $('#apiStatus').textContent = 'API: online';
    if(state.sources.length){
      if(!state.activeSource){ state.activeSource = state.sources[0].name; }
      highlightActiveTab();
      await loadSourceStats(state.activeSource);
    }
  }catch(e){
    $('#apiStatus').textContent = 'API: offline';
  }
}

function highlightActiveTab(){
  const tabs = Array.from(document.querySelectorAll('#sourceTabs .tab'));
  for(const el of tabs){
    if(el.textContent === state.activeSource){ el.classList.add('active'); } else { el.classList.remove('active'); }
  }
}

async function addSource(){
  const name = $('#sourceName').value.trim();
  const url = $('#sourceUrl').value.trim();
  if(!name || !url) return;
  try{
    await api('/sources', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({name, url})});
    $('#sourceName').value='';
    $('#sourceUrl').value='';
    await loadSources();
  }catch(e){
    alert('Failed to add source');
  }
}

async function loadSourceStats(name){
  try{
    const data = await api(`/sources/${encodeURIComponent(name)}/stats`);
    state.prices = data.prices||[];
    state.stats = data.stats||null;
    renderIndicators(state.stats);
    renderSnapshot(state.prices);
    updateChart(state.prices);
    await loadResults();
  }catch(e){
    renderIndicators(null);
    renderSnapshot([]);
    updateChart([]);
  }
}

async function upload(){
  const source = $('#uploadSource').value.trim();
  const file = $('#uploadFile').files[0];
  if(!source || !file){
    $('#uploadStatus').textContent = 'Provide source and choose a JSON file';
    return;
  }
  const fd = new FormData();
  fd.append('file', file);
  try{
    const res = await fetch(`/upload?source=${encodeURIComponent(source)}`, { method: 'POST', body: fd });
    if(!res.ok){ throw new Error(await res.text()); }
    const data = await res.json();
    $('#uploadStatus').textContent = `Uploaded ${data.filename} to ${data.source}`;
    await loadSources();
    state.activeSource = source;
    await loadSourceStats(source);
    await loadResults();
    setView('#view-dashboard');
  }catch(e){
    $('#uploadStatus').textContent = 'Upload failed';
  }
}

function tickYear(){ $('#year').textContent = new Date().getFullYear(); }

function bindNav(){
  const nd = $('#nav-dashboard'); if(nd) nd.addEventListener('click', ()=> setView('#view-dashboard'));
  const ns = $('#nav-sources'); if(ns) ns.addEventListener('click', ()=> setView('#view-sources'));
  const nu = $('#nav-uploads'); if(nu) nu.addEventListener('click', ()=> setView('#view-uploads'));
}

function bindActions(){
  const addSourceBtn = $('#addSource');
  if(addSourceBtn){ addSourceBtn.addEventListener('click', addSource); }
  const legacyUploadBtn = $('#uploadBtn');
  if(legacyUploadBtn){ legacyUploadBtn.addEventListener('click', upload); }
  const openAdd = $('#openAddSource');
  const modal = $('#addSourceModal');
  const backdrop = $('#modalBackdrop');
  const closeAdd = $('#closeAddSource');
  const confirmAdd = $('#modalAddSourceBtn');
  const addBtnIcon = openAdd;
  function openAddModal(){ modal.classList.remove('hidden'); backdrop.classList.remove('hidden'); }
  function closeAddModal(){ modal.classList.add('hidden'); backdrop.classList.add('hidden'); }
  openAdd.addEventListener('click', openAddModal);
  closeAdd.addEventListener('click', closeAddModal);
  confirmAdd.addEventListener('click', async ()=>{
    const name = $('#modalSourceName').value.trim();
    const url = $('#modalSourceUrl').value.trim();
    if(!name || !url) return;
    try{
      await api('/sources', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({name, url})});
      $('#modalSourceName').value='';
      $('#modalSourceUrl').value='';
      closeAddModal();
      await loadSources();
    }catch(e){
      alert('Failed to add source');
    }
  });

  const keySel = document.getElementById('analyzerKeySelect');
  const keyDisplay = document.getElementById('analyzerKeyDisplay');
  const keyDropdown = document.getElementById('analyzerKeyDropdown');
  const openUpload = document.getElementById('analyzerOpenUpload');
  const upModal = document.getElementById('uploadModal');
  const upClose = document.getElementById('uploadModalClose');
  const upSubmit = document.getElementById('uploadModalSubmit');
  const upSource = document.getElementById('uploadModalSource');
  const upFile = document.getElementById('uploadModalFile');
  if(keyDisplay && keyDropdown){
    keyDisplay.addEventListener('click', ()=>{
      keyDropdown.classList.toggle('hidden');
    });
    document.addEventListener('click', (e)=>{
      if(!e.target.closest('.custom-select')){
        keyDropdown.classList.add('hidden');
      }
    });
  }
  if(openUpload && upModal){
    function openUploadModal(){ upModal.classList.remove('hidden'); backdrop.classList.remove('hidden'); }
    function closeUploadModal(){ upModal.classList.add('hidden'); backdrop.classList.add('hidden'); }
    openUpload.addEventListener('click', openUploadModal);
    if(upClose){ upClose.addEventListener('click', closeUploadModal); }
    if(backdrop){ backdrop.addEventListener('click', ()=>{
      if(!modal.classList.contains('hidden')){ closeAddModal(); }
      if(!upModal.classList.contains('hidden')){ closeUploadModal(); }
    }); }
    if(upSubmit){
      upSubmit.addEventListener('click', async ()=>{
        const src = (upSource.value || state.analyzer.activeSource || '').trim();
        const file = upFile.files[0];
        if(!src || !file) return;
        const fd = new FormData();
        fd.append('file', file);
        await fetch(`/upload?source=${encodeURIComponent(src)}`, { method: 'POST', body: fd });
        closeUploadModal();
        upSource.value = '';
        upFile.value = '';
        upFile.dataset.label = 'Import JSON...';
        state.analyzer.activeSource = src;
        await loadAnalyzerFromResults();
      });
    }
    if(upFile){
      upFile.addEventListener('change', ()=>{
        const name = upFile.files && upFile.files[0] ? upFile.files[0].name : '';
        upFile.dataset.label = name ? `Selected: ${name}` : 'Import JSON...';
      });
    }
  }
}

async function boot(){
  tickYear();
  bindNav();
  bindActions();
  await loadSources();
  await loadAnalyzerFromResults();
  restartAutoRefresh();
}

function restartAutoRefresh(){
  if(state.refreshTimer){ clearInterval(state.refreshTimer); }
  state.refreshTimer = setInterval(async ()=>{
    await loadSources();
    if(state.activeSource){ await loadSourceStats(state.activeSource); }
  }, 60_000);
}

boot();


