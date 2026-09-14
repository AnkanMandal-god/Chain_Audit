const state = {
  view: 'overview',
  status: null,
  samples: null,
  audit: null,
  batch: [], // [{ name: string, source: string, original: string, modified: boolean }]
  activeBatchIndex: -1,
  auditMode: 'single',
  refinement: null,
  historyMode: 'audits',
  historyPage: 1,
  historySearch: '',
  historyTimer: null,
  historyRiskFilter: 'all',
  historyClassFilter: 'all',
  historySortOrder: 'desc',
  passcode: sessionStorage.getItem('chainmind_admin_pass') || '',
  authenticated: false,
  ws: null,
  streamRunning: false,
  streamStats: { total: 0, green: 0, yellow: 0, red: 0 },
  latestAnomaly: null,
  singleFile: null,
  autoScroll: true,
  signalFilter: 'all'
};

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
const prettyDate = (value) => {
  if (!value) return '—';
  let str = String(value).trim();
  // SQLite default CURRENT_TIMESTAMP format is 'YYYY-MM-DD HH:MM:SS' in UTC
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(str)) {
    str = str.replace(' ', 'T') + 'Z';
  } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(str)) {
    str = str + 'Z';
  }
  const date = new Date(str);
  if (isNaN(date.getTime())) return String(value);
  return date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
};
const riskClass = (score) => Number(score) >= 7 ? 'critical' : Number(score) >= 4 ? 'warning' : 'safe';
const riskLabel = (score) => riskClass(score).toUpperCase();

document.addEventListener('DOMContentLoaded', async () => {
  // Navigation
  document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.view)));
  $('refreshButton').addEventListener('click', refreshAll);

  // Single & Batch Audit Actions
  $('runAudit').addEventListener('click', runSingleAudit);
  $('generateRefinement').addEventListener('click', generateRefinedContract);
  $('downloadRefinement').addEventListener('click', downloadRefinement);
  $('detectRelationships').addEventListener('click', detectSingleRelationships);
  $('loadSuite').addEventListener('click', loadSuite);
  $('runBatch').addEventListener('click', runBatch);
  $('detectBatchDeps').addEventListener('click', detectBatchRelationships);
  $('batchAddFilesBtn').addEventListener('click', () => $('fileInput').click());
  $('clearBatchBtn').addEventListener('click', clearBatch);
  $('clearSingleFile').addEventListener('click', clearSingleFile);

  // Active Batch Editor Actions
  $('btnSaveActive').addEventListener('click', saveActiveContract);
  $('btnAuditActive').addEventListener('click', auditActiveContract);
  $('batchSourceEditor').addEventListener('input', onBatchEditorInput);

  // Real Mempool Stream Actions
  $('toggleStream').addEventListener('click', toggleStream);
  $('mempoolChain').addEventListener('change', onMempoolChainChange);
  $('latestAnomaly').addEventListener('click', openLatestAnomaly);

  // Terminal Controls
  $('btnClearFeed').addEventListener('click', clearStreamFeed);
  $('btnScrollLock').addEventListener('click', toggleScrollLock);
  $('streamSignalFilter').addEventListener('change', (e) => { state.signalFilter = e.target.value; applySignalFilter(); });

  // History Actions
  $('refreshHistory').addEventListener('click', loadHistory);
  $('historyPrev').addEventListener('click', () => changeHistoryPage(-1));
  $('historyNext').addEventListener('click', () => changeHistoryPage(1));
  $('historySearch').addEventListener('input', debounceHistory);
  $('historyRiskFilter').addEventListener('change', (e) => { state.historyRiskFilter = e.target.value; state.historyPage = 1; loadHistory(); });
  $('historyClassFilter').addEventListener('change', (e) => { state.historyClassFilter = e.target.value; state.historyPage = 1; loadHistory(); });
  $('historySortFilter').addEventListener('change', (e) => { state.historySortOrder = e.target.value; state.historyPage = 1; loadHistory(); });

  // Settings Actions
  $('unlockSettings').addEventListener('click', () => openModal('authModal'));
  $('authForm').addEventListener('submit', authenticate);
  $('settingsForm').addEventListener('submit', saveSettings);

  // Delegated UI listeners
  document.querySelectorAll('[data-close-modal]').forEach((button) => button.addEventListener('click', () => closeModal(button.dataset.closeModal)));
  document.querySelectorAll('[data-audit-mode]').forEach((button) => button.addEventListener('click', () => setAuditMode(button.dataset.auditMode)));
  document.querySelectorAll('[data-history-mode]').forEach((button) => button.addEventListener('click', () => setHistoryMode(button.dataset.historyMode)));
  document.querySelectorAll('[data-sample]').forEach((button) => button.addEventListener('click', () => loadSample(button.dataset.sample)));
  document.querySelectorAll('[data-export]').forEach((button) => button.addEventListener('click', () => exportAudit(button.dataset.export)));

  // Drag & Drop Setup
  initDropZone();

  // Initial Load
  await refreshAll();
  if (state.passcode) authenticateValue(state.passcode, false);
});

async function api(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof data.detail === 'object' ? data.detail.message : data.detail;
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return data;
}

async function refreshAll() {
  try {
    const [status, overview, samples] = await Promise.all([
      api('/api/status'), api('/api/overview'), api('/api/demo/samples')
    ]);
    state.status = status;
    state.samples = samples;
    renderStatus(status);
    renderOverview(status, overview);
    if (state.view === 'history') loadHistory();
  } catch (error) {
    toast('Connection problem', error.message, 'error');
  }
}

function switchView(view) {
  if (view === 'settings' && !state.authenticated) {
    openModal('authModal');
    return;
  }
  state.view = view;
  document.querySelectorAll('.view').forEach((item) => item.classList.toggle('active', item.id === `view-${view}`));
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === view));
  $('topbarViewName').textContent = ({ overview: 'Overview', audit: 'Contract audit', mempool: 'Mempool monitor', history: 'History', settings: 'Settings' })[view];
  if (view === 'history') loadHistory();
  if (view === 'settings') loadSettings();
}

function renderStatus(status) {
  $('chainLabel').textContent = titleCase(status.default_chain || 'ethereum');
  $('sidebarMode').textContent = status.mode === 'STRICT_REAL' ? 'Strict real mode' : 'Resilient mode';

  // Check credential readiness and toggle warnings
  const hasGemini = Boolean(status.has_gemini_key);
  const hasRpcWs = Boolean(status.has_rpc_ws);
  const auditNotice = $('auditCredentialNotice');
  if (auditNotice) {
    auditNotice.classList.toggle('hidden', hasGemini);
  }

  const mempoolWarning = $('mempoolCredentialWarning');
  if (mempoolWarning) {
    mempoolWarning.classList.toggle('hidden', hasRpcWs);
  }

  const endpointText = $('mempoolRpcEndpoint');
  if (endpointText && status.eth_rpc_ws_url) {
    endpointText.textContent = `RPC: ${status.eth_rpc_ws_url}`;
  }

  const ready = (status.credentials_matrix || []).filter((item) => item.status === 'ready').length;
  const total = (status.credentials_matrix || []).length;
  $('metricReadiness').textContent = total ? `${ready}/${total}` : '—';
  $('metricReadinessNote').textContent = `${Math.round((ready / Math.max(total, 1)) * 100)}% of capabilities ready`;
  $('capabilityList').innerHTML = (status.credentials_matrix || []).map((item) => `
    <div class="capability-row"><span class="status-dot ${item.status === 'missing' ? 'missing' : ''}" style="${item.status === 'missing' ? 'background:#b63e3e;box-shadow:0 0 0 4px rgba(182,62,62,.12)' : ''}"></span>
      <div><strong>${esc(item.name)}</strong><small>${esc(item.description)}</small></div><span class="capability-status ${item.status === 'missing' ? 'missing' : ''}">${esc(item.status_label)}</span>
    </div>`).join('') || '<div class="empty-state">No capability data.</div>';
}

function renderOverview(status, overview) {
  $('metricAudits').textContent = overview.audit_total ?? 0;
  $('metricRisk').textContent = (overview.recent_audits || []).filter((item) => Number(item.risk_score) >= 4).length;
  $('metricAnomalies').textContent = (overview.recent_anomalies || []).length;
  $('recentAudits').innerHTML = overview.recent_audits?.length ? overview.recent_audits.map((item) => `
    <div class="activity-row"><div><div class="activity-title">${esc(item.target_address)}</div><div class="activity-sub">${esc(item.summary || 'Audit completed')}</div></div>
      <div><span class="tag ${riskClass(item.risk_score) === 'critical' ? 'tag' : 'tag-neutral'}">${item.risk_score}/10 ${riskLabel(item.risk_score)}</span><div class="activity-time">${prettyDate(item.audit_timestamp)}</div></div></div>`).join('') : '<div class="empty-state">No audits recorded yet. Run your first review to see it here.</div>';
}

function setAuditMode(mode) {
  state.auditMode = mode;
  document.querySelectorAll('[data-audit-mode]').forEach((button) => button.classList.toggle('active', button.dataset.auditMode === mode));
  $('singleAuditForm').classList.toggle('hidden', mode !== 'single');
  $('batchAuditForm').classList.toggle('hidden', mode !== 'batch');
}

// -------------------------------------------------------------
// Drag & Drop and File / Folder Upload
// -------------------------------------------------------------

function initDropZone() {
  const zone = $('contractDropZone');
  if (!zone) return;

  ['dragenter', 'dragover'].forEach((evt) => {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      zone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach((evt) => {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      zone.classList.remove('dragover');
    });
  });

  zone.addEventListener('drop', async (e) => {
    const items = e.dataTransfer.items;
    const files = e.dataTransfer.files;
    const collected = [];

    if (items && items.length) {
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.webkitGetAsEntry) {
          const entry = item.webkitGetAsEntry();
          if (entry) {
            await scanEntry(entry, collected);
            continue;
          }
        }
        if (item.kind === 'file') {
          const f = item.getAsFile();
          if (f && f.name.endsWith('.sol')) {
            const text = await f.text();
            collected.push({ name: f.name, source: text });
          }
        }
      }
    } else if (files && files.length) {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        if (f.name.endsWith('.sol')) {
          const text = await f.text();
          collected.push({ name: f.name, source: text });
        }
      }
    }

    handleLoadedContracts(collected);
  });

  $('btnBrowseFiles').addEventListener('click', () => $('fileInput').click());
  $('btnBrowseFolder').addEventListener('click', () => $('folderInput').click());

  $('fileInput').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files).filter((f) => f.name.endsWith('.sol'));
    const collected = [];
    for (const f of files) {
      const text = await f.text();
      collected.push({ name: f.name, source: text });
    }
    handleLoadedContracts(collected);
    e.target.value = '';
  });

  $('folderInput').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files).filter((f) => f.name.endsWith('.sol'));
    const collected = [];
    for (const f of files) {
      const text = await f.text();
      collected.push({ name: f.name, source: text });
    }
    handleLoadedContracts(collected);
    e.target.value = '';
  });
}

async function scanEntry(entry, collected) {
  if (entry.isFile) {
    if (entry.name.endsWith('.sol')) {
      const file = await new Promise((resolve) => entry.file(resolve));
      const text = await file.text();
      collected.push({ name: entry.name, source: text });
    }
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    const readEntries = () => new Promise((resolve) => reader.readEntries(resolve));
    let entries = await readEntries();
    while (entries && entries.length) {
      for (const child of entries) {
        await scanEntry(child, collected);
      }
      entries = await readEntries();
    }
  }
}

function handleLoadedContracts(collected) {
  if (!collected.length) {
    return toast('No Solidity files found', 'Please drop or select files with a .sol extension.', 'error');
  }

  if (collected.length === 1 && state.auditMode === 'single') {
    const file = collected[0];
    state.singleFile = {
      name: file.name,
      lines: file.source.split('\n').length
    };
    $('singleFileName').textContent = file.name;
    $('singleFileMeta').textContent = `${state.singleFile.lines} lines`;
    $('singleFilePill').classList.remove('hidden');
    $('contractSource').value = file.source;
    $('contractAddress').value = '';
    toast('Contract loaded', `${file.name} loaded. You can modify the code below before auditing.`, 'success');
  } else {
    setAuditMode('batch');
    const existingMap = new Map(state.batch.map((c, i) => [c.name, i]));
    collected.forEach((item) => {
      if (existingMap.has(item.name)) {
        const idx = existingMap.get(item.name);
        state.batch[idx] = {
          name: item.name,
          source: item.source,
          original: item.source,
          modified: false
        };
      } else {
        state.batch.push({
          name: item.name,
          source: item.source,
          original: item.source,
          modified: false
        });
      }
    });

    renderBatchList();
    selectBatchContract(state.batch.length - collected.length >= 0 ? state.batch.length - collected.length : 0);
    toast('Workspace updated', `Loaded ${collected.length} contract(s). Click any file to modify its code.`, 'success');
    detectBatchRelationships();
  }
}

function clearSingleFile() {
  state.singleFile = null;
  $('singleFilePill').classList.add('hidden');
  $('contractSource').value = '';
  toast('Contract cleared', 'Editor cleared.', 'success');
}

// -------------------------------------------------------------
// Batch File Manager & Code Modifier
// -------------------------------------------------------------

function renderBatchList() {
  const container = $('batchFiles');
  const count = state.batch.length;
  $('batchCountBadge').textContent = `${count} contract${count === 1 ? '' : 's'} loaded`;
  $('batchAuditBtnCount').textContent = count;

  if (!count) {
    container.innerHTML = '<div class="empty-state">No contracts loaded. Drop a folder or add files to begin.</div>';
    $('batchSourceEditor').value = '';
    $('activeContractTitle').textContent = 'Select a contract to edit';
    $('activeContractBadge').classList.add('hidden');
    $('batchEditorMeta').textContent = 'No file selected';
    return;
  }

  container.innerHTML = state.batch.map((contract, index) => {
    const isActive = index === state.activeBatchIndex;
    const lines = (contract.source || '').split('\n').length;
    return `
      <div class="batch-item ${isActive ? 'active' : ''}" onclick="selectBatchContract(${index})">
        <div class="batch-item-name" title="${esc(contract.name)}">${esc(contract.name)}</div>
        <div class="batch-item-actions">
          <span class="tag ${contract.modified ? '' : 'tag-neutral'}">${contract.modified ? 'Modified' : `${lines}L`}</span>
          <button type="button" class="batch-item-btn" title="Edit code" onclick="event.stopPropagation(); selectBatchContract(${index});">Edit</button>
          <button type="button" class="batch-item-btn" title="Delete file" onclick="event.stopPropagation(); deleteBatchContract(${index});">×</button>
        </div>
      </div>
    `;
  }).join('');
}

function selectBatchContract(index) {
  if (index < 0 || index >= state.batch.length) return;
  state.activeBatchIndex = index;
  const contract = state.batch[index];
  const editor = $('batchSourceEditor');
  editor.value = contract.source;
  $('activeContractTitle').textContent = contract.name;
  $('activeContractBadge').classList.toggle('hidden', !contract.modified);
  const lines = contract.source.split('\n').length;
  $('batchEditorMeta').textContent = `${lines} lines • ${contract.source.length} characters`;
  renderBatchList();
}

function onBatchEditorInput() {
  if (state.activeBatchIndex < 0 || state.activeBatchIndex >= state.batch.length) return;
  const contract = state.batch[state.activeBatchIndex];
  const currentText = $('batchSourceEditor').value;
  contract.source = currentText;
  contract.modified = currentText !== contract.original;
  $('activeContractBadge').classList.toggle('hidden', !contract.modified);
  const lines = currentText.split('\n').length;
  $('batchEditorMeta').textContent = `${lines} lines (Unsaved modifications synced to batch)`;
}

function saveActiveContract() {
  if (state.activeBatchIndex < 0 || state.activeBatchIndex >= state.batch.length) return;
  const contract = state.batch[state.activeBatchIndex];
  contract.source = $('batchSourceEditor').value;
  contract.original = contract.source;
  contract.modified = false;
  $('activeContractBadge').classList.add('hidden');
  renderBatchList();
  toast('Contract saved', `Changes to ${contract.name} applied to batch.`, 'success');
  detectBatchRelationships();
}

function auditActiveContract() {
  if (state.activeBatchIndex < 0 || state.activeBatchIndex >= state.batch.length) return;
  const contract = state.batch[state.activeBatchIndex];
  setAuditMode('single');
  $('contractSource').value = contract.source;
  $('contractAddress').value = '';
  state.singleFile = { name: contract.name, lines: contract.source.split('\n').length };
  $('singleFileName').textContent = contract.name;
  $('singleFileMeta').textContent = `${state.singleFile.lines} lines`;
  $('singleFilePill').classList.remove('hidden');
  runSingleAudit();
}

function deleteBatchContract(index) {
  if (index < 0 || index >= state.batch.length) return;
  const removed = state.batch.splice(index, 1)[0];
  if (state.activeBatchIndex >= state.batch.length) {
    state.activeBatchIndex = state.batch.length - 1;
  }
  renderBatchList();
  if (state.activeBatchIndex >= 0) {
    selectBatchContract(state.activeBatchIndex);
  }
  toast('File removed', `${removed.name} removed from batch.`, 'success');
  detectBatchRelationships();
}

function clearBatch() {
  state.batch = [];
  state.activeBatchIndex = -1;
  renderBatchList();
  renderGraph({});
  toast('Workspace cleared', 'All batch contracts cleared.', 'success');
}

function loadSample(id) {
  const sample = state.samples?.single_samples?.find((item) => item.id === id);
  if (!sample) return;
  setAuditMode('single');
  state.singleFile = { name: sample.name, lines: sample.source.split('\n').length };
  $('singleFileName').textContent = sample.name;
  $('singleFileMeta').textContent = `${state.singleFile.lines} lines`;
  $('singleFilePill').classList.remove('hidden');
  $('contractSource').value = sample.source;
  $('contractAddress').value = '';
  toast('Sample loaded', `${sample.name} loaded. You can modify the code before auditing.`, 'success');
}

async function runSingleAudit() {
  const source = $('contractSource').value.trim();
  const address = $('contractAddress').value.trim();
  if (!source && !address) return toast('Add an audit target', 'Paste Solidity source, drop a file, or enter an address.', 'error');
  const button = $('runAudit');
  busy(button, 'Auditing…');
  try {
    const payload = { chain: $('auditChain').value };
    if (address) {
      payload.contract_address = address;
    } else {
      payload.source_code = source;
      if (state.singleFile?.name) payload.target_path = state.singleFile.name;
    }
    state.audit = await api('/api/audit/contract', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    renderAudit(state.audit);
    toast('Audit complete', `Risk score ${state.audit.risk_score}/10.`, 'success');
    refreshAll();
  } catch (error) {
    toast('Audit failed', error.message, 'error');
  } finally {
    restore(button, 'Run audit →');
  }
}

async function loadSuite() {
  if (!state.samples?.sample_suite?.contracts?.length) return toast('No sample suite found', 'Connected sample contracts unavailable.', 'error');
  setAuditMode('batch');
  state.batch = state.samples.sample_suite.contracts.map((c) => ({
    name: c.name,
    source: c.source,
    original: c.source,
    modified: false
  }));
  renderBatchList();
  selectBatchContract(0);
  toast('DeFi suite loaded', '4 connected contracts loaded into workspace. You can edit any file.', 'success');
  detectBatchRelationships();
}

async function runBatch() {
  if (!state.batch.length) return toast('Load contracts first', 'Drop a folder or add contracts before running a batch audit.', 'error');
  const button = $('runBatch');
  busy(button, 'Auditing batch…');
  try {
    const contractsPayload = state.batch.map((c) => ({ name: c.name, source: c.source }));
    const result = await api('/api/audit/batch', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ contracts: contractsPayload, chain: $('auditChain').value })
    });
    if (result.reports?.[0]) {
      state.audit = result.reports[0];
      renderAudit(state.audit);
    }
    renderGraph(result.dependency_graph);
    toast('Batch complete', `${result.batch_size} contracts audited. Overall status: ${result.overall_status}.`, 'success');
    refreshAll();
  } catch (error) {
    toast('Batch audit failed', error.message, 'error');
  } finally {
    restore(button, `Audit All Contracts (${state.batch.length}) →`);
  }
}

async function detectSingleRelationships() {
  const source = $('contractSource').value.trim();
  if (!source) return toast('Add source first', 'Paste or drop Solidity code to map relationships.', 'error');
  const name = state.singleFile?.name || 'Contract.sol';
  try {
    const graph = await api('/api/audit/detect-relationships', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ contracts: [{ name, source }] })
    });
    renderGraph(graph);
    toast('Dependency map updated', 'Relationship analysis completed.', 'success');
  } catch (error) {
    toast('Could not map dependencies', error.message, 'error');
  }
}

async function detectBatchRelationships() {
  if (!state.batch.length) return;
  try {
    const contractsPayload = state.batch.map((c) => ({ name: c.name, source: c.source }));
    const graph = await api('/api/audit/detect-relationships', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ contracts: contractsPayload })
    });
    renderGraph(graph);
  } catch (error) {
    console.debug('Dependency map update error:', error);
  }
}

function renderGraph(graph = {}) {
  const nodes = graph.nodes || graph.contracts || [];
  const edges = graph.edges || graph.relationships || [];
  $('relationshipCount').textContent = `${edges.length} link${edges.length === 1 ? '' : 's'}`;
  $('dependencyMap').innerHTML = nodes.length || edges.length
    ? `<div>${nodes.map((node) => `<span class="map-node">${esc(typeof node === 'string' ? node : node.id || node.name || 'Contract')}</span>`).join('')}</div>${edges.map((edge) => `<div class="map-link">${esc(edge.source || edge.from || '')} → ${esc(edge.target || edge.to || '')} <span>${esc(edge.type || edge.relationship || '')}</span></div>`).join('')}`
    : '<div class="empty-state">No relationships detected yet.</div>';
}

function renderAudit(report) {
  const score = Number(report.risk_score || 0);
  const kind = riskClass(score);
  $('auditResult').classList.remove('hidden');
  $('resultTitle').textContent = report.contract_name || report.target_address || 'Security Report';
  $('resultMeta').textContent = `Analyzed ${prettyDate(report.audit_timestamp)}`;
  $('riskScore').className = `risk-score ${kind}`;
  $('riskScore').innerHTML = `<strong>${score}/10</strong><span>Risk score</span>`;
  $('resultStatus').className = `tag ${kind === 'safe' ? 'tag-neutral' : 'tag'}`;
  $('resultStatus').textContent = riskLabel(score);

  const engineModeBadge = $('resultEngineMode');
  if (engineModeBadge) {
    const mode = report.engine_mode || (state.status?.has_gemini_key ? 'GenAI LLM' : 'Static Heuristic');
    engineModeBadge.textContent = mode;
  }

  const telemetry = report.ingestion_telemetry || {};
  $('resultInjections').textContent = `${telemetry.detected_injections || 0} neutralized`;
  $('resultFunctions').textContent = `${(telemetry.state_changing_functions || []).length} state-changing functions`;
  $('resultSummary').textContent = report.summary || 'Audit evaluation completed.';

  const findings = report.security_findings || [];
  const refinementButton = $('generateRefinement');
  const vulnerable = findings.length > 0 && score >= 4;
  if (refinementButton) {
    refinementButton.classList.toggle('hidden', !vulnerable);
    refinementButton.textContent = score >= 7 ? 'Generate secure contract' : 'Generate reviewed baseline';
  }
  state.refinement = null;
  $('refinementPanel')?.classList.add('hidden');
  $('findingCount').textContent = `${findings.length} issue${findings.length === 1 ? '' : 's'}`;
  $('findingsList').innerHTML = findings.length ? findings.map((finding) => `
    <div class="finding ${(finding.severity || '').toLowerCase()}">
      <h4>${esc(finding.title || finding.rule_id || 'Security finding')} <span class="tag tag-neutral">${esc(finding.severity || 'INFO')}</span></h4>
      ${finding.domain ? `<small>Security domain: ${esc(finding.domain)}</small>` : ''}
      <p>${esc(finding.description || '')}</p>
      ${finding.location ? `<small>Location: ${esc(finding.location)}</small>` : ''}
      ${finding.recommendation ? `<small style="margin-top:4px">Mitigation: ${esc(finding.recommendation)}</small>` : ''}
    </div>
  `).join('') : '<div class="empty-state">No vulnerabilities identified by the configured engine.</div>';

  $('patchPreview').textContent = report.remediation_patch || 'No remediation patch generated for this report.';
  $('auditResult').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function generateRefinedContract() {
  if (!state.audit?.security_findings?.length) {
    return toast('No rewrite needed', 'Only vulnerable contracts receive a generated replacement.', 'success');
  }
  const source = $('contractSource').value.trim();
  if (!source) return toast('Source unavailable', 'Keep the audited Solidity source loaded to generate a refinement.', 'error');
  const button = $('generateRefinement');
  busy(button, 'Generating…');
  try {
    state.refinement = await api('/api/audit/refine', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        source_code: source,
        findings: state.audit.security_findings,
        target_address: state.audit.target_address || 'Contract.sol'
      })
    });
    $('refinementExplanation').textContent = state.refinement.explanation || 'Compile, test, and review this generated source before deployment.';
    $('refinedContractSource').value = state.refinement.contract_source || '';
    $('refinementChanges').innerHTML = (state.refinement.changes || []).map((change) => `<span>${esc(change)}</span>`).join('');
    $('refinementPanel').classList.remove('hidden');
    toast('Secure baseline generated', 'Review the generated contract before using it.', 'success');
  } catch (error) {
    toast('Refinement failed', error.message, 'error');
  } finally {
    restore(button, state.audit.risk_score >= 7 ? 'Generate secure contract' : 'Generate reviewed baseline');
  }
}

function downloadRefinement() {
  if (!state.refinement?.contract_source) return toast('No generated contract', 'Generate a secure baseline first.', 'error');
  download(state.refinement.contract_source, 'chainmind-refined-contract.sol', 'text/plain');
}

// -------------------------------------------------------------
// Real-Time Live Mempool Streaming
// -------------------------------------------------------------

function onMempoolChainChange() {
  if (state.streamRunning) {
    stopStream();
    startStream();
  }
}

function toggleStream() {
  state.streamRunning ? stopStream() : startStream();
}

function startStream() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  state.ws?.close();
  state.ws = new WebSocket(`${protocol}//${location.host}/ws/mempool`);

  state.ws.onopen = () => {
    state.streamRunning = true;
    $('toggleStream').textContent = 'Pause live stream';
    $('streamStatus').innerHTML = '<span class="status-dot"></span>Connecting…';
    state.ws.send(JSON.stringify({ action: 'start', chain: $('mempoolChain').value }));
  };

  state.ws.onmessage = (event) => {
    try {
      handleStreamEvent(JSON.parse(event.data));
    } catch (_) {}
  };

  state.ws.onerror = () => {
    toast('Mempool error', 'WebSocket connection failed. Verify endpoint in Settings.', 'error');
    $('streamStatus').innerHTML = '<span class="status-dot" style="background:#b63e3e"></span>Error';
  };

  state.ws.onclose = () => {
    state.streamRunning = false;
    $('toggleStream').textContent = 'Start live stream';
    $('streamStatus').innerHTML = '<span class="status-dot"></span>Paused';
  };
}

function stopStream() {
  if (state.ws?.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({ action: 'pause' }));
  }
  state.ws?.close();
}

function handleStreamEvent(event) {
  // Handle explicit errors / missing credentials emitted from server
  if (event.error) {
    const warning = $('mempoolCredentialWarning');
    if (warning) {
      warning.classList.remove('hidden');
      $('mempoolWarningTitle').textContent = event.error_code || 'RPC Configuration Required';
      $('mempoolWarningBody').textContent = `${event.one_line_summary} ${event.details || ''}`;
    }
    $('streamStatus').innerHTML = '<span class="status-dot" style="background:#b63e3e"></span>Disconnected';
    $('signalMark').className = 'signal-mark red';
    $('signalTitle').textContent = event.one_line_summary || 'Connection Error';
    $('signalSummary').textContent = event.details || 'Check your RPC endpoint in Settings.';
    toast('RPC Notice', event.one_line_summary, 'error');
    return;
  }

  // Handle connection handshake
  if (event.status === 'CONNECTING') {
    $('streamStatus').innerHTML = '<span class="status-dot"></span>Listening…';
    $('signalMark').className = 'signal-mark';
    $('signalTitle').textContent = 'Listening to Live Network';
    $('signalSummary').textContent = event.one_line_summary || 'Waiting for pending transactions on Ethereum node...';
    return;
  }

  // Real transaction received
  const warning = $('mempoolCredentialWarning');
  if (warning) warning.classList.add('hidden');

  $('streamStatus').innerHTML = '<span class="status-dot"></span>Live';
  const signal = event.signal || 'green';
  const tx = event.tx || {};

  state.streamStats.total++;
  state.streamStats[signal] = (state.streamStats[signal] || 0) + 1;

  $('streamTotal').textContent = state.streamStats.total;
  $('streamSafe').textContent = state.streamStats.green;
  $('streamWarn').textContent = state.streamStats.yellow;
  $('streamCritical').textContent = state.streamStats.red;
  $('terminalCounter').textContent = `${state.streamStats.total} tx processed`;

  $('signalMark').className = `signal-mark ${signal === 'green' ? '' : signal}`;
  $('signalTitle').textContent = signal === 'red' ? 'Critical Activity Detected' : signal === 'yellow' ? 'Elevated Activity' : 'Routine Transaction Flow';
  $('signalSummary').textContent = event.one_line_summary || 'Real pending transaction evaluated.';

  if (event.anomaly_report) {
    state.latestAnomaly = event.anomaly_report;
    $('latestAnomaly').classList.remove('hidden');
  }

  // Build value display
  const valueEth = tx.value_eth || 0;
  let valueHtml = '';
  if (valueEth > 0) {
    const valClass = valueEth >= 50 ? 'critical' : valueEth >= 10 ? 'high' : '';
    valueHtml = `<span class="stream-row-value ${valClass}">${valueEth >= 0.001 ? valueEth.toFixed(4) : '<0.001'} ETH</span>`;
  }

  // Safety badges
  let badges = '';
  if (tx.is_infinite_approval) badges += '<span class="signal-label yellow" style="margin-left:6px;">UNLIMITED APPROVAL</span>';
  if (tx.high_gas_anomaly) badges += '<span class="signal-label yellow" style="margin-left:6px;">HIGH GAS</span>';
  if (tx.risk_level === 'HIGH') badges += '<span class="signal-label yellow" style="margin-left:6px;">UPGRADE</span>';

  const feed = $('streamFeed');
  if (feed.querySelector('.empty-state')) feed.innerHTML = '';

  const row = document.createElement('div');
  row.className = 'stream-row';
  row.dataset.signal = signal;
  row.title = 'Click to inspect transaction details';
  row.innerHTML = `
    <span class="signal-label ${signal}">${signal.toUpperCase()}</span>
    <span title="${esc(tx.tx_hash)}">${esc((tx.tx_hash || '—').slice(0, 16))}…</span>
    <span title="${esc(tx.sender)}">${esc((tx.sender || '—').slice(0, 12))}…</span>
    <span><strong>${esc(tx.decoded_name || tx.classification || 'Routine call')}</strong>${valueHtml}${badges}<small>${esc(tx.function_selector || '0x')}</small></span>
    <span>${tx.count_in_window || 1} tx / ${tx.window_seconds || 10}s</span>
  `;

  row.addEventListener('click', () => {
    openStreamRowDetail(event, tx, signal);
  });

  // Apply signal filter visibility
  if (!matchesSignalFilter(signal)) row.style.display = 'none';

  feed.prepend(row);
  while (feed.children.length > 200) feed.lastElementChild.remove();

  // Auto-scroll
  if (state.autoScroll) feed.scrollTop = 0;
}

function openStreamRowDetail(event, tx, signal) {
  if (event.anomaly_report) {
    state.latestAnomaly = event.anomaly_report;
    openLatestAnomaly();
    return;
  }
  const cls = tx.classification || (signal === 'red' ? 'CRITICAL_ACTIVITY' : signal === 'yellow' ? 'ELEVATED_ACTIVITY' : 'STANDARD_CALL');
  const dummyAnomaly = {
    id: 'Live',
    tx_hash: tx.tx_hash || '—',
    sender: tx.sender || '—',
    target: tx.target || '—',
    function_selector: tx.function_selector || '0x',
    classification: cls,
    frequency_count: tx.count_in_window || 1,
    window_seconds: tx.window_seconds || 10,
    anomaly_reason: event.one_line_summary || 'Live stream mempool event evaluated.',
    detected_at: new Date().toISOString()
  };
  inspectAnomalyObject(dummyAnomaly);
}

function inspectAnomalyObject(row) {
  const cls = row.classification || 'STANDARD_CALL';
  const isCritical = ['MEV_SANDWICH_ATTACK', 'SUSPICIOUS_HIGH_RISK_CALL', 'HIGH_FREQUENCY_BURST'].includes(cls) || (cls === 'LARGE_VALUE_TRANSFER' && (row.value_eth || 0) >= 50) || row.frequency_count >= 5;
  const isMedium = !isCritical && ['INFINITE_APPROVAL', 'HIGH_GAS_SPIKE', 'PROXY_UPGRADE', 'LARGE_VALUE_TRANSFER', 'ELEVATED_ACTIVITY'].includes(cls);
  const riskType = isCritical ? 'critical' : isMedium ? 'warning' : 'safe';
  const threatTitle = isCritical ? 'CRITICAL EXPLOIT VECTOR' : isMedium ? 'ELEVATED RISK TRANSACTION' : 'ROUTINE TRANSACTION';

  const selectorMap = {
    '0x095ea7b3': 'approve(address spender, uint256 amount)',
    '0xa9059cbb': 'transfer(address to, uint256 amount)',
    '0x23b87266': 'transferFrom(address from, address to, uint256 amount)',
    '0x38ed1739': 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)',
    '0x7ff36ab5': 'swapExactETHForTokens(uint256,address[],address,uint256)',
    '0x18cbafe5': 'swapExactTokensForETH(uint256,uint256,address[],address,uint256)',
    '0x3659cfe6': 'upgradeTo(address newImplementation)',
    '0x4f1ef286': 'upgradeToAndCall(address newImplementation, bytes data)',
    '0x2e1a7d4d': 'withdraw(uint256 amount)',
    '0x3ccfd60b': 'withdraw()',
    '0x00f714ce': 'selfdestruct(address)',
    '0x415b3694': 'kill()',
    '0xd0e30db0': 'deposit()'
  };
  const decodedFunction = selectorMap[row.function_selector] || (row.function_selector && row.function_selector !== '0x' ? `Custom Call (${row.function_selector})` : 'Native ETH / Standard Call');

  let impactExplanation = '';
  let playbookItems = [];

  if (cls === 'MEV_SANDWICH_ATTACK') {
    impactExplanation = 'Victim transaction in liquidity pool is subject to predatory sandwiching (front-running buy order followed by back-running sell order). The adversary extracts arbitrage value directly from the victim slippage.';
    playbookItems = [
      'Route pending swaps exclusively through MEV-protected RPC endpoints (e.g. Flashbots Protect, Eden RPC).',
      'Enforce tight slippage tolerance (<=0.5%) in frontend router settings to limit extractive sandwiching profit margins.',
      'Implement TWAP or commit-reveal settlement mechanisms in decentralized exchange contracts.'
    ];
  } else if (cls === 'INFINITE_APPROVAL') {
    impactExplanation = 'Transaction grants MAX_UINT256 unlimited token approval. If the approved contract or spender address is compromised or malicious, 100% of the caller wallet tokens can be drained without additional permission.';
    playbookItems = [
      'Revoke unlimited allowances immediately using Revoke.cash or block explorer approval management.',
      'Adopt exact-amount approvals or EIP-2612 permit with single-use deadlines instead of infinite allowances.',
      'Verify contract source code on block explorer to ensure the spender is a verified protocol router.'
    ];
  } else if (cls === 'HIGH_GAS_SPIKE') {
    impactExplanation = 'Transaction specifies extreme priority gas fee, indicating an active Priority Gas Auction (PGA). The sender is aggressively outbidding pending transactions to front-run a profitable liquidation, mint, or arbitrage.';
    playbookItems = [
      'If your transaction is stuck or being front-run, issue a replacement transaction with matching nonce and equal or higher priority fee.',
      'Utilize private relayers (Flashbots Protect) to eliminate public mempool priority bidding competition.',
      'Monitor target contract for concurrent liquidation calls.'
    ];
  } else if (cls === 'PROXY_UPGRADE') {
    impactExplanation = 'Privileged implementation change invoked on a proxy contract. If executed by an unverified or compromised account, this allows arbitrary replacement of contract logic and storage alteration.';
    playbookItems = [
      'Verify that the sender address matches the official protocol multisig or timelock governor.',
      'Verify implementation contract code on block explorer and ensure storage layout compatibility.',
      'Enforce minimum 48-hour timelock delay on all proxy upgrade operations.'
    ];
  } else if (cls === 'SUSPICIOUS_HIGH_RISK_CALL') {
    impactExplanation = 'Invocation of a potentially destructive or emergency drain method. May attempt contract self-destruction, emergency asset withdrawal, or unverified privileged parameter modification.';
    playbookItems = [
      'Inspect sender permissions: Confirm caller is strictly authorized by multisig/timelock access control.',
      'Pause affected smart contract pool if the call originated from an unauthorized or unknown account.',
      'Review contract state variables on block explorer before final block inclusion.'
    ];
  } else if (cls === 'HIGH_FREQUENCY_BURST' || cls === 'ELEVATED_ACTIVITY') {
    impactExplanation = `Sender generated a high-velocity burst of ${row.frequency_count} transactions within a ${row.window_seconds}s sliding window. Indicates automated bot hammering, liquidation spam, or mempool flooding.`;
    playbookItems = [
      'Implement sliding-window nonce throttling or CAPTCHA/proof-of-work on off-chain relayers.',
      'Add smart contract reentrancy and per-block sender rate limiters.',
      'Trace sender address history on explorer to identify automated bot clusters.'
    ];
  } else if (cls === 'LARGE_VALUE_TRANSFER') {
    impactExplanation = 'Significant on-chain funds movement detected in pending mempool. Potential whale rebalancing, exchange deposit/withdrawal, or impending market dump.';
    playbookItems = [
      'Verify recipient address against known exchange hot wallets and protocol treasuries.',
      'Monitor associated automated market maker (AMM) pools for sudden price and reserve volatility.'
    ];
  } else {
    impactExplanation = 'Routine mempool transaction evaluated. No malicious exploit patterns detected.';
    playbookItems = [
      'Standard transaction monitoring active. No manual intervention required.'
    ];
  }

  const rate = (row.frequency_count / Math.max(0.1, Number(row.window_seconds || 10))).toFixed(2);

  $('detailContent').innerHTML = `
    <div class="inspect-container">
      <div class="inspect-header-banner ${riskType}">
        <div>
          <span class="eyebrow" style="color:${isCritical ? '#991b1b' : isMedium ? '#92400e' : '#065f46'}">Mempool Stream Anomaly #${row.id}</span>
          <h2 style="font-size:1.15rem;margin:4px 0 2px;">${esc(titleCase(cls))}</h2>
          <div class="inspect-meta-bar">
            <span class="inspect-meta-pill highlight">${esc(cls)}</span>
            <span class="inspect-meta-pill">${row.frequency_count} tx / ${row.window_seconds}s</span>
            <span class="inspect-meta-pill">${rate} tx/sec</span>
            <span class="inspect-meta-pill">${prettyDate(row.detected_at)}</span>
          </div>
        </div>
        <span class="inspect-threat-badge ${riskType}">${threatTitle}</span>
      </div>

      <div class="inspect-section">
        <h4 class="inspect-section-title">Detection Reason & Trigger Analysis</h4>
        <div class="inspect-impact-box ${riskType}">
          ${esc(row.anomaly_reason || 'Anomalous mempool transaction activity flagged by sliding-window security engine.')}
        </div>
      </div>

      <div class="inspect-section">
        <h4 class="inspect-section-title">Transaction & Calldata Parameters</h4>
        <div class="inspect-grid-card">
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Transaction Hash</span>
            <span class="inspect-grid-value mono">${esc(row.tx_hash || '—')}</span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Origin Sender (from)</span>
            <span class="inspect-grid-value mono">${esc(row.sender || '—')}</span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Target Contract / Pool (to)</span>
            <span class="inspect-grid-value mono">${esc(row.target || '—')}</span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Function Selector</span>
            <span class="inspect-grid-value mono">${esc(row.function_selector || '0x')} <span style="font-weight:400;color:var(--muted);font-size:0.7rem;">(${esc(decodedFunction)})</span></span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Velocity Telemetry</span>
            <span class="inspect-grid-value">${row.frequency_count} txs in ${row.window_seconds}s (${rate} tx/sec)</span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Detection Timestamp</span>
            <span class="inspect-grid-value">${prettyDate(row.detected_at)}</span>
          </div>
        </div>
      </div>

      <div class="inspect-section">
        <h4 class="inspect-section-title">Threat & Exploit Impact Assessment</h4>
        <div class="inspect-impact-box ${riskType}">
          ${esc(impactExplanation)}
        </div>
      </div>

      <div class="inspect-section">
        <h4 class="inspect-section-title">Actionable Defense & Containment Playbook</h4>
        <ul class="inspect-playbook-list">
          ${playbookItems.map((item, i) => `
            <li class="inspect-playbook-item ${isCritical && i === 0 ? 'priority' : ''}">
              <span class="inspect-playbook-num">0${i + 1}</span>
              <span>${esc(item)}</span>
            </li>
          `).join('')}
        </ul>
      </div>
    </div>
  `;
  openModal('detailModal');
}

function matchesSignalFilter(signal) {
  const f = state.signalFilter;
  if (f === 'all') return true;
  if (f === 'red') return signal === 'red';
  if (f === 'green') return signal === 'green';
  if (f === 'yellow+red') return signal === 'yellow' || signal === 'red';
  return true;
}

function applySignalFilter() {
  const feed = $('streamFeed');
  feed.querySelectorAll('.stream-row').forEach((row) => {
    row.style.display = matchesSignalFilter(row.dataset.signal) ? '' : 'none';
  });
}

function clearStreamFeed() {
  const feed = $('streamFeed');
  feed.innerHTML = '<div class="empty-state">Terminal cleared. Stream data will appear when new transactions arrive.</div>';
  state.streamStats = { total: 0, green: 0, yellow: 0, red: 0 };
  $('streamTotal').textContent = '0';
  $('streamSafe').textContent = '0';
  $('streamWarn').textContent = '0';
  $('streamCritical').textContent = '0';
  $('terminalCounter').textContent = '0 tx processed';
  toast('Terminal cleared', 'Feed and counters reset.', 'success');
}

function toggleScrollLock() {
  state.autoScroll = !state.autoScroll;
  const btn = $('btnScrollLock');
  btn.classList.toggle('active', state.autoScroll);
  btn.textContent = state.autoScroll ? 'Auto-Scroll' : 'Scroll Locked';
}

function openLatestAnomaly() {
  const report = state.latestAnomaly;
  if (!report) return;
  const isCritical = (report.severity || '').toUpperCase() === 'CRITICAL';
  const riskType = isCritical ? 'critical' : 'warning';
  const tx = report.transaction || {};
  const freq = report.frequency_metrics || {};

  $('detailContent').innerHTML = `
    <div class="inspect-container">
      <div class="inspect-header-banner ${riskType}">
        <div>
          <span class="eyebrow" style="color:${isCritical ? '#991b1b' : '#92400e'}">Real-Time Mempool Stream Alert</span>
          <h2 style="font-size:1.15rem;margin:4px 0 2px;">${esc(report.title || 'Mempool Anomaly')}</h2>
          <div class="inspect-meta-bar">
            <span class="inspect-meta-pill highlight">${esc(report.anomaly_type || 'ANOMALY')}</span>
            <span class="inspect-meta-pill">${freq.count_in_window || 1} tx / ${freq.window_seconds || 10}s</span>
            <span class="inspect-meta-pill">${freq.calculated_rate_tx_per_sec || 0} tx/sec</span>
            <span class="inspect-meta-pill">${prettyDate(report.detected_at)}</span>
          </div>
        </div>
        <span class="inspect-threat-badge ${riskType}">${isCritical ? 'CRITICAL THREAT DETECTED' : 'ELEVATED RISK CALL'}</span>
      </div>

      <div class="inspect-section">
        <h4 class="inspect-section-title">Detection Reason & Trigger Analysis</h4>
        <div class="inspect-impact-box ${riskType}">
          ${esc(report.reason || 'Anomalous mempool transaction activity flagged.')}
        </div>
      </div>

      <div class="inspect-section">
        <h4 class="inspect-section-title">Transaction & Calldata Parameters</h4>
        <div class="inspect-grid-card">
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Transaction Hash</span>
            <span class="inspect-grid-value mono">${esc(tx.tx_hash || '—')}</span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Origin Sender (from)</span>
            <span class="inspect-grid-value mono">${esc(tx.sender || '—')}</span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Target Contract / Pool (to)</span>
            <span class="inspect-grid-value mono">${esc(tx.target || '—')}</span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Function Selector</span>
            <span class="inspect-grid-value mono">${esc(tx.function_selector || '0x')} <span style="font-weight:400;color:var(--muted);font-size:0.7rem;">(${esc(tx.function_name || 'Call')})</span></span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Gas Price</span>
            <span class="inspect-grid-value">${tx.gas_price_gwei ? `${tx.gas_price_gwei.toFixed(1)} Gwei` : 'Standard'}</span>
          </div>
          <div class="inspect-grid-item">
            <span class="inspect-grid-label">Velocity Telemetry</span>
            <span class="inspect-grid-value">${freq.count_in_window || 1} txs in ${freq.window_seconds || 10}s (${freq.calculated_rate_tx_per_sec || 0} tx/sec)</span>
          </div>
        </div>
      </div>

      <div class="inspect-section">
        <h4 class="inspect-section-title">Threat & Exploit Impact Assessment</h4>
        <div class="inspect-impact-box ${riskType}">
          ${esc(report.impact_assessment || 'Review sender and target before executing on-chain actions.')}
        </div>
      </div>

      <div class="inspect-section">
        <h4 class="inspect-section-title">Actionable Defense & Containment Playbook</h4>
        <ul class="inspect-playbook-list">
          ${(report.actionable_mitigations || []).map((item, i) => `
            <li class="inspect-playbook-item ${isCritical && i === 0 ? 'priority' : ''}">
              <span class="inspect-playbook-num">0${i + 1}</span>
              <span>${esc(item)}</span>
            </li>
          `).join('')}
        </ul>
      </div>
    </div>
  `;
  openModal('detailModal');
}

// -------------------------------------------------------------
// History and Record Inspection
// -------------------------------------------------------------

function setHistoryMode(mode) {
  state.historyMode = mode;
  state.historyPage = 1;
  document.querySelectorAll('[data-history-mode]').forEach((button) => button.classList.toggle('active', button.dataset.historyMode === mode));

  const riskGroup = $('historyRiskGroup');
  if (riskGroup) riskGroup.style.display = mode === 'audits' ? '' : 'none';

  const classGroup = $('historyClassificationGroup');
  if (classGroup) classGroup.style.display = mode === 'anomalies' ? '' : 'none';

  const riskFilter = $('historyRiskFilter');
  if (riskFilter) riskFilter.value = 'all';
  const classFilter = $('historyClassFilter');
  if (classFilter) classFilter.value = 'all';
  state.historyRiskFilter = 'all';
  state.historyClassFilter = 'all';

  loadHistory();
}

function debounceHistory() {
  clearTimeout(state.historyTimer);
  state.historyTimer = setTimeout(() => {
    state.historySearch = $('historySearch').value;
    state.historyPage = 1;
    loadHistory();
  }, 300);
}

function changeHistoryPage(delta) {
  state.historyPage = Math.max(1, state.historyPage + delta);
  loadHistory();
}

async function loadHistory() {
  const btn = $('refreshHistory');
  if (btn) busy(btn, 'Loading…');
  try {
    const endpoint = state.historyMode === 'audits' ? '/api/history/audits' : '/api/history/anomalies';
    const params = new URLSearchParams({
      page: state.historyPage,
      page_size: 10,
      search: state.historySearch,
      sort_order: state.historySortOrder
    });

    if (state.historyMode === 'audits') {
      const riskRanges = { all: [0, 10], safe: [0, 3], warning: [4, 6], critical: [7, 10] };
      const [rMin, rMax] = riskRanges[state.historyRiskFilter] || [0, 10];
      params.set('risk_min', rMin);
      params.set('risk_max', rMax);
    } else {
      if (state.historyClassFilter !== 'all') {
        params.set('classification', state.historyClassFilter);
      }
    }

    const data = await api(`${endpoint}?${params.toString()}`);
    renderHistory(data);
  } catch (error) {
    toast('History unavailable', error.message, 'error');
  } finally {
    if (btn) restore(btn, 'Refresh');
  }
}

function renderHistory(data) {
  const audits = state.historyMode === 'audits';
  $('historyCount').textContent = `Showing ${data.showing_from}-${data.showing_to} of ${data.total}`;
  $('historyPage').textContent = `Page ${data.page} of ${data.total_pages}`;
  $('historyPrev').disabled = data.page <= 1;
  $('historyNext').disabled = data.page >= data.total_pages;

  $('historyHead').innerHTML = audits
    ? '<tr><th>Target</th><th>Risk</th><th>Priority</th><th>Injections</th><th>Audited</th><th></th></tr>'
    : '<tr><th>Transaction</th><th>Classification</th><th>Priority</th><th>Burst</th><th>Detected</th><th></th></tr>';

  $('historyBody').innerHTML = data.items.length ? data.items.map((row) => audits
     ? `<tr><td><div>${esc(row.target_address)}</div><div class="table-sub">${esc(row.summary || '')}</div></td><td><span class="tag">${row.risk_score}/10 ${riskLabel(row.risk_score)}</span></td><td>${priorityBadge(Number(row.risk_score) >= 7 ? 'critical' : Number(row.risk_score) >= 4 ? 'high' : 'routine')}</td><td>${row.detected_injections || 0}</td><td>${prettyDate(row.audit_timestamp)}</td><td><button class="button button-quiet" onclick="inspectAudit(${row.id})">Inspect</button></td></tr>`
     : `<tr><td><div class="mono">${esc((row.tx_hash || '').slice(0, 18))}…</div><div class="table-sub">${esc(row.sender || '')}</div></td><td><span class="tag">${esc(row.classification)}</span></td><td>${priorityBadge(anomalyPriority(row.classification))}</td><td>${row.frequency_count} / ${row.window_seconds}s</td><td>${prettyDate(row.detected_at)}</td><td><button class="button button-quiet" onclick="inspectAnomaly(${row.id})">Inspect</button></td></tr>`
  ).join('') : `<tr><td colspan="6"><div class="empty-state">No matching records found.</div></td></tr>`;
}

function anomalyPriority(classification) {
  if (['MEV_SANDWICH_ATTACK', 'SUSPICIOUS_HIGH_RISK_CALL', 'HIGH_FREQUENCY_BURST'].includes(classification)) return 'critical';
  if (['PROXY_UPGRADE', 'INFINITE_APPROVAL', 'HIGH_GAS_SPIKE', 'LARGE_VALUE_TRANSFER'].includes(classification)) return 'high';
  return 'routine';
}

function priorityBadge(level) {
  const labels = { critical: 'P1 critical', high: 'P2 review', routine: 'P3 routine' };
  return `<span class="priority-pill ${level === 'critical' ? 'critical' : level === 'high' ? 'high' : ''}">${labels[level] || labels.routine}</span>`;
}

async function inspectAudit(id) {
  try {
    const record = await api(`/api/history/audit/${id}`);
    const score = Number(record.risk_score || 0);
    const isCritical = score >= 7;
    const isMedium = score >= 4 && score < 7;
    const riskType = isCritical ? 'critical' : isMedium ? 'warning' : 'safe';
    const threatTitle = isCritical ? 'CRITICAL SECURITY THREAT' : isMedium ? 'ELEVATED / MEDIUM RISK' : 'LOW RISK / ROUTINE';
    const findings = record.security_findings || [];
    const recommendations = record.actionable_recommendations || [];

    let findingsHtml = '';
    if (findings.length) {
      findingsHtml = findings.map((f, idx) => {
        const sev = (f.severity || (isCritical ? 'CRITICAL' : 'MEDIUM')).toUpperCase();
        const sevClass = sev === 'CRITICAL' || sev === 'HIGH' ? 'critical' : sev === 'MEDIUM' ? 'medium' : 'low';
        return `
          <div class="inspect-finding-card ${sevClass}">
            <div class="inspect-finding-header">
              <h4 class="inspect-finding-title">${esc(f.title || f.rule_id || `Vulnerability #${idx + 1}`)}</h4>
              <span class="signal-label ${sevClass === 'critical' ? 'red' : sevClass === 'medium' ? 'yellow' : 'green'}">${esc(sev)}</span>
            </div>
            ${f.rule_id ? `<div style="font-size:0.68rem;color:var(--muted);font-weight:600;">Rule / CWE: <span class="mono">${esc(f.rule_id)}</span></div>` : ''}
            ${f.location ? `<div class="inspect-code-location">Target: ${esc(f.location)}</div>` : ''}
            <p style="font-size:0.75rem;color:var(--ink);margin:4px 0 0;line-height:1.5;">${esc(f.description || 'Vulnerability detected in contract logic.')}</p>
            ${f.recommendation ? `
              <div class="inspect-mitigation-box">
                <strong style="display:block;font-size:0.68rem;color:#0f172a;margin-bottom:2px;">Mitigation & Code Pattern:</strong>
                ${esc(f.recommendation)}
              </div>
            ` : ''}
          </div>
        `;
      }).join('');
    } else {
      findingsHtml = '<div class="empty-state" style="padding:16px;">No specific vulnerability findings flagged for this record.</div>';
    }

    // High & Medium Risk Playbook
    let playbookHtml = '';
    if (isCritical || isMedium) {
      const defaultPlaybook = isCritical ? [
        'Apply Checks-Effects-Interactions (CEI) pattern and OpenZeppelin ReentrancyGuard mutex on state-altering functions.',
        'Enforce strict multi-signature (e.g. Gnosis Safe 3-of-5) and timelock delays on administrative methods.',
        'Use SafeERC20 wrapper (safeTransfer / safeTransferFrom) to guard against non-standard token return values.',
        'Integrate decentralized TWAP oracles or slippage constraints to prevent single-block flash loan arbitrage.',
        'Execute formal verification and invariant fuzz testing suite (Foundry / Echidna) before mainnet release.'
      ] : [
        'Review access control modifiers (onlyOwner, onlyRole) to avoid unintended caller execution.',
        'Verify zero-address validation and bounds checking on all input arguments.',
        'Ensure token allowances and transfer amounts are explicitly validated against contract state.',
        'Conduct peer code review and static analysis checks prior to contract upgrade.'
      ];

      const activePlaybook = recommendations.length ? recommendations : defaultPlaybook;
      playbookHtml = `
        <div class="inspect-section">
          <h4 class="inspect-section-title">Actionable Defense & Remediation Playbook</h4>
          <ul class="inspect-playbook-list">
            ${activePlaybook.map((item, i) => `
              <li class="inspect-playbook-item ${isCritical && i < 2 ? 'priority' : ''}">
                <span class="inspect-playbook-num">0${i + 1}</span>
                <span>${esc(item)}</span>
              </li>
            `).join('')}
          </ul>
        </div>
      `;
    }

    $('detailContent').innerHTML = `
      <div class="inspect-container">
        <div class="inspect-header-banner ${riskType}">
          <div>
            <span class="eyebrow" style="color:${isCritical ? '#991b1b' : isMedium ? '#92400e' : '#065f46'}">Smart Contract Audit Record #${record.id}</span>
            <h2 style="font-size:1.15rem;margin:4px 0 2px;">${esc(record.target_address || 'Contract Audit')}</h2>
            <div class="inspect-meta-bar">
              <span class="inspect-meta-pill highlight">Score: ${score}/10</span>
              <span class="inspect-meta-pill">${record.detected_injections || 0} Injections Neutralized</span>
              <span class="inspect-meta-pill">${prettyDate(record.audit_timestamp)}</span>
            </div>
          </div>
          <span class="inspect-threat-badge ${riskType}">${threatTitle}</span>
        </div>

        <div class="inspect-section">
          <h4 class="inspect-section-title">Executive Security Assessment</h4>
          <div class="inspect-impact-box ${riskType}">
            ${esc(record.summary || 'Security evaluation completed. Review identified findings and remediation playbook below.')}
          </div>
        </div>

        <div class="inspect-section">
          <h4 class="inspect-section-title">Contract & Analysis Parameters</h4>
          <div class="inspect-grid-card">
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Target Identifier</span>
              <span class="inspect-grid-value mono">${esc(record.target_address || '—')}</span>
            </div>
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Analysis Profile</span>
              <span class="inspect-grid-value">${esc(record.analysis_type || 'SMART_CONTRACT_AUDIT')}</span>
            </div>
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Ingestion Shield</span>
              <span class="inspect-grid-value">${record.detected_injections || 0} malicious prompt injections neutralized</span>
            </div>
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Timestamp</span>
              <span class="inspect-grid-value">${prettyDate(record.audit_timestamp)}</span>
            </div>
          </div>
        </div>

        <div class="inspect-section">
          <h4 class="inspect-section-title">Vulnerability Findings (${findings.length})</h4>
          <div style="display:flex;flex-direction:column;gap:10px;">
            ${findingsHtml}
          </div>
        </div>

        ${playbookHtml}
      </div>
    `;
    openModal('detailModal');
  } catch (error) {
    toast('Could not load audit', error.message, 'error');
  }
}

async function inspectAnomaly(id) {
  try {
    const row = await api(`/api/history/anomaly/${id}`);
    const cls = row.classification || 'STANDARD_CALL';
    const isCritical = ['MEV_SANDWICH_ATTACK', 'SUSPICIOUS_HIGH_RISK_CALL', 'HIGH_FREQUENCY_BURST'].includes(cls) || (cls === 'LARGE_VALUE_TRANSFER' && (row.value_eth || 0) >= 50) || row.frequency_count >= 5;
    const isMedium = !isCritical && ['INFINITE_APPROVAL', 'HIGH_GAS_SPIKE', 'PROXY_UPGRADE', 'LARGE_VALUE_TRANSFER', 'ELEVATED_ACTIVITY'].includes(cls);
    const riskType = isCritical ? 'critical' : isMedium ? 'warning' : 'safe';
    const threatTitle = isCritical ? 'CRITICAL EXPLOIT VECTOR' : isMedium ? 'ELEVATED RISK TRANSACTION' : 'ROUTINE TRANSACTION';

    // Decode selector if known
    const selectorMap = {
      '0x095ea7b3': 'approve(address spender, uint256 amount)',
      '0xa9059cbb': 'transfer(address to, uint256 amount)',
      '0x23b87266': 'transferFrom(address from, address to, uint256 amount)',
      '0x38ed1739': 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)',
      '0x7ff36ab5': 'swapExactETHForTokens(uint256,address[],address,uint256)',
      '0x18cbafe5': 'swapExactTokensForETH(uint256,uint256,address[],address,uint256)',
      '0x3659cfe6': 'upgradeTo(address newImplementation)',
      '0x4f1ef286': 'upgradeToAndCall(address newImplementation, bytes data)',
      '0x2e1a7d4d': 'withdraw(uint256 amount)',
      '0x3ccfd60b': 'withdraw()',
      '0x00f714ce': 'selfdestruct(address)',
      '0x415b3694': 'kill()',
      '0xd0e30db0': 'deposit()'
    };
    const decodedFunction = selectorMap[row.function_selector] || (row.function_selector && row.function_selector !== '0x' ? `Custom Call (${row.function_selector})` : 'Native ETH / Standard Call');

    // Impact assessments based on classification
    let impactExplanation = '';
    let playbookItems = [];

    if (cls === 'MEV_SANDWICH_ATTACK') {
      impactExplanation = 'Victim transaction in liquidity pool is subject to predatory sandwiching (front-running buy order followed by back-running sell order). The adversary extracts arbitrage value directly from the victim slippage.';
      playbookItems = [
        'Route pending swaps exclusively through MEV-protected RPC endpoints (e.g. Flashbots Protect, Eden RPC).',
        'Enforce tight slippage tolerance (<=0.5%) in frontend router settings to limit extractive sandwiching profit margins.',
        'Implement TWAP or commit-reveal settlement mechanisms in decentralized exchange contracts.'
      ];
    } else if (cls === 'INFINITE_APPROVAL') {
      impactExplanation = 'Transaction grants MAX_UINT256 unlimited token approval. If the approved contract or spender address is compromised or malicious, 100% of the caller wallet tokens can be drained without additional permission.';
      playbookItems = [
        'Revoke unlimited allowances immediately using Revoke.cash or block explorer approval management.',
        'Adopt exact-amount approvals or EIP-2612 permit with single-use deadlines instead of infinite allowances.',
        'Verify contract source code on block explorer to ensure the spender is a verified protocol router.'
      ];
    } else if (cls === 'HIGH_GAS_SPIKE') {
      impactExplanation = 'Transaction specifies extreme priority gas fee, indicating an active Priority Gas Auction (PGA). The sender is aggressively outbidding pending transactions to front-run a profitable liquidation, mint, or arbitrage.';
      playbookItems = [
        'If your transaction is stuck or being front-run, issue a replacement transaction with matching nonce and equal or higher priority fee.',
        'Utilize private relayers (Flashbots Protect) to eliminate public mempool priority bidding competition.',
        'Monitor target contract for concurrent liquidation calls.'
      ];
    } else if (cls === 'PROXY_UPGRADE') {
      impactExplanation = 'Privileged implementation change invoked on a proxy contract. If executed by an unverified or compromised account, this allows arbitrary replacement of contract logic and storage alteration.';
      playbookItems = [
        'Verify that the sender address matches the official protocol multisig or timelock governor.',
        'Verify implementation contract code on block explorer and ensure storage layout compatibility.',
        'Enforce minimum 48-hour timelock delay on all proxy upgrade operations.'
      ];
    } else if (cls === 'SUSPICIOUS_HIGH_RISK_CALL') {
      impactExplanation = 'Invocation of a potentially destructive or emergency drain method. May attempt contract self-destruction, emergency asset withdrawal, or unverified privileged parameter modification.';
      playbookItems = [
        'Inspect sender permissions: Confirm caller is strictly authorized by multisig/timelock access control.',
        'Pause affected smart contract pool if the call originated from an unauthorized or unknown account.',
        'Review contract state variables on block explorer before final block inclusion.'
      ];
    } else if (cls === 'HIGH_FREQUENCY_BURST' || cls === 'ELEVATED_ACTIVITY') {
      impactExplanation = `Sender generated a high-velocity burst of ${row.frequency_count} transactions within a ${row.window_seconds}s sliding window. Indicates automated bot hammering, liquidation spam, or mempool flooding.`;
      playbookItems = [
        'Implement sliding-window nonce throttling or CAPTCHA/proof-of-work on off-chain relayers.',
        'Add smart contract reentrancy and per-block sender rate limiters.',
        'Trace sender address history on explorer to identify automated bot clusters.'
      ];
    } else if (cls === 'LARGE_VALUE_TRANSFER') {
      impactExplanation = 'Significant on-chain funds movement detected in pending mempool. Potential whale rebalancing, exchange deposit/withdrawal, or impending market dump.';
      playbookItems = [
        'Verify recipient address against known exchange hot wallets and protocol treasuries.',
        'Monitor associated automated market maker (AMM) pools for sudden price and reserve volatility.'
      ];
    } else {
      impactExplanation = 'Routine mempool transaction evaluated. No malicious exploit patterns detected.';
      playbookItems = [
        'Standard transaction monitoring active. No manual intervention required.'
      ];
    }

    const rate = (row.frequency_count / Math.max(0.1, Number(row.window_seconds || 10))).toFixed(2);

    $('detailContent').innerHTML = `
      <div class="inspect-container">
        <div class="inspect-header-banner ${riskType}">
          <div>
            <span class="eyebrow" style="color:${isCritical ? '#991b1b' : isMedium ? '#92400e' : '#065f46'}">Mempool Stream Anomaly #${row.id}</span>
            <h2 style="font-size:1.15rem;margin:4px 0 2px;">${esc(titleCase(cls))}</h2>
            <div class="inspect-meta-bar">
              <span class="inspect-meta-pill highlight">${esc(cls)}</span>
              <span class="inspect-meta-pill">${row.frequency_count} tx / ${row.window_seconds}s</span>
              <span class="inspect-meta-pill">${rate} tx/sec</span>
              <span class="inspect-meta-pill">${prettyDate(row.detected_at)}</span>
            </div>
          </div>
          <span class="inspect-threat-badge ${riskType}">${threatTitle}</span>
        </div>

        <div class="inspect-section">
          <h4 class="inspect-section-title">Detection Reason & Trigger Analysis</h4>
          <div class="inspect-impact-box ${riskType}">
            ${esc(row.anomaly_reason || 'Anomalous mempool transaction activity flagged by sliding-window security engine.')}
          </div>
        </div>

        <div class="inspect-section">
          <h4 class="inspect-section-title">Transaction & Calldata Parameters</h4>
          <div class="inspect-grid-card">
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Transaction Hash</span>
              <span class="inspect-grid-value mono">${esc(row.tx_hash || '—')}</span>
            </div>
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Origin Sender (from)</span>
              <span class="inspect-grid-value mono">${esc(row.sender || '—')}</span>
            </div>
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Target Contract / Pool (to)</span>
              <span class="inspect-grid-value mono">${esc(row.target || '—')}</span>
            </div>
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Function Selector</span>
              <span class="inspect-grid-value mono">${esc(row.function_selector || '0x')} <span style="font-weight:400;color:var(--muted);font-size:0.7rem;">(${esc(decodedFunction)})</span></span>
            </div>
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Velocity Telemetry</span>
              <span class="inspect-grid-value">${row.frequency_count} txs in ${row.window_seconds}s (${rate} tx/sec)</span>
            </div>
            <div class="inspect-grid-item">
              <span class="inspect-grid-label">Detection Timestamp</span>
              <span class="inspect-grid-value">${prettyDate(row.detected_at)}</span>
            </div>
          </div>
        </div>

        <div class="inspect-section">
          <h4 class="inspect-section-title">Threat & Exploit Impact Assessment</h4>
          <div class="inspect-impact-box ${riskType}">
            ${esc(impactExplanation)}
          </div>
        </div>

        <div class="inspect-section">
          <h4 class="inspect-section-title">Actionable Defense & Containment Playbook</h4>
          <ul class="inspect-playbook-list">
            ${playbookItems.map((item, i) => `
              <li class="inspect-playbook-item ${isCritical && i === 0 ? 'priority' : ''}">
                <span class="inspect-playbook-num">0${i + 1}</span>
                <span>${esc(item)}</span>
              </li>
            `).join('')}
          </ul>
        </div>
      </div>
    `;
    openModal('detailModal');
  } catch (error) {
    toast('Could not load anomaly', error.message, 'error');
  }
}

// -------------------------------------------------------------
// Settings & Authentication
// -------------------------------------------------------------

async function authenticate(event) {
  event.preventDefault();
  await authenticateValue($('authPasscode').value.trim(), true);
}

async function authenticateValue(passcode, feedback) {
  try {
    await api('/api/settings/verify-auth', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ passcode })
    });
    state.passcode = passcode;
    state.authenticated = true;
    sessionStorage.setItem('chainmind_admin_pass', passcode);
    $('settingsLock').textContent = 'Unlocked';
    closeModal('authModal');
    switchView('settings');
    if (feedback) toast('Settings unlocked', 'Configuration is now editable.', 'success');
    return true;
  } catch (error) {
    if (feedback) toast('Access denied', error.message, 'error');
    return false;
  }
}

async function loadSettings() {
  if (!state.authenticated) return;
  try {
    const data = await api('/api/settings/load', { headers: { 'X-Admin-Passcode': state.passcode } });
    const s = data.settings || {};
    const configured = s.configured_secrets || {};

    $('cfgGemini').value = '';
    $('cfgGemini').placeholder = configured.gemini_api_key ? 'Saved key configured — enter to replace' : 'Not configured';
    $('cfgGeminiHint').textContent = configured.gemini_api_key ? 'A Gemini key is configured.' : 'No key configured. Running local heuristic checks.';

    [['cfgEtherscan','etherscan_api_key'],['cfgArbiscan','arbiscan_api_key'],['cfgPolygonscan','polygonscan_api_key'],['cfgBasescan','basescan_api_key'],['cfgOptimistic','optimistic_api_key']].forEach(([id, key]) => {
      $(id).value = '';
      $(id).placeholder = configured[key] ? 'Saved key configured — enter to replace' : 'Optional (Free Tier Rate-Limited)';
    });

    $('cfgRpcWs').value = s.eth_rpc_ws_url || '';
    $('cfgRpcHttp').value = s.eth_rpc_http_url || '';
    $('cfgChain').value = s.default_chain || 'ethereum';
    $('cfgWindow').value = s.sliding_window_seconds || 10;
    $('cfgThreshold').value = s.anomaly_tx_threshold || 5;
    $('cfgStrict').checked = Boolean(s.strict_mode);
    $('cfgHeuristic').checked = s.enable_heuristic_engine !== false;
    $('cfgLlm').checked = s.enable_llm_engine !== false;
    $('cfgSelector').checked = s.enable_selector_analysis !== false;
    $('cfgFrequency').checked = s.enable_frequency_analysis !== false;
    $('cfgSandwich').checked = s.enable_sandwich_detection !== false;
    $('cfgNeutralization').checked = s.enable_prompt_neutralization !== false;
    $('cfgRetention').value = s.history_retention_days || 30;
    $('cfgMaxRecords').value = s.history_max_records || 1000;

    $('settingsLocked').classList.add('hidden');
    $('settingsContent').classList.remove('hidden');
  } catch (error) {
    toast('Could not load settings', error.message, 'error');
  }
}

async function saveSettings(event) {
  event.preventDefault();
  const button = $('saveSettings');
  busy(button, 'Saving…');

  const settingsPayload = {
    eth_rpc_ws_url: $('cfgRpcWs').value.trim(),
    eth_rpc_http_url: $('cfgRpcHttp').value.trim(),
    default_chain: $('cfgChain').value,
    sliding_window_seconds: Number($('cfgWindow').value),
    anomaly_tx_threshold: Number($('cfgThreshold').value),
    strict_mode: $('cfgStrict').checked
    , enable_heuristic_engine: $('cfgHeuristic').checked
    , enable_llm_engine: $('cfgLlm').checked
    , enable_selector_analysis: $('cfgSelector').checked
    , enable_frequency_analysis: $('cfgFrequency').checked
    , enable_sandwich_detection: $('cfgSandwich').checked
    , enable_prompt_neutralization: $('cfgNeutralization').checked
    , history_retention_days: Number($('cfgRetention').value)
    , history_max_records: Number($('cfgMaxRecords').value)
  };

  [['cfgGemini','gemini_api_key'],['cfgEtherscan','etherscan_api_key'],['cfgArbiscan','arbiscan_api_key'],['cfgPolygonscan','polygonscan_api_key'],['cfgBasescan','basescan_api_key'],['cfgOptimistic','optimistic_api_key'],['cfgPasscode','new_admin_passcode']].forEach(([id, key]) => {
    if ($(id).value.trim()) settingsPayload[key] = $(id).value.trim();
  });

  try {
    await api('/api/settings/save', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ passcode: state.passcode, settings: settingsPayload })
    });
    $('cfgPasscode').value = '';
    toast('Settings saved', 'Configuration updated successfully.', 'success');
    await refreshAll();
    await loadSettings();
  } catch (error) {
    toast('Could not save settings', error.message, 'error');
  } finally {
    restore(button, 'Save changes →');
  }
}

// -------------------------------------------------------------
// Exporters and Utility Helpers
// -------------------------------------------------------------

async function exportAudit(type) {
  if (!state.audit) return toast('No report to export', 'Run an audit first.', 'error');
  try {
    let endpoint = type === 'json' ? null : `/api/export/${type}`;
    if (!endpoint) return download(JSON.stringify(state.audit, null, 2), 'audit_report.json', 'application/json');

    const payload = type === 'patch'
      ? { source_code: $('contractSource').value, findings: state.audit.security_findings || [] }
      : state.audit;

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    if (!response.ok) throw new Error('Export failed');
    const contentType = type === 'html' ? 'text/html' : type === 'patch' ? 'text/x-diff' : 'application/json';
    download(await response.text(), `audit_report.${type === 'patch' ? 'patch' : type === 'html' ? 'html' : 'json'}`, contentType);
  } catch (error) {
    toast('Export failed', error.message, 'error');
  }
}

function download(content, name, type) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([content], { type }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

function openModal(id) { $(id).classList.add('open'); }
function closeModal(id) { $(id).classList.remove('open'); }
function busy(button, label) { button.disabled = true; button.textContent = label; }
function restore(button, label) { button.disabled = false; button.textContent = label; }
function toast(title, message, type = 'success') {
  const item = document.createElement('div');
  item.className = `toast ${type}`;
  item.innerHTML = `<strong>${esc(title)}</strong><span>${esc(message)}</span>`;
  $('toastRegion').appendChild(item);
  setTimeout(() => item.remove(), 4500);
}
function titleCase(value) { return String(value).replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()); }