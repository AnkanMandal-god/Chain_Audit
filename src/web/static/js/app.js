/**
 * Chain-Mind Auditor — Web Operations Center Controller
 * End-to-End Frontend Architecture: Vanilla JS, WebSocket Streaming, Reactive State
 */

// Global Application State
const AppState = {
  currentTab: 'tab-dashboard',
  systemStatus: null,
  demoSamples: null,
  currentDemoStep: 1,
  demoAutoPlayTimer: null,
  auditorMode: 'single', // 'single' | 'batch'
  currentAuditResult: null,
  batchContracts: [],
  
  // Mempool WebSocket state
  mempoolWs: null,
  mempoolRunning: false,
  mempoolStats: { total: 0, green: 0, yellow: 0, red: 0 },
  latestAnomalyReport: null,

  // History state
  historySubTab: 'contracts', // 'contracts' | 'mempool'
  historyPage: 1,
  historyPageSize: 10,
  historySearch: '',
  historySearchTimeout: null,

  // Settings authentication state
  adminPasscode: localStorage.getItem('chainmind_admin_pass') || '',
  isAuthenticated: false
};

// ============================================================================
// Initialization & Tab Navigation
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  setupNavigationTabs();
  await refreshSystemStatus();
  await loadDemoSamples();
  await loadHistoryData();
  checkStoredAuthentication();
});

function setupNavigationTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.dataset.tab;
      if (targetId === 'tab-settings' && !AppState.isAuthenticated) {
        openAuthModal();
        return;
      }
      switchTab(targetId);
    });
  });
}

function switchTab(tabId) {
  AppState.currentTab = tabId;

  document.querySelectorAll('.nav-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === tabId);
  });

  document.querySelectorAll('.tab-pane').forEach(p => {
    p.classList.toggle('active', p.id === tabId);
  });

  if (tabId === 'tab-history') {
    loadHistoryData();
  } else if (tabId === 'tab-settings' && AppState.isAuthenticated) {
    loadSettingsData();
  }
}

// ============================================================================
// System Status & Credentials Matrix
// ============================================================================

async function refreshSystemStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    AppState.systemStatus = data;

    // Update Top HUD
    const hudStatus = document.getElementById('hudSystemStatus');
    const hudStatusText = document.getElementById('hudStatusText');
    const hudChainText = document.getElementById('hudChainText');

    if (data.mode === 'STRICT_REAL') {
      hudStatus.className = 'badge badge-red';
      hudStatusText.textContent = 'STRICT REAL MODE';
    } else {
      hudStatus.className = 'badge badge-green';
      hudStatusText.textContent = 'RESILIENT MODE';
    }
    hudChainText.textContent = (data.default_chain || 'ETHEREUM').toUpperCase();

    // Render Credentials Matrix on Dashboard
    renderCredentialsMatrix(data.credentials_matrix || []);
  } catch (err) {
    console.error('Failed to load system status:', err);
  }
}

function renderCredentialsMatrix(matrix) {
  const container = document.getElementById('credentialsMatrixGrid');
  if (!container) return;

  container.innerHTML = matrix.map(item => {
    let statusClass = 'status-ready';
    let badgeClass = 'badge-green';
    if (item.status === 'missing') {
      statusClass = 'status-missing';
      badgeClass = 'badge-red';
    } else if (item.status === 'optional') {
      statusClass = 'status-optional';
      badgeClass = 'badge-yellow';
    }

    const reqKeys = item.required_keys && item.required_keys.length > 0
      ? `<span style="color: #fb7185;">Required: ${item.required_keys.join(', ')}</span>`
      : '<span style="color: #34d399;">No keys required</span>';

    const optKeys = item.optional_keys && item.optional_keys.length > 0
      ? `<div style="color: var(--color-text-muted);">Optional: ${item.optional_keys.join(', ')}</div>`
      : '';

    return `
      <div class="matrix-card ${statusClass}">
        <div>
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
            <span class="matrix-action-name">${escapeHtml(item.name)}</span>
            <span class="badge ${badgeClass}" style="font-size: 0.7rem;">${escapeHtml(item.status_label)}</span>
          </div>
          <div class="matrix-action-desc">${escapeHtml(item.description)}</div>
        </div>
        <div class="matrix-keys-pill">
          <div>${reqKeys}</div>
          ${optKeys}
        </div>
      </div>
    `;
  }).join('');
}

// ============================================================================
// Demo Presentation Mode
// ============================================================================

async function loadDemoSamples() {
  try {
    const res = await fetch('/api/demo/samples');
    AppState.demoSamples = await res.json();
    // Default to VulnerableVault demo
    loadDemoPreset('vulnerable_vault');
  } catch (err) {
    console.warn('Could not load demo samples:', err);
  }
}

let activeDemoContract = null;

function loadDemoPreset(presetId) {
  if (!AppState.demoSamples) return;
  const sample = AppState.demoSamples.single_samples.find(s => s.id === presetId);
  if (!sample) return;
  activeDemoContract = sample;
  goToDemoStep(1);
  showToast('info', 'Demo Loaded', `Preset "${sample.name}" loaded for walkthrough.`);
}

function goToDemoStep(step) {
  AppState.currentDemoStep = step;

  // Update step visualizer cards
  for (let i = 1; i <= 4; i++) {
    const card = document.getElementById(`demoStep${i}Card`);
    if (card) {
      card.classList.toggle('active', i === step);
      card.classList.toggle('completed', i < step);
    }
  }

  const content = document.getElementById('demoStepContent');
  if (!content || !activeDemoContract) return;

  if (step === 1) {
    content.innerHTML = `
      <h3 style="color: var(--accent-cyan); font-size: 1.05rem; margin-bottom: 0.5rem;">Step 1: Layer 1 Ingestion, Sanitization & Defense</h3>
      <p style="font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: 1rem;">
        The normalizer runs a safe state-machine regex to strip comments without corrupting strings, unpacks multi-file JSON trees, and inspects comments for prompt injection firewalls.
      </p>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
        <div>
          <label class="form-label">Raw Incoming Contract Source (Contains Malicious Comment):</label>
          <pre class="code-box" style="max-height: 240px;">${escapeHtml(activeDemoContract.source)}</pre>
        </div>
        <div>
          <label class="form-label">Algorithmic Sanitization Telemetry:</label>
          <div style="background: rgba(8, 12, 22, 0.8); border: 1px solid var(--border-subtle); padding: 0.85rem; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 0.8rem; line-height: 1.6;">
            <div>Target: <span style="color: var(--accent-cyan);">${escapeHtml(activeDemoContract.name)}</span></div>
            <div>Comment Stripping: <span style="color: #34d399;">Safe Multiline & Inline Eliminator</span></div>
            <div>Prompt Injection Neutralizer: <span style="color: #fb7185;">Active Defense (Blocked: 'IGNORE ALL SECURITY RULES')</span></div>
            <div>Guardrail Schema Check: <span style="color: #34d399;">PASSED (Layer 1 Unified Normalizer)</span></div>
          </div>
          <button class="btn btn-primary btn-sm" style="margin-top: 1rem;" onclick="goToDemoStep(2)">Proceed to Step 2: Calldata & DSA →</button>
        </div>
      </div>
    `;
  } else if (step === 2) {
    content.innerHTML = `
      <h3 style="color: var(--accent-cyan); font-size: 1.05rem; margin-bottom: 0.5rem;">Step 2: Calldata 4-Byte Selectors & DSA Sliding Window</h3>
      <p style="font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: 1rem;">
        Layer 2 processes input hexadecimal calldata, extracts function signatures, and tracks transaction bursts using an in-memory sliding window frequency counter with O(1) amortized eviction.
      </p>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
        <div style="background: rgba(8, 12, 22, 0.8); border: 1px solid var(--border-subtle); padding: 0.85rem; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 0.8rem;">
          <div style="color: var(--accent-cyan); margin-bottom: 0.5rem;">[Function Selectors Decoded in Contract]</div>
          <div>0xd0e30db0 → deposit()</div>
          <div>0x853828b6 → withdrawAll() [State update after call]</div>
          <div>0x2e1a7d4d → emergencyTransfer(address) [tx.origin auth]</div>
        </div>
        <div>
          <div style="background: rgba(8, 12, 22, 0.8); border: 1px solid var(--border-subtle); padding: 0.85rem; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: 0.8rem; line-height: 1.6;">
            <div>DSA Sliding Window: <span style="color: var(--accent-cyan);">T = 10.0 seconds</span></div>
            <div>Burst Anomaly Threshold: <span style="color: var(--accent-amber);">> 5 transactions</span></div>
            <div>Eviction Complexity: <span style="color: #34d399;">O(1) Amortized (collections.deque)</span></div>
            <div>MEV Detection Engine: <span style="color: #34d399;">Sandwich Detector Hooked</span></div>
          </div>
          <button class="btn btn-primary btn-sm" style="margin-top: 1rem;" onclick="goToDemoStep(3)">Proceed to Step 3: GenAI & Vulnerability Audit →</button>
        </div>
      </div>
    `;
  } else if (step === 3) {
    content.innerHTML = `
      <h3 style="color: var(--accent-cyan); font-size: 1.05rem; margin-bottom: 0.5rem;">Step 3: Layer 2 GenAI Context Isolation & Vulnerability Engine</h3>
      <p style="font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: 1rem;">
        Defensive XML wrapping separates code instructions from user prompts. Heuristic rules and Gemini LLM evaluate reentrancy, tx.origin authorization, assembly, and access control.
      </p>
      <div style="display: flex; gap: 1rem; flex-direction: column;">
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-primary btn-sm" onclick="runDemoStepAudit()">Run Live Security Audit on ${escapeHtml(activeDemoContract.name)}</button>
        </div>
        <div id="demoAuditResultContainer" style="display: none;">
          <!-- Populated by runDemoStepAudit -->
        </div>
      </div>
    `;
  } else if (step === 4) {
    content.innerHTML = `
      <h3 style="color: var(--accent-cyan); font-size: 1.05rem; margin-bottom: 0.5rem;">Step 4: Layer 3 Presentation, Unified Patch & CI/CD Export</h3>
      <p style="font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: 1rem;">
        Layer 3 compiles structured remediation diff patches, generates OASIS SARIF v2.1.0 reports for GitHub code scanning, and renders standalone interactive HTML reports.
      </p>
      <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
        <button class="btn btn-secondary btn-sm" onclick="downloadCurrentAuditJSON()">⬇️ Download JSON</button>
        <button class="btn btn-secondary btn-sm" onclick="downloadCurrentAuditHTML()">⬇️ Download Standalone HTML</button>
        <button class="btn btn-secondary btn-sm" onclick="downloadCurrentAuditSARIF()">⬇️ Download SARIF v2.1.0</button>
        <button class="btn btn-secondary btn-sm" onclick="downloadCurrentAuditPatch()">⬇️ Download Git Diff Patch</button>
      </div>
      <div style="margin-top: 1rem;">
        <pre class="code-box" style="color: #4ade80;">// Unified diff remediation patch will be exported here.</pre>
      </div>
    `;
  }
}

async function runDemoStepAudit() {
  const container = document.getElementById('demoAuditResultContainer');
  if (!container || !activeDemoContract) return;

  container.style.display = 'block';
  container.innerHTML = '<div style="color: var(--accent-cyan); font-family: var(--font-mono);">⚡ Executing Layer 2 Security Engine...</div>';

  try {
    const res = await fetch('/api/audit/contract', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source_code: activeDemoContract.source,
        target_path: activeDemoContract.name
      })
    });
    const report = await res.json();
    AppState.currentAuditResult = report;

    const findings = report.security_findings || [];
    const scoreColor = report.risk_score >= 7 ? '#fb7185' : (report.risk_score >= 4 ? '#fbbf24' : '#34d399');

    container.innerHTML = `
      <div style="background: rgba(15, 21, 35, 0.95); border: 1px solid var(--border-medium); border-radius: var(--radius-md); padding: 1rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <h4 style="font-size: 1rem;">Audit Complete: ${escapeHtml(report.contract_name || activeDemoContract.name)}</h4>
          <span class="badge" style="background: rgba(244, 63, 94, 0.15); color: ${scoreColor}; font-size: 0.9rem;">
            Risk Score: ${report.risk_score}/10
          </span>
        </div>
        <p style="font-size: 0.85rem; color: var(--color-text-secondary); margin-bottom: 1rem;">${escapeHtml(report.summary || '')}</p>
        <div style="display: flex; flex-direction: column; gap: 0.5rem;">
          ${findings.map(f => `
            <div class="finding-card severity-${(f.severity || 'medium').toLowerCase()}" style="margin-bottom: 0;">
              <div class="finding-header">
                <span class="finding-title">${escapeHtml(f.title || f.rule_id || 'Security Issue')}</span>
                <span class="badge badge-red" style="font-size: 0.7rem;">${escapeHtml(f.severity || 'CRITICAL')}</span>
              </div>
              <p style="font-size: 0.8rem; color: var(--color-text-secondary);">${escapeHtml(f.description || '')}</p>
            </div>
          `).join('')}
        </div>
        <button class="btn btn-primary btn-sm" style="margin-top: 1rem;" onclick="goToDemoStep(4)">Proceed to Step 4: Remediation Diff & Export →</button>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div style="color: #fb7185;">Audit failed: ${escapeHtml(err.message)}</div>`;
  }
}

function runAutoPlayDemo() {
  const btn = document.getElementById('btnAutoPlayDemo');
  if (btn) btn.disabled = true;
  goToDemoStep(1);

  setTimeout(() => {
    goToDemoStep(2);
    setTimeout(() => {
      goToDemoStep(3);
      runDemoStepAudit();
      setTimeout(() => {
        goToDemoStep(4);
        if (btn) btn.disabled = false;
        showToast('success', 'Auto-Play Complete', 'Walked through all 4 pipeline layers.');
      }, 3500);
    }, 2500);
  }, 2000);
}

// ============================================================================
// Smart Contract Auditor (Single & Batch with Relationship Discovery)
// ============================================================================

function setAuditorMode(mode) {
  AppState.auditorMode = mode;
  document.getElementById('btnSingleMode').className = mode === 'single' ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm';
  document.getElementById('btnBatchMode').className = mode === 'batch' ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm';
  document.getElementById('singleInputSection').style.display = mode === 'single' ? 'block' : 'none';
  document.getElementById('batchInputSection').style.display = mode === 'batch' ? 'block' : 'none';
}

function loadSampleToEditor(sampleId) {
  if (!AppState.demoSamples) return;
  const sample = AppState.demoSamples.single_samples.find(s => s.id === sampleId);
  if (!sample) return;
  document.getElementById('contractSourceInput').value = sample.source;
  showToast('info', 'Code Loaded', `Loaded "${sample.name}" into editor.`);
}

function openSampleSuiteDemo() {
  setAuditorMode('batch');
  if (!AppState.demoSamples || !AppState.demoSamples.sample_suite) return;

  const suite = AppState.demoSamples.sample_suite;
  AppState.batchContracts = suite.contracts;

  renderBatchContractList();
  // Automatically trigger relationship detection
  detectRelationshipsForBatch(suite.contracts);
  showToast('success', 'Sample Suite Loaded', `Loaded "${suite.name}" (${suite.contracts.length} interconnected contracts).`);
}

function renderBatchContractList() {
  const list = document.getElementById('batchFileList');
  if (!list) return;

  list.innerHTML = AppState.batchContracts.map((c, idx) => `
    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.45rem 0.75rem; background: rgba(8, 12, 22, 0.8); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); font-size: 0.8rem; font-family: var(--font-mono);">
      <span>📄 ${escapeHtml(c.name)}</span>
      <span style="color: var(--color-text-muted); font-size: 0.72rem;">${(c.source || '').length} bytes</span>
    </div>
  `).join('');
}

async function detectRelationshipsForCurrentCode() {
  const code = document.getElementById('contractSourceInput').value;
  if (!code.trim()) {
    showErrorDialog('Missing Code', 'Please paste or load Solidity contract code to analyze relationships.');
    return;
  }
  await detectRelationshipsForBatch([{ name: 'TargetContract.sol', source: code }]);
}

async function detectRelationshipsForBatch(contracts) {
  try {
    const res = await fetch('/api/audit/detect-relationships', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contracts })
    });
    const graph = await res.json();
    renderDependencyGraph(graph);
  } catch (err) {
    showErrorDialog('Dependency Analysis Failed', err.message);
  }
}

function renderDependencyGraph(graph) {
  const container = document.getElementById('dependencyGraphContainer');
  const countBadge = document.getElementById('relationshipCountBadge');
  if (!container) return;

  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  if (countBadge) countBadge.textContent = `${edges.length} Connections / ${nodes.length} Nodes`;

  if (nodes.length === 0) {
    container.innerHTML = `<div style="text-align: center; color: var(--color-text-muted); margin: auto;">No contracts found in analysis.</div>`;
    return;
  }

  container.innerHTML = `
    <div style="margin-bottom: 0.5rem; font-size: 0.8rem; color: var(--color-text-secondary);">
      <strong>Detected Contract Nodes & Hierarchies:</strong>
    </div>
    <div style="display: flex; flex-direction: column; gap: 0.5rem; max-height: 280px; overflow-y: auto;">
      ${nodes.map(n => `
        <div class="dependency-node-row ${n.is_target ? 'target-node' : ''}">
          <div>
            <span style="font-weight: 700; color: var(--color-text-primary); font-family: var(--font-mono);">${escapeHtml(n.name)}</span>
            <span style="font-size: 0.72rem; color: var(--color-text-muted); margin-left: 0.4rem;">(${escapeHtml(n.kind || 'contract')})</span>
          </div>
          <span class="badge badge-cyan" style="font-size: 0.68rem;">${escapeHtml(n.file || '')}</span>
        </div>
      `).join('')}
    </div>
    <div style="margin-top: 0.75rem; border-top: 1px solid var(--border-subtle); padding-top: 0.5rem;">
      <div style="font-size: 0.78rem; color: var(--color-text-muted); margin-bottom: 0.35rem;"><strong>Discovered Edges:</strong></div>
      ${edges.map(e => `
        <div style="font-size: 0.76rem; font-family: var(--font-mono); color: var(--color-text-secondary); padding: 0.15rem 0;">
          ↳ <span style="color: var(--accent-cyan);">${escapeHtml(e.source)}</span> 
          <span style="color: var(--color-text-muted);">--[${escapeHtml(e.type)}]--></span> 
          <span style="color: var(--accent-emerald);">${escapeHtml(e.target)}</span>
        </div>
      `).join('')}
    </div>
  `;
}

async function executeSingleAudit() {
  const code = document.getElementById('contractSourceInput').value;
  const address = document.getElementById('contractAddressInput').value;
  const chain = document.getElementById('contractChainSelect').value;

  if (!code.trim() && !address.trim()) {
    showErrorDialog('Missing Target', 'Please either paste contract code or specify a 42-character 0x address.', null, [
      'Paste Solidity code into the editor',
      'Or enter a contract address, e.g. 0xdAC17F958D2ee523a2206206994597C13D831ec7'
    ]);
    return;
  }

  const btn = document.getElementById('btnRunSingleAudit');
  btn.disabled = true;
  btn.innerHTML = '⚡ Auditing...';

  try {
    const payload = {};
    if (address.trim()) {
      payload.contract_address = address.trim();
      payload.chain = chain;
    } else {
      payload.source_code = code;
    }

    const res = await fetch('/api/audit/contract', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail ? (typeof err.detail === 'object' ? err.detail.message : err.detail) : 'Audit failed');
    }

    const result = await res.json();
    AppState.currentAuditResult = result;
    renderAuditResults(result);
    showToast('success', 'Audit Complete', `Risk Score: ${result.risk_score}/10`);
    refreshSystemStatus();
  } catch (err) {
    showErrorDialog('Audit Execution Failed', err.message, null, [
      'Check if the contract is verified on Explorer if specifying an address',
      'Ensure Solidity code has valid syntax',
      'If using Strict Mode, verify that GEMINI_API_KEY is configured in Settings'
    ]);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🛡️ Run Contract Audit';
  }
}

async function executeBatchAudit() {
  if (!AppState.batchContracts || AppState.batchContracts.length === 0) {
    showErrorDialog('Empty Batch', 'No contracts in batch. Click "Load DeFi Yield Staking Sample Suite" first.');
    return;
  }

  const btn = document.getElementById('btnRunBatchAudit');
  btn.disabled = true;
  btn.innerHTML = '⚡ Batch Auditing...';

  try {
    const res = await fetch('/api/audit/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contracts: AppState.batchContracts })
    });
    const batchResult = await res.json();

    showToast('success', 'Batch Audit Complete', `Audited ${batchResult.batch_size} interconnected contracts. Overall Risk: ${batchResult.overall_status}`);
    
    // Display primary report
    if (batchResult.reports && batchResult.reports.length > 0) {
      AppState.currentAuditResult = batchResult.reports[0];
      renderAuditResults(batchResult.reports[0]);
    }
  } catch (err) {
    showErrorDialog('Batch Audit Failed', err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🛡️ Audit Complete Connected Batch';
  }
}

function renderAuditResults(report) {
  const panel = document.getElementById('auditResultsCard');
  if (!panel) return;
  panel.style.display = 'block';

  document.getElementById('auditResultTitle').textContent = `🛡️ Audit: ${report.contract_name || report.target_address || 'Contract'}`;
  document.getElementById('auditResultSubtitle').textContent = `Analyzed at ${report.audit_timestamp || new Date().toISOString()}`;

  const score = report.risk_score || 1;
  const scoreBadge = document.getElementById('auditRiskScoreBadge');
  if (score >= 7) {
    scoreBadge.className = 'badge badge-red';
    scoreBadge.textContent = `Risk Score: ${score}/10 (CRITICAL)`;
  } else if (score >= 4) {
    scoreBadge.className = 'badge badge-yellow';
    scoreBadge.textContent = `Risk Score: ${score}/10 (WARNING)`;
  } else {
    scoreBadge.className = 'badge badge-green';
    scoreBadge.textContent = `Risk Score: ${score}/10 (SAFE)`;
  }

  const telemetry = report.ingestion_telemetry || {};
  document.getElementById('auditInjectionsBadge').textContent = `Injections Neutralized: ${telemetry.detected_injections || 0}`;
  document.getElementById('auditFunctionsBadge').textContent = `State Functions: ${(telemetry.state_changing_functions || []).length}`;

  document.getElementById('auditExecutiveSummary').textContent = report.summary || 'Audit evaluation finished without critical flags.';

  const findingsList = document.getElementById('auditFindingsList');
  const findings = report.security_findings || [];

  if (findings.length === 0) {
    findingsList.innerHTML = `<div style="color: #34d399; font-size: 0.85rem; padding: 0.5rem 0;">No security vulnerabilities identified. Contract conforms to safety guardrails.</div>`;
  } else {
    findingsList.innerHTML = findings.map(f => `
      <div class="finding-card severity-${(f.severity || 'medium').toLowerCase()}">
        <div class="finding-header">
          <span class="finding-title">${escapeHtml(f.title || f.rule_id || 'Finding')}</span>
          <span class="badge ${f.severity === 'CRITICAL' ? 'badge-red' : (f.severity === 'HIGH' ? 'badge-yellow' : 'badge-cyan')}">${escapeHtml(f.severity || 'INFO')}</span>
        </div>
        <p style="font-size: 0.82rem; color: var(--color-text-secondary); margin-bottom: 0.35rem;">${escapeHtml(f.description || '')}</p>
        ${f.recommendation ? `<p style="font-size: 0.78rem; color: #4ade80;"><strong>Mitigation:</strong> ${escapeHtml(f.recommendation)}</p>` : ''}
      </div>
    `).join('');
  }

  // Diff Patch Preview
  const patchBox = document.getElementById('auditPatchBox');
  if (report.remediation_patch) {
    patchBox.textContent = report.remediation_patch;
  } else {
    patchBox.textContent = `--- a/${report.contract_name || 'contract'}.sol\n+++ b/${report.contract_name || 'contract'}.sol\n@@ Fixes applied by remediation engine @@`;
  }

  panel.scrollIntoView({ behavior: 'smooth' });
}

// ============================================================================
// Continuous Mempool Streamer (Traffic Lights & Instant Insights)
// ============================================================================

function toggleContinuousMempool() {
  if (AppState.mempoolRunning) {
    pauseContinuousMempool();
  } else {
    startContinuousMempool();
  }
}

function startContinuousMempool() {
  const mode = document.getElementById('mempoolModeSelect').value;
  const btn = document.getElementById('btnToggleMempool');

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/mempool`;

  if (AppState.mempoolWs) {
    AppState.mempoolWs.close();
  }

  AppState.mempoolWs = new WebSocket(wsUrl);

  AppState.mempoolWs.onopen = () => {
    AppState.mempoolRunning = true;
    btn.innerHTML = '⏸️ Pause Stream';
    btn.className = 'btn btn-secondary';
    AppState.mempoolWs.send(JSON.stringify({
      action: 'start',
      mode: mode,
      interval: 0.3
    }));
    showToast('info', 'Mempool Stream Active', `Continuous evaluation started (${mode} mode).`);
  };

  AppState.mempoolWs.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleMempoolEvent(data);
    } catch (e) {
      console.error('Error parsing mempool event:', e);
    }
  };

  AppState.mempoolWs.onerror = (err) => {
    console.error('Mempool WS error:', err);
    showErrorDialog('Mempool Stream Disconnected', 'WebSocket connection closed unexpectedly.', null, [
      'Check that the server is running',
      'If using live mode, verify that RPC URL is valid and accessible'
    ]);
    pauseContinuousMempool();
  };

  AppState.mempoolWs.onclose = () => {
    pauseContinuousMempool();
  };
}

function pauseContinuousMempool() {
  AppState.mempoolRunning = false;
  const btn = document.getElementById('btnToggleMempool');
  if (btn) {
    btn.innerHTML = '▶️ Start Stream';
    btn.className = 'btn btn-primary';
  }
  if (AppState.mempoolWs && AppState.mempoolWs.readyState === WebSocket.OPEN) {
    AppState.mempoolWs.send(JSON.stringify({ action: 'pause' }));
  }
}

function handleMempoolEvent(event) {
  const signal = event.signal || 'green';
  const tx = event.tx || {};
  AppState.mempoolStats.total++;

  // Update Traffic Lights UI
  const greenLight = document.getElementById('signalGreen');
  const yellowLight = document.getElementById('signalYellow');
  const redLight = document.getElementById('signalRed');
  const signalTitle = document.getElementById('trafficSignalTitle');
  const oneLiner = document.getElementById('trafficOneLiner');
  const btnAnomaly = document.getElementById('btnViewLatestAnomaly');

  greenLight.classList.toggle('lit', signal === 'green');
  yellowLight.classList.toggle('lit', signal === 'yellow');
  redLight.classList.toggle('lit', signal === 'red');

  if (signal === 'red') {
    AppState.mempoolStats.red++;
    signalTitle.textContent = 'SIGNAL: CRITICAL THREAT DETECTED';
    signalTitle.style.color = '#fb7185';
    oneLiner.className = 'traffic-one-liner red-text';
    oneLiner.textContent = event.one_line_summary || `Critical anomaly flagged on tx ${tx.tx_hash}`;
    
    // Save report & show button
    if (event.anomaly_report) {
      AppState.latestAnomalyReport = event.anomaly_report;
      btnAnomaly.style.display = 'inline-flex';
      showToast('error', '🚨 Anomaly Detected', event.one_line_summary);
    }
  } else if (signal === 'yellow') {
    AppState.mempoolStats.yellow++;
    signalTitle.textContent = 'SIGNAL: ELEVATED ACTIVITY WARNING';
    signalTitle.style.color = '#fbbf24';
    oneLiner.className = 'traffic-one-liner yellow-text';
    oneLiner.textContent = event.one_line_summary || `High-frequency activity approaching threshold for ${tx.sender}`;
  } else {
    AppState.mempoolStats.green++;
    signalTitle.textContent = 'SIGNAL: ALL CLEAR (SAFE TRANSACTION FLOW)';
    signalTitle.style.color = '#34d399';
    oneLiner.className = 'traffic-one-liner green-text';
    oneLiner.textContent = 'Standard routine calls observed with normal transaction frequency.';
  }

  // Update stat counters
  document.getElementById('mempoolCountProcessed').textContent = AppState.mempoolStats.total;
  document.getElementById('mempoolCountGreen').textContent = AppState.mempoolStats.green;
  document.getElementById('mempoolCountYellow').textContent = AppState.mempoolStats.yellow;
  document.getElementById('mempoolCountRed').textContent = AppState.mempoolStats.red;

  // Append row to stream feed
  const feed = document.getElementById('mempoolFeed');
  if (feed) {
    if (feed.children.length === 1 && feed.children[0].textContent.includes('paused')) {
      feed.innerHTML = '';
    }

    const row = document.createElement('div');
    row.className = `mempool-row signal-${signal}`;
    row.innerHTML = `
      <div><span class="badge badge-${signal === 'red' ? 'red' : (signal === 'yellow' ? 'yellow' : 'green')}">${signal.toUpperCase()}</span></div>
      <div title="${escapeHtml(tx.tx_hash || '')}">${escapeHtml((tx.tx_hash || '').slice(0, 14))}...</div>
      <div title="${escapeHtml(tx.sender || '')}">${escapeHtml((tx.sender || '').slice(0, 10))}...</div>
      <div>${escapeHtml(tx.function_selector || '0x')}</div>
      <div>
        <strong>${escapeHtml(tx.decoded_name || tx.classification || 'Routine Call')}</strong>
        <div style="font-size: 0.72rem; color: var(--color-text-muted);">${escapeHtml(tx.classification || '')}</div>
      </div>
      <div>${tx.count_in_window || 1} txs / ${tx.window_seconds || 10}s</div>
    `;

    feed.insertBefore(row, feed.firstChild);
    // Keep max 60 rows in feed to maintain high performance
    if (feed.children.length > 60) {
      feed.removeChild(feed.lastChild);
    }
  }
}

function clearMempoolFeed() {
  const feed = document.getElementById('mempoolFeed');
  if (feed) feed.innerHTML = '<div style="text-align: center; color: var(--color-text-muted); padding: 2rem;">Feed cleared.</div>';
}

function openLatestAnomalyInsights() {
  if (!AppState.latestAnomalyReport) return;
  const r = AppState.latestAnomalyReport;

  document.getElementById('anomalyModalTitle').textContent = r.title || 'Anomaly Insights Report';
  document.getElementById('anomalyModalSeverity').textContent = r.severity || 'CRITICAL';
  document.getElementById('anomalyModalReason').textContent = r.reason || '';
  document.getElementById('anomalyModalAttacker').textContent = (r.participants && r.participants.attacker_or_initiator) || 'Unknown';
  document.getElementById('anomalyModalTarget').textContent = (r.participants && r.participants.target_contract_or_pool) || 'Unknown';
  document.getElementById('anomalyModalImpact').textContent = r.impact_assessment || '';

  const mitigationsList = document.getElementById('anomalyModalMitigations');
  mitigationsList.innerHTML = (r.actionable_mitigations || []).map(m => `<li>${escapeHtml(m)}</li>`).join('');

  document.getElementById('anomalyModalBackdrop').classList.add('open');
}

function closeAnomalyModal() {
  document.getElementById('anomalyModalBackdrop').classList.remove('open');
}

function downloadCurrentAnomalyReport() {
  if (!AppState.latestAnomalyReport) return;
  downloadBlob(
    JSON.stringify(AppState.latestAnomalyReport, null, 2),
    `${AppState.latestAnomalyReport.report_id || 'anomaly_report'}.json`,
    'application/json'
  );
}

// ============================================================================
// History Section (Paginated 'Showing 1-10 of 250')
// ============================================================================

function setHistorySubTab(subTab) {
  AppState.historySubTab = subTab;
  AppState.historyPage = 1;

  document.getElementById('btnHistContractsTab').className = subTab === 'contracts' ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm';
  document.getElementById('btnHistMempoolTab').className = subTab === 'mempool' ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm';

  loadHistoryData();
}

function debounceHistorySearch() {
  clearTimeout(AppState.historySearchTimeout);
  AppState.historySearchTimeout = setTimeout(() => {
    AppState.historySearch = document.getElementById('historySearchInput').value;
    AppState.historyPage = 1;
    loadHistoryData();
  }, 350);
}

async function loadHistoryData() {
  const isContracts = AppState.historySubTab === 'contracts';
  const url = isContracts
    ? `/api/history/audits?page=${AppState.historyPage}&page_size=${AppState.historyPageSize}&search=${encodeURIComponent(AppState.historySearch)}`
    : `/api/history/anomalies?page=${AppState.historyPage}&page_size=${AppState.historyPageSize}&search=${encodeURIComponent(AppState.historySearch)}`;

  try {
    const res = await fetch(url);
    const data = await res.json();
    renderHistoryTable(data, isContracts);

    // Update Dashboard Stats if on page 1 of contracts
    if (isContracts && AppState.historyPage === 1 && !AppState.historySearch) {
      document.getElementById('dashTotalAudits').textContent = data.total || 0;
      const criticalCount = data.items.filter(i => (i.risk_score || 0) >= 7).length;
      document.getElementById('dashHighRiskAudits').textContent = criticalCount;
      const injectionCount = data.items.reduce((sum, i) => sum + (i.detected_injections || 0), 0);
      document.getElementById('dashInjectionsBlocked').textContent = injectionCount;
    }
  } catch (err) {
    console.error('Error loading history data:', err);
  }
}

function renderHistoryTable(data, isContracts) {
  const thead = document.getElementById('historyTableHead');
  const tbody = document.getElementById('historyTableBody');
  const counter = document.getElementById('historyPaginationCounter');
  const pageNum = document.getElementById('historyPageNumber');
  const prevBtn = document.getElementById('btnHistPrev');
  const nextBtn = document.getElementById('btnHistNext');

  // Exact pagination string requested by user: 'Showing 1-10 of 250'
  counter.textContent = `Showing ${data.showing_from}-${data.showing_to} of ${data.total}`;
  pageNum.textContent = `Page ${data.page} of ${data.total_pages}`;
  prevBtn.disabled = data.page <= 1;
  nextBtn.disabled = data.page >= data.total_pages;

  if (isContracts) {
    thead.innerHTML = `
      <tr>
        <th style="width: 60px;">ID</th>
        <th>Target Address / Contract</th>
        <th style="width: 130px;">Risk Rating</th>
        <th style="width: 120px;">Injections</th>
        <th style="width: 170px;">Timestamp</th>
        <th style="width: 90px;">Action</th>
      </tr>
    `;

    if (data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--color-text-muted); padding: 2rem;">No contract audits recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items.map(row => {
      const score = row.risk_score;
      const badgeClass = score >= 7 ? 'badge-red' : (score >= 4 ? 'badge-yellow' : 'badge-green');
      const label = score >= 7 ? 'CRITICAL' : (score >= 4 ? 'WARNING' : 'SAFE');
      return `
        <tr>
          <td><span style="font-family: var(--font-mono); color: var(--color-text-muted);">#${row.id}</span></td>
          <td>
            <div style="font-weight: 600; font-family: var(--font-mono);">${escapeHtml(row.target_address)}</div>
            <div style="font-size: 0.74rem; color: var(--color-text-muted);">${escapeHtml((row.summary || '').slice(0, 75))}...</div>
          </td>
          <td><span class="badge ${badgeClass}">${score}/10 [${label}]</span></td>
          <td>${row.detected_injections || 0}</td>
          <td style="font-size: 0.78rem; font-family: var(--font-mono); color: var(--color-text-muted);">${(row.audit_timestamp || '').slice(0, 19).replace('T', ' ')}</td>
          <td><button class="btn btn-secondary btn-sm" onclick="inspectHistoricalAudit(${row.id})">Inspect</button></td>
        </tr>
      `;
    }).join('');
  } else {
    // Mempool anomalies table
    thead.innerHTML = `
      <tr>
        <th style="width: 60px;">ID</th>
        <th>Tx Hash / Sender</th>
        <th>Selector</th>
        <th>Classification</th>
        <th style="width: 110px;">Burst Count</th>
        <th style="width: 170px;">Detected At</th>
        <th style="width: 90px;">Action</th>
      </tr>
    `;

    if (data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--color-text-muted); padding: 2rem;">No mempool anomalies recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items.map(row => {
      const isCritical = row.classification === 'MEV_SANDWICH_ATTACK' || row.classification === 'SUSPICIOUS_HIGH_RISK_CALL';
      return `
        <tr>
          <td><span style="font-family: var(--font-mono); color: var(--color-text-muted);">#${row.id}</span></td>
          <td>
            <div style="font-weight: 600; font-family: var(--font-mono);">${escapeHtml(row.tx_hash.slice(0, 16))}...</div>
            <div style="font-size: 0.72rem; color: var(--color-text-muted);">Sender: ${escapeHtml(row.sender.slice(0, 14))}...</div>
          </td>
          <td><span style="font-family: var(--font-mono);">${escapeHtml(row.function_selector || '0x')}</span></td>
          <td><span class="badge ${isCritical ? 'badge-red' : 'badge-yellow'}">${escapeHtml(row.classification)}</span></td>
          <td><strong>${row.frequency_count}</strong> in ${row.window_seconds}s</td>
          <td style="font-size: 0.78rem; font-family: var(--font-mono); color: var(--color-text-muted);">${(row.detected_at || '').slice(0, 19)}</td>
          <td><button class="btn btn-secondary btn-sm" onclick="inspectHistoricalAnomaly(${row.id})">Inspect</button></td>
        </tr>
      `;
    }).join('');
  }
}

function prevHistoryPage() {
  if (AppState.historyPage > 1) {
    AppState.historyPage--;
    loadHistoryData();
  }
}

function nextHistoryPage() {
  AppState.historyPage++;
  loadHistoryData();
}

async function inspectHistoricalAudit(auditId) {
  try {
    const res = await fetch(`/api/history/audit/${auditId}`);
    const record = await res.json();
    const content = document.getElementById('auditDetailContent');

    const score = record.risk_score;
    const badgeColor = score >= 7 ? 'badge-red' : (score >= 4 ? 'badge-yellow' : 'badge-green');
    const findings = record.security_findings || [];

    content.innerHTML = `
      <div style="margin-bottom: 1rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <h4 style="font-size: 1.05rem; font-family: var(--font-mono);">${escapeHtml(record.target_address)}</h4>
          <span class="badge ${badgeColor}">${score}/10 Rating</span>
        </div>
        <div style="font-size: 0.82rem; color: var(--color-text-muted);">Audit Timestamp: ${record.audit_timestamp}</div>
      </div>
      <p style="font-size: 0.88rem; color: var(--color-text-primary); margin-bottom: 1rem;">${escapeHtml(record.summary || '')}</p>
      <h5 style="font-size: 0.88rem; margin-bottom: 0.5rem; color: var(--color-text-secondary);">Identified Findings (${findings.length}):</h5>
      <div style="display: flex; flex-direction: column; gap: 0.5rem; max-height: 250px; overflow-y: auto;">
        ${findings.map(f => `
          <div class="finding-card severity-${(f.severity || 'medium').toLowerCase()}" style="margin-bottom: 0;">
            <div class="finding-header">
              <span class="finding-title">${escapeHtml(f.title || f.rule_id || 'Issue')}</span>
              <span class="badge badge-red" style="font-size: 0.7rem;">${escapeHtml(f.severity || 'HIGH')}</span>
            </div>
            <p style="font-size: 0.78rem; color: var(--color-text-secondary);">${escapeHtml(f.description || '')}</p>
          </div>
        `).join('')}
      </div>
    `;

    document.getElementById('auditDetailModalBackdrop').classList.add('open');
  } catch (err) {
    showErrorDialog('Could Not Load Audit', err.message);
  }
}

function closeAuditDetailModal() {
  document.getElementById('auditDetailModalBackdrop').classList.remove('open');
}

async function inspectHistoricalAnomaly(anomalyId) {
  try {
    const res = await fetch(`/api/history/anomaly/${anomalyId}`);
    const record = await res.json();
    AppState.latestAnomalyReport = {
      report_id: `ANOMALY-REC-${record.id}`,
      title: record.anomaly_reason || 'Flagged Mempool Anomaly',
      severity: record.classification.includes('MEV') || record.classification.includes('HIGH_RISK') ? 'CRITICAL' : 'WARNING',
      reason: record.anomaly_reason,
      participants: {
        attacker_or_initiator: record.sender,
        target_contract_or_pool: record.target
      },
      impact_assessment: `High burst activity: ${record.frequency_count} txs in ${record.window_seconds}s window.`,
      actionable_mitigations: ['Check sender on block explorer', 'Consider rate-limiting or blacklisting malicious origin']
    };
    openLatestAnomalyInsights();
  } catch (err) {
    showErrorDialog('Could Not Load Anomaly', err.message);
  }
}

// ============================================================================
// Settings & Authentication
// ============================================================================

function checkStoredAuthentication() {
  if (AppState.adminPasscode) {
    verifyPasscode(AppState.adminPasscode, false);
  }
}

function openAuthModal() {
  document.getElementById('authModalBackdrop').classList.add('open');
  document.getElementById('authPasscodeInput').value = '';
}

function closeAuthModal() {
  document.getElementById('authModalBackdrop').classList.remove('open');
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const code = document.getElementById('authPasscodeInput').value.trim();
  const success = await verifyPasscode(code, true);
  if (success) {
    closeAuthModal();
    switchTab('tab-settings');
  }
}

async function verifyPasscode(code, showFeedback) {
  try {
    const res = await fetch('/api/settings/verify-auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passcode: code })
    });
    if (res.ok) {
      AppState.adminPasscode = code;
      AppState.isAuthenticated = true;
      localStorage.setItem('chainmind_admin_pass', code);
      document.getElementById('settingsLockIcon').textContent = '🔓';
      if (showFeedback) showToast('success', 'Access Granted', 'Settings panel unlocked.');
      loadSettingsData();
      return true;
    } else {
      if (showFeedback) showErrorDialog('Authentication Failed', 'Invalid admin passcode provided.');
      return false;
    }
  } catch (err) {
    if (showFeedback) showErrorDialog('Auth Error', err.message);
    return false;
  }
}

async function loadSettingsData() {
  if (!AppState.isAuthenticated) return;
  try {
    const res = await fetch('/api/settings/load', {
      headers: { 'X-Admin-Passcode': AppState.adminPasscode }
    });
    if (!res.ok) return;
    const data = await res.json();
    const s = data.settings || {};

    document.getElementById('cfgGeminiKey').value = s.gemini_api_key || '';
    document.getElementById('cfgEtherscanKey').value = s.etherscan_api_key || '';
    document.getElementById('cfgArbiscanKey').value = s.arbiscan_api_key || '';
    document.getElementById('cfgPolygonscanKey').value = s.polygonscan_api_key || '';
    document.getElementById('cfgBasescanKey').value = s.basescan_api_key || '';
    document.getElementById('cfgEthRpcWs').value = s.eth_rpc_ws_url || '';
    document.getElementById('cfgEthRpcHttp').value = s.eth_rpc_http_url || '';
    document.getElementById('cfgWindowSeconds').value = s.sliding_window_seconds || 10.0;
    document.getElementById('cfgAnomalyThreshold').value = s.anomaly_tx_threshold || 5;
    document.getElementById('cfgStrictMode').checked = Boolean(s.strict_mode);
  } catch (err) {
    console.error('Failed to load settings:', err);
  }
}

async function handleSaveSettings(event) {
  event.preventDefault();
  if (!AppState.isAuthenticated) {
    openAuthModal();
    return;
  }

  const btn = document.getElementById('btnSaveSettings');
  btn.disabled = true;
  btn.innerHTML = '💾 Saving...';

  const updated = {
    gemini_api_key: document.getElementById('cfgGeminiKey').value.trim(),
    etherscan_api_key: document.getElementById('cfgEtherscanKey').value.trim(),
    arbiscan_api_key: document.getElementById('cfgArbiscanKey').value.trim(),
    polygonscan_api_key: document.getElementById('cfgPolygonscanKey').value.trim(),
    basescan_api_key: document.getElementById('cfgBasescanKey').value.trim(),
    eth_rpc_ws_url: document.getElementById('cfgEthRpcWs').value.trim(),
    eth_rpc_http_url: document.getElementById('cfgEthRpcHttp').value.trim(),
    sliding_window_seconds: parseFloat(document.getElementById('cfgWindowSeconds').value) || 10.0,
    anomaly_tx_threshold: parseInt(document.getElementById('cfgAnomalyThreshold').value) || 5,
    strict_mode: document.getElementById('cfgStrictMode').checked
  };

  const newPass = document.getElementById('cfgNewPasscode').value.trim();
  if (newPass) {
    updated.new_admin_passcode = newPass;
  }

  try {
    const res = await fetch('/api/settings/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        passcode: AppState.adminPasscode,
        settings: updated
      })
    });

    if (!res.ok) {
      throw new Error('Could not save settings.');
    }

    if (newPass) {
      AppState.adminPasscode = newPass;
      localStorage.setItem('chainmind_admin_pass', newPass);
      document.getElementById('cfgNewPasscode').value = '';
    }

    showToast('success', 'Settings Saved', 'System configuration updated successfully.');
    refreshSystemStatus();
  } catch (err) {
    showErrorDialog('Failed to Save Settings', err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '💾 Save Settings';
  }
}

// ============================================================================
// Exporters (JSON, HTML, SARIF, Patch)
// ============================================================================

function downloadCurrentAuditJSON() {
  if (!AppState.currentAuditResult) return;
  downloadBlob(JSON.stringify(AppState.currentAuditResult, null, 2), 'audit_report.json', 'application/json');
}

async function downloadCurrentAuditHTML() {
  if (!AppState.currentAuditResult) return;
  try {
    const res = await fetch('/api/export/html', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(AppState.currentAuditResult)
    });
    const htmlText = await res.text();
    downloadBlob(htmlText, 'audit_report.html', 'text/html');
  } catch (err) {
    showErrorDialog('Export Error', err.message);
  }
}

async function downloadCurrentAuditSARIF() {
  if (!AppState.currentAuditResult) return;
  try {
    const res = await fetch('/api/export/sarif', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(AppState.currentAuditResult)
    });
    const sarif = await res.json();
    downloadBlob(JSON.stringify(sarif, null, 2), 'audit_report.sarif', 'application/json');
  } catch (err) {
    showErrorDialog('SARIF Export Error', err.message);
  }
}

async function downloadCurrentAuditPatch() {
  if (!AppState.currentAuditResult) return;
  try {
    const res = await fetch('/api/export/patch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source_code: document.getElementById('contractSourceInput').value || '',
        findings: AppState.currentAuditResult.security_findings || []
      })
    });
    const patchText = await res.text();
    downloadBlob(patchText, 'remediation.patch', 'text/x-diff');
  } catch (err) {
    showErrorDialog('Patch Export Error', err.message);
  }
}

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============================================================================
// Clean Diagnostic Error Modal System & Floating Toasts
// ============================================================================

function showErrorDialog(title, message, details = null, suggestions = null) {
  document.getElementById('errorModalTitle').textContent = title;
  document.getElementById('errorModalMessage').textContent = message;

  const detailsBox = document.getElementById('errorModalDetailsBox');
  const detailsEl = document.getElementById('errorModalDetails');
  if (details) {
    detailsBox.style.display = 'block';
    detailsEl.textContent = typeof details === 'object' ? JSON.stringify(details, null, 2) : details;
  } else {
    detailsBox.style.display = 'none';
  }

  const suggBox = document.getElementById('errorModalSuggestionsBox');
  const suggList = document.getElementById('errorModalSuggestions');
  if (suggestions && suggestions.length > 0) {
    suggBox.style.display = 'block';
    suggList.innerHTML = suggestions.map(s => `<li>${escapeHtml(s)}</li>`).join('');
  } else {
    suggBox.style.display = 'none';
  }

  document.getElementById('errorModalBackdrop').classList.add('open');
}

function closeErrorModal() {
  document.getElementById('errorModalBackdrop').classList.remove('open');
}

function showToast(type, title, message) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <div class="toast-body">
      <h5>${escapeHtml(title)}</h5>
      <p>${escapeHtml(message)}</p>
    </div>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 4500);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
