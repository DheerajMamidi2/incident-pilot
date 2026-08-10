'use strict';

const appState = {
  scenarios: [],
  incident: null,
  busy: false,
};

const stateOrder = ['DETECTED', 'TRIAGING', 'AWAITING_APPROVAL', 'EXECUTING', 'VERIFYING', 'RESOLVED'];
const stateLabels = ['Detect', 'Triage + gate', 'Human approval', 'Typed action', 'Verify'];

const elements = {
  scenarioGrid: document.querySelector('#scenario-grid'),
  workspace: document.querySelector('#workspace'),
  workspaceTitle: document.querySelector('#workspace-title'),
  incidentID: document.querySelector('#incident-id'),
  stateBadge: document.querySelector('#state-badge'),
  stateRail: document.querySelector('#state-rail'),
  sloComparison: document.querySelector('#slo-comparison'),
  freshBadge: document.querySelector('#fresh-badge'),
  evidenceList: document.querySelector('#evidence-list'),
  evidenceCount: document.querySelector('#evidence-count'),
  confidence: document.querySelector('#confidence'),
  triageContent: document.querySelector('#triage-content'),
  proposalContent: document.querySelector('#proposal-content'),
  approvalPanel: document.querySelector('#approval-panel'),
  approvalCopy: document.querySelector('#approval-copy'),
  actor: document.querySelector('#actor'),
  rejectionReason: document.querySelector('#rejection-reason'),
  approveButton: document.querySelector('#approve-button'),
  rejectButton: document.querySelector('#reject-button'),
  timeline: document.querySelector('#timeline'),
  budgetList: document.querySelector('#budget-list'),
  costList: document.querySelector('#cost-list'),
  toast: document.querySelector('#toast'),
};

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers,
    },
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload?.success) {
    throw new Error(payload?.error?.message || `Request failed (${response.status})`);
  }
  return payload.data;
}

async function loadScenarios() {
  try {
    appState.scenarios = await api('/api/scenarios');
    renderScenarios();
  } catch (error) {
    elements.scenarioGrid.replaceChildren(node('div', 'loading-card', 'The local scenarios could not be loaded.'));
    showToast(error.message, true);
  }
}

function renderScenarios() {
  const cards = appState.scenarios.map((scenario, index) => {
    const card = node('article', 'scenario-card');
    const top = node('div', 'scenario-top');
    top.append(node('span', 'severity', scenario.severity), node('span', 'scenario-index', `SCN-${String(index + 1).padStart(2, '0')}`));
    card.append(top, node('h3', '', scenario.title), node('p', '', scenario.summary));
    card.append(node('div', 'scenario-signal', scenario.signal));
    const button = node('button', 'button button-quiet', 'Investigate scenario');
    button.type = 'button';
    button.addEventListener('click', () => startIncident(scenario.id));
    card.append(button);
    return card;
  });
  elements.scenarioGrid.replaceChildren(...cards);
}

async function startIncident(scenarioID) {
  if (appState.busy) return;
  setBusy(true);
  try {
    appState.incident = await api('/api/incidents', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: scenarioID }),
    });
    renderIncident();
    elements.workspace.hidden = false;
    elements.workspace.scrollIntoView({ behavior: 'smooth', block: 'start' });
    showToast('Triage complete. The loop is stopped for your decision.');
  } catch (error) {
    showToast(error.message, true);
  } finally {
    setBusy(false);
  }
}

async function decide(decision) {
  const incident = appState.incident;
  if (!incident?.proposal || incident.state !== 'AWAITING_APPROVAL' || appState.busy) return;
  const actor = elements.actor.value.trim();
  const payload = {
    proposal_id: incident.proposal.id,
    proposal_digest: incident.proposal.digest,
    actor,
  };
  if (decision === 'reject') payload.reason = elements.rejectionReason.value.trim();
  setBusy(true);
  try {
    appState.incident = await api(`/api/incidents/${incident.id}/${decision}`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    renderIncident();
    showToast(decision === 'approve' ? 'Typed action executed and independently verified.' : 'Proposal rejected. No action executed.');
  } catch (error) {
    showToast(error.message, true);
  } finally {
    setBusy(false);
  }
}

function renderIncident() {
  const incident = appState.incident;
  if (!incident) return;
  elements.workspaceTitle.textContent = incident.title;
  elements.incidentID.textContent = `${incident.id} · ${incident.severity}`;
  elements.stateBadge.textContent = incident.state;
  elements.stateBadge.className = `state-badge ${incident.state.toLowerCase()}`;
  renderStateRail(incident);
  renderSLO(incident);
  renderEvidence(incident);
  renderTriage(incident);
  renderApproval(incident);
  renderTimeline(incident.events || []);
  renderBudget(incident);
}

function renderStateRail(incident) {
  const terminalResolved = incident.state === 'RESOLVED';
  const terminalEscalated = incident.state === 'ESCALATED';
  let activeIndex = stateOrder.indexOf(incident.state);
  if (incident.state === 'PROPOSED') activeIndex = 1;
  if (terminalEscalated) activeIndex = Math.min(4, incident.execution ? 4 : 2);
  const steps = stateLabels.map((label, index) => {
    let className = 'rail-step';
    if (index < activeIndex || terminalResolved) className += ' complete';
    if (index === activeIndex && !terminalResolved && !terminalEscalated) className += ' current';
    const step = node('span', className, label);
    step.setAttribute('aria-current', className.includes('current') ? 'step' : 'false');
    return step;
  });
  elements.stateRail.replaceChildren(...steps);
}

function renderSLO(incident) {
  const rows = [
    { label: 'p95 latency', key: 'latency_p95_ms', unit: ' ms', target: `≤ ${formatNumber(incident.slo_target.max_latency_p95_ms)} ms`, max: Math.max(incident.before.latency_p95_ms, incident.slo_target.max_latency_p95_ms) * 1.15 },
    { label: 'Error rate', key: 'error_rate_percent', unit: '%', target: `≤ ${formatNumber(incident.slo_target.max_error_rate_percent)}%`, max: Math.max(incident.before.error_rate_percent, incident.slo_target.max_error_rate_percent) * 1.15 },
    { label: 'Availability', key: 'availability_percent', unit: '%', target: `≥ ${formatNumber(incident.slo_target.min_availability_percent)}%`, max: 100 },
  ];
  const table = node('div', 'slo-table');
  rows.forEach((metric) => {
    const row = node('div', 'slo-row');
    const label = node('div', 'slo-label', metric.label);
    label.append(node('div', '', `Target ${metric.target}`));
    row.append(label, metricValue('Before', incident.before[metric.key], metric.unit, false, metric.max));
    const afterValue = incident.after ? incident.after[metric.key] : null;
    row.append(metricValue('After', afterValue, metric.unit, incident.after?.passing === true, metric.max));
    table.append(row);
  });
  elements.sloComparison.replaceChildren(table);
  if (incident.verification) {
    elements.freshBadge.textContent = `${incident.verification.outcome} · FRESH PROBE`;
  } else {
    elements.freshBadge.textContent = 'AWAITING ACTION';
  }
}

function metricValue(label, value, unit, passing, max) {
  const wrapper = node('div', `slo-value ${value === null ? '' : passing ? 'pass' : 'fail'}`);
  wrapper.append(node('small', '', label), node('span', '', value === null ? '—' : `${formatNumber(value)}${unit}`));
  const progress = document.createElement('progress');
  progress.max = max || 100;
  progress.value = value === null ? 0 : Math.min(value, progress.max);
  progress.setAttribute('aria-label', `${label} ${value ?? 'not available'}`);
  wrapper.append(progress);
  return wrapper;
}

function renderEvidence(incident) {
  const evidence = incident.observations || [];
  const items = evidence.map((observation) => {
    const item = node('div', 'evidence-item');
    item.append(node('span', 'evidence-icon', observation.type.slice(0, 2)));
    const content = node('div', '');
    content.append(node('div', 'evidence-name', observation.name));
    const displayValue = observation.text || `${formatNumber(observation.value)} ${observation.unit || ''}`;
    content.append(node('p', 'evidence-value', `${displayValue} · ${observation.source_uri}`));
    item.append(content);
    const trustClass = observation.trust === 'UNTRUSTED_DATA' ? 'trust-tag untrusted' : 'trust-tag';
    item.append(node('span', trustClass, observation.trust === 'UNTRUSTED_DATA' ? 'Untrusted' : 'Observed'));
    return item;
  });
  elements.evidenceList.replaceChildren(...items);
  elements.evidenceCount.textContent = `${evidence.length} signals`;
}

function renderTriage(incident) {
  elements.confidence.textContent = `${Math.round((incident.triage?.confidence || 0) * 100)}% CONFIDENCE`;
  const hypothesis = node('p', 'hypothesis', incident.triage?.hypothesis || 'No hypothesis available.');
  const links = node('div', 'evidence-links');
  (incident.triage?.evidence_ids || []).forEach((id) => links.append(node('span', 'evidence-chip', id)));
  elements.triageContent.replaceChildren(hypothesis, links);

  const proposal = incident.proposal;
  if (!proposal) {
    elements.proposalContent.replaceChildren(node('p', 'approval-copy', 'No remediation proposal was produced.'));
    return;
  }
  const action = `${proposal.action.kind} · ${proposal.action.target}`;
  const transition = `${proposal.action.from} → ${proposal.action.to}`;
  const policy = proposal.policy.allowed ? 'ALLOW · deterministic-policy/v1' : 'DENY';
  elements.proposalContent.replaceChildren(
    proposalRow('Action', action),
    proposalRow('Transition', transition),
    proposalRow('Policy gate', policy, 'policy-pass'),
    proposalRow('Proposal digest', proposal.digest, 'digest'),
    proposalRow('Expires', formatTime(proposal.expires_at)),
  );
}

function proposalRow(label, value, valueClass = '') {
  const row = node('div', 'proposal-row');
  row.append(node('span', '', label), node('span', valueClass, value));
  return row;
}

function renderApproval(incident) {
  const waiting = incident.state === 'AWAITING_APPROVAL';
  elements.approveButton.disabled = !waiting || appState.busy;
  elements.rejectButton.disabled = !waiting || appState.busy;
  elements.actor.disabled = !waiting || appState.busy;
  elements.rejectionReason.disabled = !waiting || appState.busy;
  if (waiting) {
    elements.approvalCopy.textContent = 'Execution is stopped. Your decision is bound to the exact proposal, action, policy digest, and TTL shown above.';
    return;
  }
  if (incident.approval) {
    elements.approvalCopy.textContent = `${incident.approval.decision} by ${incident.approval.actor}. ${incident.approval.decision === 'REJECTED' ? 'No action was executed.' : 'The approved typed action could not change after approval.'}`;
  } else {
    elements.approvalCopy.textContent = 'No human decision was recorded.';
  }
}

function renderTimeline(events) {
  const items = events.map((event) => {
    const item = node('li', 'timeline-item');
    item.append(node('span', 'timeline-marker'));
    const content = node('div', 'timeline-content');
    content.append(node('div', 'timeline-type', event.type), node('p', 'timeline-summary', event.summary));
    item.append(content, node('span', 'timeline-seq', `#${String(event.sequence).padStart(2, '0')}`));
    return item;
  });
  elements.timeline.replaceChildren(...items);
}

function renderBudget(incident) {
  const deadline = formatTime(incident.budget.deadline);
  const entries = [
    ['Iteration', `${incident.iteration} / ${incident.budget.max_iterations}`],
    ['Retries', `${incident.retry_count} / ${incident.budget.max_retries}`],
    ['Deadline', deadline],
    ['Audit events', String((incident.events || []).length)],
    ['Terminal', ['RESOLVED', 'ESCALATED'].includes(incident.state) ? 'yes' : 'no'],
  ].map(([term, value]) => {
    const row = node('div');
    row.append(node('dt', '', term), node('dd', '', value));
    return row;
  });
  elements.budgetList.replaceChildren(...entries);
  const costs = (incident.cost_ledger || []).map((entry) => {
    const row = node('div', 'cost-entry');
    row.append(node('span', '', entry.stage), node('span', '', `$${Number(entry.usd).toFixed(4)}`));
    return row;
  });
  elements.costList.replaceChildren(...costs);
}

function setBusy(busy) {
  appState.busy = busy;
  document.querySelectorAll('.scenario-card button').forEach((button) => { button.disabled = busy; });
  if (appState.incident) renderApproval(appState.incident);
}

let toastTimer;
function showToast(message, isError = false) {
  clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.className = isError ? 'toast error' : 'toast';
  elements.toast.hidden = false;
  toastTimer = setTimeout(() => { elements.toast.hidden = true; }, 4500);
}

function formatNumber(value) {
  return Number(value).toLocaleString(undefined, { maximumFractionDigits: 2 });
}

function formatTime(value) {
  if (!value) return '—';
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

elements.approveButton.addEventListener('click', () => decide('approve'));
elements.rejectButton.addEventListener('click', () => decide('reject'));
loadScenarios();
