/**
 * Application entry point: owns state, wires events, drives rendering.
 * All computation lives in the pure modules; this file only orchestrates.
 */

import { mountExecShell } from './exec-shell.js';
import { generateEvents, mulberry32 } from './generate.js';
import {
  attackDistribution,
  bucketTimeline,
  filterEvents,
  geoDistribution,
  summarize,
  topSources
} from './detect.js';
import { correlate } from './correlate.js';
import { mitreMatrix, techniquesObserved } from './rules.js';
import { buildIncidentReport } from './report.js';
import { createCharts } from './charts.js';
import {
  renderCorrelations,
  renderFeed,
  renderGeo,
  renderMitre,
  renderReport,
  renderTopSources
} from './ui.js';

const REPO = 'https://github.com/Freddricklogan/siem-log-analyzer';
const PAGES = 'https://freddricklogan.github.io/siem-log-analyzer/';

/** Hard cap so repeated ingests cannot grow the heap without bound. */
const MAX_EVENTS = 5000;

const store = {
  /** @type {Array<object>} */ events: [],
  /** @type {Array<object>} */ visible: [],
  /** @type {Array<object>} */ correlations: [],
  ingestBatches: 0,
  /** Seeded so a given session is reproducible; reseeded per batch. */
  seed: 0x5eed1e
};

const dom = {
  severity: document.querySelector('#filter-severity'),
  type: document.querySelector('#filter-type'),
  ip: document.querySelector('#filter-ip'),
  window: document.querySelector('#filter-window'),
  generate: document.querySelector('#btn-generate'),
  export: document.querySelector('#btn-export'),
  clear: document.querySelector('#btn-clear'),
  geo: document.querySelector('#geo-map'),
  topIps: document.querySelector('#top-sources'),
  mitre: document.querySelector('#mitre-map'),
  correlations: document.querySelector('#correlations'),
  feed: document.querySelector('#log-feed'),
  reportPanel: document.querySelector('#report-panel'),
  report: document.querySelector('#report-output'),
  timeline: document.querySelector('#timeline-chart'),
  distribution: document.querySelector('#attack-chart')
};

let charts = { available: false, update() {}, destroy() {} };

function criteria() {
  return {
    severity: dom.severity.value,
    type: dom.type.value,
    ip: dom.ip.value,
    window: dom.window.value
  };
}

function render() {
  const now = Date.now();
  const windowKey = dom.window.value;
  store.visible = filterEvents(store.events, criteria(), now);
  store.correlations = correlate(store.visible);

  charts.update({
    buckets: bucketTimeline(store.visible, now, windowKey),
    windowKey,
    distribution: attackDistribution(store.visible)
  });

  renderGeo(dom.geo, geoDistribution(store.visible));
  renderTopSources(dom.topIps, topSources(store.visible));
  renderMitre(dom.mitre, mitreMatrix(store.visible));
  renderCorrelations(dom.correlations, store.correlations);
  renderFeed(dom.feed, store.visible);

  shell.refreshKpis();
}

function ingest(count = 320) {
  store.ingestBatches += 1;
  store.seed = (store.seed + 0x9e3779b9) >>> 0;
  const batch = generateEvents({
    count,
    now: Date.now(),
    windowMs: 7 * 24 * 60 * 60 * 1000,
    rng: mulberry32(store.seed)
  });
  store.events = [...batch, ...store.events]
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, MAX_EVENTS);
  render();
}

function clearEvents() {
  store.events = [];
  store.ingestBatches = 0;
  dom.reportPanel.hidden = true;
  render();
}

function exportReport() {
  renderReport(
    dom.report,
    buildIncidentReport({
      events: store.visible,
      correlations: store.correlations,
      windowKey: dom.window.value,
      generatedAt: Date.now()
    })
  );
  dom.reportPanel.hidden = false;
  dom.reportPanel.scrollIntoView({ block: 'nearest' });
}

function setFilters({ severity = 'all', type = 'all', ip = '', window: win = '24h' } = {}) {
  dom.severity.value = severity;
  dom.type.value = type;
  dom.ip.value = ip;
  dom.window.value = win;
}

/* -------------------------------------------------------------------------- */
/* Executive Shell                                                            */
/* -------------------------------------------------------------------------- */

const shell = mountExecShell({
  title: 'SIEM Log Analyzer',
  tagline:
    'A browser-based detection-engineering sandbox: synthetic security telemetry is ' +
    'normalized, scored against eight detection rules, mapped to MITRE ATT&CK and ' +
    'correlated into multi-stage incidents — entirely client-side, on simulated data.',
  repo: REPO,
  pagesUrl: PAGES,
  badges: [
    { label: 'Simulated telemetry', tone: 'accent' },
    { label: '8 detection rules' },
    { label: '6 correlation rules' },
    { label: 'Client-side only · no backend', dot: true }
  ],
  kpis: [
    { label: 'Events in window', compute: () => summarize(store.visible).total, tone: 'accent' },
    {
      label: 'Critical alerts',
      compute: () => summarize(store.visible).bySeverity.critical,
      tone: 'danger'
    },
    { label: 'Correlated incidents', compute: () => store.correlations.length, tone: 'warn' },
    { label: 'Distinct source IPs', compute: () => summarize(store.visible).uniqueSources },
    { label: 'ATT&CK techniques', compute: () => techniquesObserved(store.visible).length }
  ],
  tour: [
    {
      selector: '#btn-generate',
      title: '1 · Ingest telemetry',
      body:
        'Ingest generates a fresh batch of synthetic events across eight detection rules, ' +
        'including a handful of multi-stage campaign actors. Clicking this now — watch the ' +
        'KPI strip fill in.',
      action: () => {
        setFilters({ window: '24h' });
        ingest(360);
      }
    },
    {
      selector: '#filter-severity',
      title: '2 · Triage by severity',
      body:
        'Filters recompute every panel from the same normalized event set. Narrowing to ' +
        'critical alerts only — the timeline, ATT&CK map and source ranking all follow.',
      action: () => {
        setFilters({ severity: 'critical', window: '24h' });
        render();
      }
    },
    {
      selector: '#panel-mitre',
      title: '3 · Map to MITRE ATT&CK',
      body:
        'Each detection carries a technique and tactic, so coverage rolls up into the ' +
        'ATT&CK matrix. Switching to the privilege-escalation rule shows how a single ' +
        'detection maps into the kill chain.',
      action: () => {
        setFilters({ type: 'privilege_escalation', window: '24h' });
        render();
      }
    },
    {
      selector: '#panel-correlations',
      title: '4 · Correlate into incidents',
      body:
        'Correlation runs across events, not one at a time: order-aware chains such as ' +
        'brute force -> privilege escalation, recon -> exploitation and beaconing -> ' +
        'exfiltration. Filters reset to the full 7-day window so every rule can fire.',
      action: () => {
        setFilters({ window: '7d' });
        render();
      }
    },
    {
      selector: '#btn-export',
      title: '5 · Export the incident report',
      body:
        'The analyst deliverable: an executive summary, the correlated incidents with ' +
        'evidence, ATT&CK coverage, ranked sources and recommended actions — generated ' +
        'from exactly what is on screen.',
      action: () => exportReport()
    }
  ]
});

/* -------------------------------------------------------------------------- */
/* Wiring — no inline handlers anywhere                                       */
/* -------------------------------------------------------------------------- */

dom.generate.addEventListener('click', () => ingest());
dom.export.addEventListener('click', exportReport);
dom.clear.addEventListener('click', clearEvents);
dom.severity.addEventListener('change', render);
dom.type.addEventListener('change', render);
dom.window.addEventListener('change', render);
dom.ip.addEventListener('input', render);

createCharts({ timelineCanvas: dom.timeline, distributionCanvas: dom.distribution })
  .then((instance) => {
    charts = instance;
    ingest();
  })
  .catch(() => {
    ingest();
  });
