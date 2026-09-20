/**
 * Incident report rendering (plain text, pure).
 *
 * The report takes `generatedAt` as a parameter so its output is fully
 * deterministic and therefore snapshot-testable.
 */

import { attackDistribution, geoDistribution, summarize, topSources } from './detect.js';
import { mitreMatrix, techniquesObserved } from './rules.js';

const RULE_LINE = '='.repeat(64);

/** @param {number} ms */
function iso(ms) {
  return new Date(ms).toISOString();
}

/** @param {string} title */
function heading(title) {
  return `\n${title}\n${RULE_LINE}`;
}

/**
 * @param {object} input
 * @param {Array<object>} input.events        Events already filtered to the window.
 * @param {Array<object>} input.correlations  Output of `correlate()`.
 * @param {string} input.windowKey            e.g. '24h'
 * @param {number} input.generatedAt          epoch ms
 * @returns {string}
 */
export function buildIncidentReport({ events, correlations, windowKey, generatedAt }) {
  const stats = summarize(events);
  const sources = topSources(events, 10);
  const matrix = mitreMatrix(events);
  const distribution = attackDistribution(events);
  const geo = geoDistribution(events, 5);
  const techniques = techniquesObserved(events);

  const lines = [];
  lines.push('SECURITY INCIDENT REPORT — SIEM Log Analyzer');
  lines.push(RULE_LINE);
  lines.push(`Generated:        ${iso(generatedAt)}`);
  lines.push(`Analysis window:  ${windowKey}`);
  lines.push('Data source:      synthetic events generated in-browser (simulation)');
  lines.push('Classification:   demonstration material — not a real incident');

  lines.push(heading('1. EXECUTIVE SUMMARY'));
  lines.push(`Events analysed:        ${stats.total}`);
  lines.push(`Critical:               ${stats.bySeverity.critical}`);
  lines.push(`High:                   ${stats.bySeverity.high}`);
  lines.push(`Medium:                 ${stats.bySeverity.medium}`);
  lines.push(`Low:                    ${stats.bySeverity.low}`);
  lines.push(`Distinct source IPs:    ${stats.uniqueSources}`);
  lines.push(`Origin countries:       ${stats.uniqueCountries}`);
  lines.push(`ATT&CK techniques hit:  ${techniques.length} (${techniques.join(', ') || 'none'})`);
  lines.push(`Correlated incidents:   ${correlations.length}`);

  lines.push(heading('2. CORRELATED INCIDENTS'));
  if (correlations.length === 0) {
    lines.push('No multi-event correlations fired in this window.');
  } else {
    for (const finding of correlations) {
      lines.push(`[${finding.severity.toUpperCase()}] ${finding.rule} — ${finding.title}`);
      lines.push(`  ${finding.detail}`);
      if (finding.evidence.length) {
        lines.push(`  Evidence: ${finding.evidence.join('; ')}`);
      }
      lines.push(`  Tactics:  ${finding.tactics.join(' -> ')}`);
      lines.push('');
    }
  }

  lines.push(heading('3. DETECTION BREAKDOWN'));
  if (distribution.length === 0) {
    lines.push('No detections in this window.');
  } else {
    for (const row of distribution) {
      lines.push(`${row.name.padEnd(36)} ${String(row.count).padStart(5)} events`);
    }
  }

  lines.push(heading('4. MITRE ATT&CK COVERAGE'));
  if (matrix.length === 0) {
    lines.push('No techniques observed.');
  } else {
    for (const tactic of matrix) {
      lines.push(`${tactic.tactic} (${tactic.count} events)`);
      for (const technique of tactic.techniques) {
        lines.push(`  ${technique.id}  ${technique.name} — ${technique.count} events`);
      }
    }
  }

  lines.push(heading('5. TOP THREAT SOURCES (deterministic score, 0-100)'));
  if (sources.length === 0) {
    lines.push('No sources in this window.');
  } else {
    lines.push('  #  SOURCE IP          SCORE  EVENTS  CLASSES  SEVERITY   ORIGIN');
    sources.forEach((row, i) => {
      lines.push(
        `  ${String(i + 1).padStart(2)}  ${row.ip.padEnd(17)}` +
          `${String(row.threatScore).padStart(5)}  ${String(row.eventCount).padStart(6)}  ` +
          `${String(row.distinctTypes).padStart(7)}  ${row.severity.padEnd(9)}  ${row.country}`
      );
    });
  }

  lines.push(heading('6. GEOGRAPHIC CONCENTRATION'));
  if (geo.length === 0) {
    lines.push('No geographic data in this window.');
  } else {
    for (const row of geo) lines.push(`${row.country.padEnd(20)} ${String(row.count).padStart(5)}`);
  }

  lines.push(heading('7. RECOMMENDED ACTIONS'));
  const actions = [];
  if (correlations.some((c) => c.rule === 'CORR-02')) {
    actions.push('Force credential rotation on accounts targeted by the escalation chain.');
  }
  if (correlations.some((c) => c.rule === 'CORR-06')) {
    actions.push('Isolate beaconing hosts and preserve volatile memory before reimaging.');
  }
  if (correlations.some((c) => c.rule === 'CORR-04')) {
    actions.push('Engage upstream scrubbing for the volumetric flood; verify anycast failover.');
  }
  if (correlations.some((c) => c.rule === 'CORR-05')) {
    actions.push('Move from per-IP lockout to per-account and per-credential rate limiting.');
  }
  if (sources.length > 0) {
    actions.push(
      `Block or throttle the top ${Math.min(5, sources.length)} source addresses at the perimeter.`
    );
  }
  actions.push('Tune the detections that produced the highest false-positive volume.');
  actions.push('Escalate every critical correlation to the incident response on-call.');
  actions.forEach((action, i) => lines.push(`${i + 1}. ${action}`));

  lines.push('');
  lines.push(RULE_LINE);
  lines.push('End of report.');

  return lines.join('\n');
}
