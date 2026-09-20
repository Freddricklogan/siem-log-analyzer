/**
 * Alert correlation engine.
 *
 * Correlation rules look across events rather than at one event at a time.
 * Every rule is order-aware where order matters (recon before exploitation,
 * brute force before escalation) — the original demo treated co-occurrence as
 * a chain even when the escalation happened first, which produces false
 * "credential compromise" findings on shuffled data.
 *
 * Pure module: no DOM, no clock, no randomness.
 */

import { maxSeverity } from './rules.js';

/** Tunables, exported so tests and the UI agree on the thresholds. */
export const CORRELATION_THRESHOLDS = Object.freeze({
  multiVectorMinTypes: 3,
  /**
   * CORR-01 fires once per source IP, so on a busy window it can fill every
   * slot and hide the single-instance chain rules that an analyst most needs to
   * see. Only the worst few per-source findings are kept.
   */
  maxMultiVectorFindings: 3,
  ddosMinEvents: 15,
  ddosMinSources: 3,
  distributedBruteForceMinSources: 5,
  exfilMinEvents: 2,
  maxFindings: 8
});

/**
 * @param {Array<object>} events
 * @returns {Map<string, Array<object>>} events grouped by source IP, each list ascending in time
 */
function groupBySource(events) {
  const bySource = new Map();
  for (const event of events) {
    const list = bySource.get(event.sourceIp);
    if (list) list.push(event);
    else bySource.set(event.sourceIp, [event]);
  }
  for (const list of bySource.values()) list.sort((a, b) => a.timestamp - b.timestamp);
  return bySource;
}

/**
 * Earliest timestamp of a given type within one source's ordered event list.
 * @param {Array<object>} list @param {string} type
 */
function firstOf(list, type) {
  for (const event of list) if (event.type === type) return event.timestamp;
  return null;
}

/**
 * Latest timestamp of a given type.
 * @param {Array<object>} list @param {string} type
 */
function lastOf(list, type) {
  for (let i = list.length - 1; i >= 0; i -= 1) if (list[i].type === type) return list[i].timestamp;
  return null;
}

/**
 * Run every correlation rule over a set of events.
 *
 * @param {Array<object>} events
 * @param {{ thresholds?: object }} [options]
 * @returns {Array<{
 *   id: string, rule: string, title: string, severity: string, detail: string,
 *   evidence: string[], tactics: string[], eventCount: number
 * }>} sorted most severe first, capped at `maxFindings`
 */
export function correlate(events, options = {}) {
  const t = { ...CORRELATION_THRESHOLDS, ...(options.thresholds ?? {}) };
  const bySource = groupBySource(events);
  const findings = [];

  // ---- CORR-01: one source, many distinct attack classes --------------------
  const multiVector = [];
  for (const [ip, list] of bySource) {
    const types = new Set(list.map((e) => e.type));
    if (types.size < t.multiVectorMinTypes) continue;
    const tactics = [...new Set(list.map((e) => e.tactic))];
    multiVector.push({
      id: `CORR-01:${ip}`,
      rule: 'CORR-01',
      title: `Multi-vector campaign from ${ip}`,
      severity: maxSeverity(list),
      detail:
        `${types.size} distinct attack classes and ${tactics.length} ATT&CK tactics ` +
        `observed from a single source across ${list.length} events. Single-source ` +
        'breadth of this kind is characteristic of a directed campaign rather than ' +
        'opportunistic background noise.',
      evidence: [...types].sort(),
      tactics: tactics.sort(),
      eventCount: list.length
    });
  }
  // Keep only the broadest, busiest sources so the chain rules below stay visible.
  multiVector.sort(
    (a, b) =>
      b.evidence.length - a.evidence.length ||
      b.eventCount - a.eventCount ||
      a.id.localeCompare(b.id)
  );
  findings.push(...multiVector.slice(0, t.maxMultiVectorFindings));

  // ---- CORR-02: brute force then privilege escalation (order enforced) ------
  const chainSources = [];
  for (const [ip, list] of bySource) {
    const firstBrute = firstOf(list, 'brute_force');
    const lastEsc = lastOf(list, 'privilege_escalation');
    if (firstBrute !== null && lastEsc !== null && lastEsc > firstBrute) {
      chainSources.push({ ip, gapMs: lastEsc - firstBrute, events: list.length });
    }
  }
  if (chainSources.length > 0) {
    chainSources.sort((a, b) => a.gapMs - b.gapMs);
    findings.push({
      id: 'CORR-02',
      rule: 'CORR-02',
      title: 'Credential compromise chain',
      severity: 'critical',
      detail:
        `${chainSources.length} source(s) escalated privileges after an earlier brute ` +
        'force attempt from the same address. Temporal ordering is enforced, so this ' +
        'is a chain rather than co-occurrence. Treat the targeted accounts as ' +
        'compromised until proven otherwise.',
      evidence: chainSources
        .slice(0, 5)
        .map((c) => `${c.ip} — escalation ${Math.round(c.gapMs / 60000)} min after first failure`),
      tactics: ['Credential Access', 'Privilege Escalation'],
      eventCount: chainSources.reduce((sum, c) => sum + c.events, 0)
    });
  }

  // ---- CORR-03: recon followed by exploitation -----------------------------
  const reconExploit = [];
  for (const [ip, list] of bySource) {
    const scan = firstOf(list, 'port_scan');
    if (scan === null) continue;
    const exploit = list.find(
      (e) => (e.type === 'sql_injection' || e.type === 'xss') && e.timestamp > scan
    );
    if (exploit) reconExploit.push(`${ip} — ${exploit.type} after service discovery`);
  }
  if (reconExploit.length > 0) {
    findings.push({
      id: 'CORR-03',
      rule: 'CORR-03',
      title: 'Reconnaissance to exploitation',
      severity: 'high',
      detail:
        `${reconExploit.length} source(s) enumerated services and then attacked an ` +
        'application on a discovered port. The discovery phase is the cheapest place ' +
        'to break this chain at the perimeter.',
      evidence: reconExploit.slice(0, 5),
      tactics: ['Discovery', 'Initial Access'],
      eventCount: reconExploit.length
    });
  }

  // ---- CORR-04: distributed volumetric denial of service --------------------
  const ddos = events.filter((e) => e.type === 'ddos');
  const ddosSources = new Set(ddos.map((e) => e.sourceIp));
  if (ddos.length >= t.ddosMinEvents && ddosSources.size >= t.ddosMinSources) {
    findings.push({
      id: 'CORR-04',
      rule: 'CORR-04',
      title: 'Distributed denial of service',
      severity: 'critical',
      detail:
        `${ddos.length} volumetric events from ${ddosSources.size} distinct sources. ` +
        'Source diversity at this level rules out a single misbehaving client and ' +
        'indicates a coordinated or reflected flood.',
      evidence: [...ddosSources].slice(0, 5),
      tactics: ['Impact'],
      eventCount: ddos.length
    });
  }

  // ---- CORR-05: password spray across many sources -------------------------
  const brute = events.filter((e) => e.type === 'brute_force');
  const bruteSources = new Set(brute.map((e) => e.sourceIp));
  if (bruteSources.size >= t.distributedBruteForceMinSources) {
    findings.push({
      id: 'CORR-05',
      rule: 'CORR-05',
      title: 'Distributed password spray',
      severity: 'high',
      detail:
        `${brute.length} authentication failures spread over ${bruteSources.size} sources. ` +
        'Per-IP lockout thresholds do not catch this shape; rate-limit per account and ' +
        'per credential instead.',
      evidence: [...bruteSources].slice(0, 5),
      tactics: ['Credential Access'],
      eventCount: brute.length
    });
  }

  // ---- CORR-06: C2 beaconing followed by exfiltration ----------------------
  const exfilChain = [];
  for (const [ip, list] of bySource) {
    const beacon = firstOf(list, 'malware_c2');
    if (beacon === null) continue;
    const exfil = list.filter((e) => e.type === 'data_exfiltration' && e.timestamp > beacon);
    if (exfil.length >= t.exfilMinEvents) {
      exfilChain.push(`${ip} — ${exfil.length} transfers after first beacon`);
    }
  }
  if (exfilChain.length > 0) {
    findings.push({
      id: 'CORR-06',
      rule: 'CORR-06',
      title: 'Beaconing to data exfiltration',
      severity: 'critical',
      detail:
        `${exfilChain.length} host(s) began bulk outbound transfers after command and ` +
        'control was established. This is the latest stage represented in the data set ' +
        'and should be escalated first.',
      evidence: exfilChain.slice(0, 5),
      tactics: ['Command and Control', 'Exfiltration'],
      eventCount: exfilChain.length
    });
  }

  const rank = { critical: 3, high: 2, medium: 1, low: 0 };
  return findings
    .sort(
      (a, b) =>
        (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0) ||
        b.eventCount - a.eventCount ||
        a.id.localeCompare(b.id)
    )
    .slice(0, t.maxFindings);
}
