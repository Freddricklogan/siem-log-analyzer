/**
 * Detection rule catalogue and MITRE ATT&CK mapping.
 *
 * Pure data + pure functions only — nothing in this module touches the DOM,
 * the clock or the random number generator, so every rule is unit-testable.
 */

/** Severity ranking, lowest to highest. */
export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

/** Weight used when turning a severity into a numeric threat contribution. */
const SEVERITY_WEIGHT = { low: 10, medium: 30, high: 55, critical: 80 };

/**
 * @typedef {object} DetectionRule
 * @property {string} id        Stable rule identifier (used in reports).
 * @property {string} type      Machine-readable attack class.
 * @property {string} name      Human-readable detection name.
 * @property {'low'|'medium'|'high'|'critical'} severity
 * @property {{ technique: string, name: string, tactic: string }} mitre
 * @property {string} logic     One-line description of what the rule keys on.
 * @property {string[]} messages Sample log lines this rule fires on.
 * @property {string[]} sources  Log sources that can emit this detection.
 */

/** @type {DetectionRule[]} */
export const DETECTION_RULES = [
  {
    id: 'SIEM-001',
    type: 'brute_force',
    name: 'Brute Force Authentication',
    severity: 'high',
    mitre: { technique: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
    logic: '>= 10 failed authentications from one source IP inside 5 minutes',
    messages: [
      'Failed login attempt for user svc-backup',
      'Multiple authentication failures — account lockout threshold reached',
      'Password spray pattern detected across 40 accounts',
      'SSH brute force attempt on port 22'
    ],
    sources: ['Auth Server', 'Endpoint Agent', 'Firewall']
  },
  {
    id: 'SIEM-002',
    type: 'sql_injection',
    name: 'SQL Injection',
    severity: 'critical',
    mitre: { technique: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    logic: 'WAF signature match on UNION/boolean/time-based payloads in a request parameter',
    messages: [
      'SQL injection payload in login form parameter',
      'Union-based SQLi detected in /api/search',
      'Blind SQL injection attempt — time-delay payload',
      'Suspected database exfiltration via stacked query'
    ],
    sources: ['Web Server', 'IDS/IPS']
  },
  {
    id: 'SIEM-003',
    type: 'xss',
    name: 'Cross-Site Scripting',
    severity: 'medium',
    mitre: { technique: 'T1189', name: 'Drive-by Compromise', tactic: 'Initial Access' },
    logic: 'Script-context breakout characters reflected into a response body',
    messages: [
      'Reflected XSS in search parameter',
      'Stored XSS payload detected in profile bio field',
      'DOM-based XSS attempt via location.hash',
      'Script injection blocked by output encoding'
    ],
    sources: ['Web Server', 'IDS/IPS']
  },
  {
    id: 'SIEM-004',
    type: 'port_scan',
    name: 'Network Service Discovery',
    severity: 'low',
    mitre: { technique: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
    logic: '>= 20 distinct destination ports touched by one source inside 60 seconds',
    messages: [
      'Sequential port scan detected across 1024 ports',
      'SYN scan from external host',
      'Service enumeration attempt on DMZ subnet',
      'Nmap OS fingerprint signature matched'
    ],
    sources: ['Firewall', 'IDS/IPS']
  },
  {
    id: 'SIEM-005',
    type: 'ddos',
    name: 'Volumetric Denial of Service',
    severity: 'critical',
    mitre: { technique: 'T1498', name: 'Network Denial of Service', tactic: 'Impact' },
    logic: 'Request rate exceeds 20x the rolling 7-day baseline for the edge',
    messages: [
      'Volumetric flood detected at edge — 12 Gbps',
      'SYN flood: half-open connection table saturated',
      'HTTP flood sustained above rate limit',
      'DNS amplification reflection attack observed'
    ],
    sources: ['Firewall', 'DNS Server', 'Web Server']
  },
  {
    id: 'SIEM-006',
    type: 'privilege_escalation',
    name: 'Privilege Escalation',
    severity: 'critical',
    mitre: { technique: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
    logic: 'Unexpected UID 0 transition or SUID execution outside the allow-list',
    messages: [
      'Sudo exploit attempt — malformed argv',
      'Kernel exploit signature matched in syscall trace',
      'SUID binary executed from a world-writable path',
      'Unexpected token elevation to SYSTEM'
    ],
    sources: ['Endpoint Agent', 'Auth Server']
  },
  {
    id: 'SIEM-007',
    type: 'malware_c2',
    name: 'Command & Control Beaconing',
    severity: 'high',
    mitre: { technique: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
    logic: 'Low-jitter periodic egress to a low-reputation destination',
    messages: [
      'Periodic beacon to low-reputation host (jitter < 3%)',
      'DNS tunnelling: oversized TXT responses',
      'TLS client fingerprint matches known implant',
      'Egress to newly registered domain from server VLAN'
    ],
    sources: ['DNS Server', 'Firewall', 'Endpoint Agent']
  },
  {
    id: 'SIEM-008',
    type: 'data_exfiltration',
    name: 'Data Exfiltration',
    severity: 'critical',
    mitre: { technique: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
    logic: 'Outbound transfer volume exceeds the per-host daily 99th percentile',
    messages: [
      'Large outbound transfer to external host — 4.2 GB',
      'Archive staged in temp directory then uploaded',
      'Cloud storage upload from a server with no business need',
      'Mail forwarding rule created for external recipient'
    ],
    sources: ['Firewall', 'Mail Server', 'Endpoint Agent']
  }
];

/** Every attack type the catalogue can emit. */
export const ATTACK_TYPES = DETECTION_RULES.map((r) => r.type);

/** Stable, severity-aware colour per attack type (never positional). */
export const TYPE_COLORS = Object.freeze({
  brute_force: '#d29922',
  sql_injection: '#f85149',
  xss: '#58a6ff',
  port_scan: '#8b98b0',
  ddos: '#ff7b72',
  privilege_escalation: '#d2a8ff',
  malware_c2: '#3fb950',
  data_exfiltration: '#f0883e'
});

const RULES_BY_TYPE = new Map(DETECTION_RULES.map((r) => [r.type, r]));

/**
 * @param {string} type
 * @returns {DetectionRule|undefined}
 */
export function getRule(type) {
  return RULES_BY_TYPE.get(type);
}

/**
 * Compare two severities. Returns > 0 when `a` outranks `b`.
 * @param {string} a @param {string} b
 */
export function compareSeverity(a, b) {
  return SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b);
}

/**
 * Highest severity present in a list of events ('low' when the list is empty).
 * @param {{severity: string}[]} events
 */
export function maxSeverity(events) {
  let best = 'low';
  for (const e of events) {
    if (compareSeverity(e.severity, best) > 0) best = e.severity;
  }
  return best;
}

/**
 * Deterministic threat score for one source IP, on 0–100.
 *
 * Replaces the original demo's `Math.random() * 100`, which made the
 * "Top attacking IPs" ranking meaningless. The score is a bounded sum of:
 *   - the weight of the most severe detection seen from the source
 *   - volume pressure (logarithmic, so one noisy scanner cannot dominate)
 *   - breadth pressure (distinct attack types => likely a campaign)
 *   - a kill-chain bonus when the source spans >= 3 ATT&CK tactics
 *
 * @param {{ severity: string, eventCount: number, distinctTypes: number, distinctTactics?: number }} input
 * @returns {number} integer 0–100
 */
export function computeThreatScore({ severity, eventCount, distinctTypes, distinctTactics = 1 }) {
  const base = SEVERITY_WEIGHT[severity] ?? 10;
  const volume = Math.min(12, Math.log2(Math.max(1, eventCount)) * 3);
  const breadth = Math.min(15, Math.max(0, distinctTypes - 1) * 5);
  const chain = distinctTactics >= 3 ? 8 : 0;
  return Math.max(0, Math.min(100, Math.round(base + volume + breadth + chain)));
}

/**
 * Group events into the ATT&CK matrix: tactic -> techniques -> counts.
 *
 * @param {{ type: string }[]} events
 * @returns {{ tactic: string, count: number, techniques: { id: string, name: string, detection: string, count: number }[] }[]}
 *   Sorted by tactic event count, descending, then tactic name for stability.
 */
export function mitreMatrix(events) {
  /** @type {Map<string, Map<string, {id:string,name:string,detection:string,count:number}>>} */
  const tactics = new Map();

  for (const event of events) {
    const rule = getRule(event.type);
    if (!rule) continue;
    const { tactic, technique, name } = rule.mitre;
    if (!tactics.has(tactic)) tactics.set(tactic, new Map());
    const techniques = tactics.get(tactic);
    const existing = techniques.get(technique);
    if (existing) existing.count += 1;
    else techniques.set(technique, { id: technique, name, detection: rule.name, count: 1 });
  }

  return [...tactics.entries()]
    .map(([tactic, techniques]) => {
      const list = [...techniques.values()].sort(
        (a, b) => b.count - a.count || a.id.localeCompare(b.id)
      );
      return { tactic, count: list.reduce((sum, t) => sum + t.count, 0), techniques: list };
    })
    .sort((a, b) => b.count - a.count || a.tactic.localeCompare(b.tactic));
}

/**
 * Distinct ATT&CK technique IDs observed, sorted.
 * @param {{ type: string }[]} events
 */
export function techniquesObserved(events) {
  const ids = new Set();
  for (const e of events) {
    const rule = getRule(e.type);
    if (rule) ids.add(rule.mitre.technique);
  }
  return [...ids].sort();
}
