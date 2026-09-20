import { describe, expect, it } from 'vitest';
import { correlate, CORRELATION_THRESHOLDS } from '../src/correlate.js';
import { getRule } from '../src/rules.js';

const NOW = Date.parse('2026-03-01T12:00:00.000Z');
const MIN = 60 * 1000;

function ev({ type, ip = '198.51.100.1', at = 0 }) {
  const rule = getRule(type);
  return {
    type,
    severity: rule.severity,
    tactic: rule.mitre.tactic,
    technique: rule.mitre.technique,
    sourceIp: ip,
    timestamp: NOW + at
  };
}

const ruleIds = (findings) => findings.map((f) => f.rule);

describe('CORR-01 multi-vector campaign', () => {
  it('fires when one source spans at least three attack classes', () => {
    const findings = correlate([
      ev({ type: 'port_scan', ip: '1.1.1.1', at: 0 }),
      ev({ type: 'xss', ip: '1.1.1.1', at: MIN }),
      ev({ type: 'ddos', ip: '1.1.1.1', at: 2 * MIN })
    ]);
    const finding = findings.find((f) => f.rule === 'CORR-01');
    expect(finding).toBeDefined();
    expect(finding.evidence).toEqual(['ddos', 'port_scan', 'xss']);
    expect(finding.eventCount).toBe(3);
    expect(finding.severity).toBe('critical');
  });

  it('does not fire on two classes from one source', () => {
    const findings = correlate([
      ev({ type: 'port_scan', ip: '1.1.1.1' }),
      ev({ type: 'xss', ip: '1.1.1.1', at: MIN })
    ]);
    expect(ruleIds(findings)).not.toContain('CORR-01');
  });

  it('does not fire when three classes come from three different sources', () => {
    const findings = correlate([
      ev({ type: 'port_scan', ip: '1.1.1.1' }),
      ev({ type: 'xss', ip: '2.2.2.2' }),
      ev({ type: 'ddos', ip: '3.3.3.3' })
    ]);
    expect(ruleIds(findings)).not.toContain('CORR-01');
  });
});

describe('CORR-02 credential compromise chain', () => {
  it('fires when privilege escalation follows brute force from the same source', () => {
    const findings = correlate([
      ev({ type: 'brute_force', ip: '4.4.4.4', at: 0 }),
      ev({ type: 'privilege_escalation', ip: '4.4.4.4', at: 12 * MIN })
    ]);
    const finding = findings.find((f) => f.rule === 'CORR-02');
    expect(finding).toBeDefined();
    expect(finding.severity).toBe('critical');
    expect(finding.evidence[0]).toContain('12 min');
  });

  it('does NOT fire when the escalation precedes the brute force (ordering is enforced)', () => {
    const findings = correlate([
      ev({ type: 'privilege_escalation', ip: '4.4.4.4', at: 0 }),
      ev({ type: 'brute_force', ip: '4.4.4.4', at: 12 * MIN })
    ]);
    expect(ruleIds(findings)).not.toContain('CORR-02');
  });

  it('does not fire when the two stages come from different sources', () => {
    const findings = correlate([
      ev({ type: 'brute_force', ip: '4.4.4.4', at: 0 }),
      ev({ type: 'privilege_escalation', ip: '5.5.5.5', at: MIN })
    ]);
    expect(ruleIds(findings)).not.toContain('CORR-02');
  });
});

describe('CORR-03 recon to exploitation', () => {
  it('fires when an injection attack follows a port scan from the same source', () => {
    const findings = correlate([
      ev({ type: 'port_scan', ip: '6.6.6.6', at: 0 }),
      ev({ type: 'sql_injection', ip: '6.6.6.6', at: 5 * MIN })
    ]);
    expect(ruleIds(findings)).toContain('CORR-03');
  });

  it('does not fire when the exploitation precedes the scan', () => {
    const findings = correlate([
      ev({ type: 'sql_injection', ip: '6.6.6.6', at: 0 }),
      ev({ type: 'port_scan', ip: '6.6.6.6', at: 5 * MIN })
    ]);
    expect(ruleIds(findings)).not.toContain('CORR-03');
  });
});

describe('CORR-04 distributed denial of service', () => {
  it('needs both the event threshold and the source-diversity threshold', () => {
    const many = Array.from({ length: 20 }, (_, i) =>
      ev({ type: 'ddos', ip: `203.0.113.${i + 1}`, at: i * MIN })
    );
    expect(ruleIds(correlate(many))).toContain('CORR-04');

    const oneSource = Array.from({ length: 20 }, (_, i) =>
      ev({ type: 'ddos', ip: '203.0.113.9', at: i * MIN })
    );
    expect(ruleIds(correlate(oneSource))).not.toContain('CORR-04');
  });

  it('respects overridden thresholds', () => {
    const few = [
      ev({ type: 'ddos', ip: '1.1.1.1' }),
      ev({ type: 'ddos', ip: '2.2.2.2' }),
      ev({ type: 'ddos', ip: '3.3.3.3' })
    ];
    expect(ruleIds(correlate(few))).not.toContain('CORR-04');
    expect(
      ruleIds(correlate(few, { thresholds: { ddosMinEvents: 3, ddosMinSources: 3 } }))
    ).toContain('CORR-04');
  });
});

describe('CORR-05 distributed password spray', () => {
  it('fires once enough distinct sources attempt authentication', () => {
    const events = Array.from({ length: CORRELATION_THRESHOLDS.distributedBruteForceMinSources }, (_, i) =>
      ev({ type: 'brute_force', ip: `198.51.100.${i + 1}`, at: i * MIN })
    );
    expect(ruleIds(correlate(events))).toContain('CORR-05');
    expect(ruleIds(correlate(events.slice(0, 2)))).not.toContain('CORR-05');
  });
});

describe('CORR-06 beaconing to exfiltration', () => {
  it('fires when repeated transfers follow the first beacon', () => {
    const findings = correlate([
      ev({ type: 'malware_c2', ip: '7.7.7.7', at: 0 }),
      ev({ type: 'data_exfiltration', ip: '7.7.7.7', at: MIN }),
      ev({ type: 'data_exfiltration', ip: '7.7.7.7', at: 2 * MIN })
    ]);
    expect(ruleIds(findings)).toContain('CORR-06');
  });

  it('does not fire on a single transfer, nor when transfers precede the beacon', () => {
    expect(
      ruleIds(
        correlate([
          ev({ type: 'malware_c2', ip: '7.7.7.7', at: 0 }),
          ev({ type: 'data_exfiltration', ip: '7.7.7.7', at: MIN })
        ])
      )
    ).not.toContain('CORR-06');

    expect(
      ruleIds(
        correlate([
          ev({ type: 'data_exfiltration', ip: '7.7.7.7', at: 0 }),
          ev({ type: 'data_exfiltration', ip: '7.7.7.7', at: MIN }),
          ev({ type: 'malware_c2', ip: '7.7.7.7', at: 2 * MIN })
        ])
      )
    ).not.toContain('CORR-06');
  });
});

describe('correlate output contract', () => {
  it('returns nothing for an empty event set', () => {
    expect(correlate([])).toEqual([]);
  });

  it('sorts critical findings before high ones', () => {
    const events = [
      ev({ type: 'brute_force', ip: '8.8.8.8', at: 0 }),
      ev({ type: 'privilege_escalation', ip: '8.8.8.8', at: MIN }),
      ...Array.from({ length: 6 }, (_, i) =>
        ev({ type: 'brute_force', ip: `192.0.2.${i + 1}`, at: i * MIN })
      )
    ];
    const findings = correlate(events);
    const severities = findings.map((f) => f.severity);
    expect(severities.indexOf('critical')).toBeLessThan(severities.lastIndexOf('high'));
  });

  it('caps the number of findings so one noisy window cannot flood the panel', () => {
    const events = [];
    for (let actor = 0; actor < 40; actor += 1) {
      const ip = `203.0.113.${actor + 1}`;
      events.push(ev({ type: 'port_scan', ip, at: 0 }));
      events.push(ev({ type: 'xss', ip, at: MIN }));
      events.push(ev({ type: 'ddos', ip, at: 2 * MIN }));
    }
    expect(correlate(events).length).toBeLessThanOrEqual(CORRELATION_THRESHOLDS.maxFindings);
  });

  it('caps per-source findings so the chain rules are not crowded out', () => {
    const events = [];
    // 30 noisy multi-vector sources...
    for (let actor = 0; actor < 30; actor += 1) {
      const ip = `203.0.113.${actor + 1}`;
      events.push(ev({ type: 'port_scan', ip, at: 0 }));
      events.push(ev({ type: 'xss', ip, at: MIN }));
      events.push(ev({ type: 'ddos', ip, at: 2 * MIN }));
    }
    // ...plus one genuine credential-compromise chain.
    events.push(ev({ type: 'brute_force', ip: '198.51.100.1', at: 0 }));
    events.push(ev({ type: 'privilege_escalation', ip: '198.51.100.1', at: MIN }));

    const findings = correlate(events);
    const corr01 = findings.filter((f) => f.rule === 'CORR-01');
    expect(corr01.length).toBeLessThanOrEqual(CORRELATION_THRESHOLDS.maxMultiVectorFindings);
    expect(ruleIds(findings)).toContain('CORR-02');
  });

  it('gives every finding the documented shape', () => {
    const findings = correlate([
      ev({ type: 'port_scan', ip: '9.9.9.9', at: 0 }),
      ev({ type: 'sql_injection', ip: '9.9.9.9', at: MIN }),
      ev({ type: 'data_exfiltration', ip: '9.9.9.9', at: 2 * MIN })
    ]);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(typeof f.id).toBe('string');
      expect(typeof f.rule).toBe('string');
      expect(typeof f.title).toBe('string');
      expect(typeof f.detail).toBe('string');
      expect(Array.isArray(f.evidence)).toBe(true);
      expect(Array.isArray(f.tactics)).toBe(true);
      expect(typeof f.eventCount).toBe('number');
    }
  });
});
