import { describe, expect, it } from 'vitest';
import { buildIncidentReport } from '../src/report.js';
import { correlate } from '../src/correlate.js';
import { generateEvents, mulberry32 } from '../src/generate.js';
import { getRule } from '../src/rules.js';

const NOW = Date.parse('2026-03-01T12:00:00.000Z');

function ev({ type, ip = '198.51.100.1', at = 0, country = 'Germany' }) {
  const rule = getRule(type);
  return {
    type,
    name: rule.name,
    ruleId: rule.id,
    severity: rule.severity,
    technique: rule.mitre.technique,
    tactic: rule.mitre.tactic,
    message: rule.messages[0],
    sourceIp: ip,
    source: rule.sources[0],
    country,
    destinationPort: 443,
    timestamp: NOW + at
  };
}

describe('buildIncidentReport', () => {
  const events = [
    ev({ type: 'brute_force', ip: '203.0.113.9', at: 0 }),
    ev({ type: 'privilege_escalation', ip: '203.0.113.9', at: 60000 }),
    ev({ type: 'xss', ip: '198.51.100.4', country: 'Brazil' })
  ];
  const correlations = correlate(events);
  const report = buildIncidentReport({
    events,
    correlations,
    windowKey: '24h',
    generatedAt: NOW
  });

  it('is deterministic — same inputs produce byte-identical output', () => {
    expect(
      buildIncidentReport({ events, correlations, windowKey: '24h', generatedAt: NOW })
    ).toBe(report);
  });

  it('stamps the injected generation time and window, not the wall clock', () => {
    expect(report).toContain('2026-03-01T12:00:00.000Z');
    expect(report).toContain('Analysis window:  24h');
  });

  it('labels the data as a simulation rather than a real incident', () => {
    expect(report).toContain('simulation');
    expect(report).toContain('not a real incident');
  });

  it('contains all seven report sections', () => {
    for (const section of [
      '1. EXECUTIVE SUMMARY',
      '2. CORRELATED INCIDENTS',
      '3. DETECTION BREAKDOWN',
      '4. MITRE ATT&CK COVERAGE',
      '5. TOP THREAT SOURCES',
      '6. GEOGRAPHIC CONCENTRATION',
      '7. RECOMMENDED ACTIONS'
    ]) {
      expect(report).toContain(section);
    }
  });

  it('reports counts that match the input set', () => {
    expect(report).toContain('Events analysed:        3');
    expect(report).toContain('Critical:               1');
    expect(report).toContain('High:                   1');
    expect(report).toContain('Medium:                 1');
    expect(report).toContain('Distinct source IPs:    2');
    expect(report).toContain('T1068');
  });

  it('raises a credential-rotation action when the compromise chain fired', () => {
    expect(correlations.some((c) => c.rule === 'CORR-02')).toBe(true);
    expect(report).toContain('Force credential rotation');
  });

  it('degrades gracefully on an empty event set', () => {
    const empty = buildIncidentReport({
      events: [],
      correlations: [],
      windowKey: '1h',
      generatedAt: NOW
    });
    expect(empty).toContain('Events analysed:        0');
    expect(empty).toContain('No multi-event correlations fired');
    expect(empty).toContain('No detections in this window.');
    expect(empty).toContain('No techniques observed.');
    expect(empty).toContain('No sources in this window.');
    expect(empty).toContain('End of report.');
  });

  it('handles a full generated batch without throwing', () => {
    const batch = generateEvents({ count: 300, now: NOW, rng: mulberry32(2026) });
    const out = buildIncidentReport({
      events: batch,
      correlations: correlate(batch),
      windowKey: '7d',
      generatedAt: NOW
    });
    expect(out.split('\n').length).toBeGreaterThan(40);
    expect(out).toContain('Events analysed:        300');
  });
});
