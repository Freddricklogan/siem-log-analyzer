import { describe, expect, it } from 'vitest';
import {
  ATTACK_TYPES,
  compareSeverity,
  computeThreatScore,
  DETECTION_RULES,
  getRule,
  maxSeverity,
  mitreMatrix,
  SEVERITY_ORDER,
  techniquesObserved,
  TYPE_COLORS
} from '../src/rules.js';

const ev = (type, extra = {}) => {
  const rule = getRule(type);
  return {
    type,
    severity: rule.severity,
    technique: rule.mitre.technique,
    tactic: rule.mitre.tactic,
    ...extra
  };
};

describe('detection rule catalogue', () => {
  it('has a unique id, type and colour for every rule', () => {
    const ids = new Set(DETECTION_RULES.map((r) => r.id));
    const types = new Set(DETECTION_RULES.map((r) => r.type));
    expect(ids.size).toBe(DETECTION_RULES.length);
    expect(types.size).toBe(DETECTION_RULES.length);
    for (const type of ATTACK_TYPES) expect(TYPE_COLORS[type]).toMatch(/^#[0-9a-f]{6}$/i);
  });

  it('gives every rule a valid severity, ATT&CK technique and sample messages', () => {
    for (const rule of DETECTION_RULES) {
      expect(SEVERITY_ORDER).toContain(rule.severity);
      expect(rule.mitre.technique).toMatch(/^T\d{4}$/);
      expect(rule.mitre.tactic.length).toBeGreaterThan(0);
      expect(rule.messages.length).toBeGreaterThan(0);
      expect(rule.sources.length).toBeGreaterThan(0);
    }
  });

  it('resolves rules by type and returns undefined for unknown types', () => {
    expect(getRule('ddos').id).toBe('SIEM-005');
    expect(getRule('not-a-rule')).toBeUndefined();
  });
});

describe('severity ordering', () => {
  it('ranks critical above high above medium above low', () => {
    expect(compareSeverity('critical', 'high')).toBeGreaterThan(0);
    expect(compareSeverity('medium', 'high')).toBeLessThan(0);
    expect(compareSeverity('low', 'low')).toBe(0);
  });

  it('returns low for an empty event list', () => {
    expect(maxSeverity([])).toBe('low');
  });

  it('finds the highest severity present', () => {
    expect(maxSeverity([{ severity: 'low' }, { severity: 'critical' }, { severity: 'medium' }])).toBe(
      'critical'
    );
  });
});

describe('computeThreatScore', () => {
  it('is deterministic for identical input', () => {
    const input = { severity: 'high', eventCount: 12, distinctTypes: 2, distinctTactics: 2 };
    expect(computeThreatScore(input)).toBe(computeThreatScore(input));
  });

  it('ranks a critical source above a low-severity one at equal volume', () => {
    const base = { eventCount: 10, distinctTypes: 1, distinctTactics: 1 };
    expect(computeThreatScore({ ...base, severity: 'critical' })).toBeGreaterThan(
      computeThreatScore({ ...base, severity: 'low' })
    );
  });

  it('rewards breadth and kill-chain span', () => {
    const one = computeThreatScore({ severity: 'high', eventCount: 10, distinctTypes: 1, distinctTactics: 1 });
    const many = computeThreatScore({ severity: 'high', eventCount: 10, distinctTypes: 4, distinctTactics: 3 });
    expect(many).toBeGreaterThan(one);
  });

  it('grows sublinearly with volume so one noisy scanner cannot saturate the board', () => {
    const a = computeThreatScore({ severity: 'low', eventCount: 10, distinctTypes: 1 });
    const b = computeThreatScore({ severity: 'low', eventCount: 1000, distinctTypes: 1 });
    expect(b - a).toBeLessThan(12);
  });

  it('clamps to 0-100 and defaults unknown severities to the lowest weight', () => {
    const huge = computeThreatScore({
      severity: 'critical',
      eventCount: 1e6,
      distinctTypes: 40,
      distinctTactics: 9
    });
    expect(huge).toBeLessThanOrEqual(100);
    expect(huge).toBeGreaterThanOrEqual(0);
    expect(computeThreatScore({ severity: 'bogus', eventCount: 1, distinctTypes: 1 })).toBe(10);
  });
});

describe('mitreMatrix', () => {
  it('groups techniques under their tactic and counts events', () => {
    const matrix = mitreMatrix([
      ev('brute_force'),
      ev('brute_force'),
      ev('privilege_escalation'),
      ev('port_scan')
    ]);
    const credential = matrix.find((t) => t.tactic === 'Credential Access');
    expect(credential.count).toBe(2);
    expect(credential.techniques).toEqual([
      { id: 'T1110', name: 'Brute Force', detection: 'Brute Force Authentication', count: 2 }
    ]);
  });

  it('sorts tactics by event volume, descending', () => {
    const matrix = mitreMatrix([ev('port_scan'), ev('brute_force'), ev('brute_force')]);
    expect(matrix[0].tactic).toBe('Credential Access');
    expect(matrix[1].tactic).toBe('Discovery');
  });

  it('ignores events whose type has no rule, and handles an empty list', () => {
    expect(mitreMatrix([])).toEqual([]);
    expect(mitreMatrix([{ type: 'unknown' }])).toEqual([]);
  });
});

describe('techniquesObserved', () => {
  it('returns sorted, de-duplicated technique ids', () => {
    expect(techniquesObserved([ev('ddos'), ev('brute_force'), ev('brute_force')])).toEqual([
      'T1110',
      'T1498'
    ]);
  });
});
