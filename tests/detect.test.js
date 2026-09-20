import { describe, expect, it } from 'vitest';
import {
  attackDistribution,
  bucketSizeFor,
  bucketTimeline,
  filterEvents,
  geoDistribution,
  summarize,
  TIME_WINDOWS,
  topSources
} from '../src/detect.js';
import { getRule, TYPE_COLORS } from '../src/rules.js';

const NOW = Date.parse('2026-03-01T12:00:00.000Z');
const HOUR = 60 * 60 * 1000;

/** Build a normalized event with rule-consistent metadata. */
function ev({ type = 'brute_force', ago = 0, ip = '198.51.100.1', country = 'Germany' } = {}) {
  const rule = getRule(type);
  return {
    id: `${type}-${ago}-${ip}`,
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
    timestamp: NOW - ago
  };
}

describe('filterEvents', () => {
  const events = [
    ev({ type: 'ddos', ago: 10 * 60 * 1000, ip: '203.0.113.5' }),
    ev({ type: 'brute_force', ago: 3 * HOUR, ip: '198.51.100.7' }),
    ev({ type: 'xss', ago: 3 * 24 * HOUR, ip: '198.51.100.8' })
  ];

  it('applies the time window relative to the injected clock, not Date.now()', () => {
    expect(filterEvents(events, { window: '1h' }, NOW)).toHaveLength(1);
    expect(filterEvents(events, { window: '6h' }, NOW)).toHaveLength(2);
    expect(filterEvents(events, { window: '7d' }, NOW)).toHaveLength(3);
  });

  it('defaults to the 24h window for an unknown window key', () => {
    expect(filterEvents(events, { window: 'nonsense' }, NOW)).toHaveLength(2);
  });

  it('filters by severity and detection type', () => {
    expect(filterEvents(events, { window: '7d', severity: 'critical' }, NOW)).toHaveLength(1);
    expect(filterEvents(events, { window: '7d', type: 'xss' }, NOW)).toHaveLength(1);
  });

  it('matches source IP as a substring and ignores surrounding whitespace', () => {
    expect(filterEvents(events, { window: '7d', ip: '  198.51  ' }, NOW)).toHaveLength(2);
    expect(filterEvents(events, { window: '7d', ip: '10.0' }, NOW)).toHaveLength(0);
  });

  it('excludes events dated in the future', () => {
    const future = [ev({ ago: -HOUR })];
    expect(filterEvents(future, { window: '24h' }, NOW)).toHaveLength(0);
  });

  it('returns everything in window with no criteria supplied', () => {
    expect(filterEvents(events, {}, NOW)).toHaveLength(2);
  });
});

describe('summarize', () => {
  it('counts totals, severities and distinct sources and countries', () => {
    const stats = summarize([
      ev({ type: 'ddos', ip: '1.1.1.1', country: 'Iran' }),
      ev({ type: 'ddos', ip: '1.1.1.1', country: 'Iran' }),
      ev({ type: 'brute_force', ip: '2.2.2.2', country: 'Brazil' }),
      ev({ type: 'xss', ip: '3.3.3.3', country: 'Brazil' })
    ]);
    expect(stats.total).toBe(4);
    expect(stats.bySeverity).toEqual({ low: 0, medium: 1, high: 1, critical: 2 });
    expect(stats.uniqueSources).toBe(3);
    expect(stats.uniqueCountries).toBe(2);
  });

  it('reports zeroes for an empty set rather than undefined', () => {
    expect(summarize([])).toEqual({
      total: 0,
      bySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
      uniqueSources: 0,
      uniqueCountries: 0
    });
  });
});

describe('bucketTimeline', () => {
  it('chooses a bucket size appropriate to the window', () => {
    expect(bucketSizeFor('1h')).toBe(5 * 60 * 1000);
    expect(bucketSizeFor('6h')).toBe(30 * 60 * 1000);
    expect(bucketSizeFor('24h')).toBe(HOUR);
    expect(bucketSizeFor('7d')).toBe(6 * HOUR);
    expect(bucketSizeFor('unknown')).toBe(HOUR);
  });

  it('returns a dense, strictly ascending series covering the window', () => {
    const buckets = bucketTimeline([], NOW, '24h');
    expect(buckets).toHaveLength(25); // 24 hourly buckets plus the current partial one
    for (let i = 1; i < buckets.length; i += 1) {
      expect(buckets[i].start).toBeGreaterThan(buckets[i - 1].start);
      expect(buckets[i].start - buckets[i - 1].start).toBe(HOUR);
    }
    expect(buckets.every((b) => b.total === 0)).toBe(true);
  });

  it('separates same-hour events on different days (the original hour-of-day bug)', () => {
    const events = [ev({ type: 'ddos', ago: 0 }), ev({ type: 'ddos', ago: 3 * 24 * HOUR })];
    const buckets = bucketTimeline(events, NOW, '7d');
    const populated = buckets.filter((b) => b.total > 0);
    expect(populated).toHaveLength(2);
    expect(populated[0].start).toBeLessThan(populated[1].start);
  });

  it('counts each event into exactly one bucket, by severity', () => {
    const events = [
      ev({ type: 'ddos', ago: 30 * 60 * 1000 }),
      ev({ type: 'brute_force', ago: 30 * 60 * 1000 }),
      ev({ type: 'port_scan', ago: 90 * 60 * 1000 })
    ];
    const buckets = bucketTimeline(events, NOW, '24h');
    expect(buckets.reduce((sum, b) => sum + b.total, 0)).toBe(3);
    const populated = buckets.filter((b) => b.total > 0);
    expect(populated).toHaveLength(2);
    expect(populated[1].counts).toMatchObject({ critical: 1, high: 1, low: 0 });
    expect(populated[0].counts.low).toBe(1);
  });

  it('keeps an event sitting exactly on the window edge', () => {
    const buckets = bucketTimeline([ev({ ago: 24 * HOUR })], NOW, '24h');
    expect(buckets.reduce((sum, b) => sum + b.total, 0)).toBe(1);
    expect(buckets[0].total).toBe(1);
  });

  it('drops events outside the window instead of clamping them into edge buckets', () => {
    const buckets = bucketTimeline([ev({ ago: 40 * 24 * HOUR })], NOW, '7d');
    expect(buckets.reduce((sum, b) => sum + b.total, 0)).toBe(0);
  });
});

describe('attackDistribution', () => {
  it('gives each detection type a stable colour regardless of which types are present', () => {
    const withAll = attackDistribution([ev({ type: 'ddos' }), ev({ type: 'xss' })]);
    const withOne = attackDistribution([ev({ type: 'xss' })]);
    const colorOf = (rows, type) => rows.find((r) => r.type === type).color;
    expect(colorOf(withAll, 'xss')).toBe(colorOf(withOne, 'xss'));
    expect(colorOf(withAll, 'xss')).toBe(TYPE_COLORS.xss);
  });

  it('sorts by count descending and resolves the rule display name', () => {
    const rows = attackDistribution([ev({ type: 'xss' }), ev({ type: 'ddos' }), ev({ type: 'ddos' })]);
    expect(rows.map((r) => r.type)).toEqual(['ddos', 'xss']);
    expect(rows[0].name).toBe('Volumetric Denial of Service');
    expect(rows[0].count).toBe(2);
  });

  it('returns an empty list for no events', () => {
    expect(attackDistribution([])).toEqual([]);
  });
});

describe('topSources', () => {
  it('ranks by deterministic threat score, not by a random number', () => {
    const events = [
      ...Array.from({ length: 5 }, () => ev({ type: 'port_scan', ip: '5.5.5.5' })),
      ev({ type: 'privilege_escalation', ip: '6.6.6.6' })
    ];
    const rows = topSources(events);
    expect(rows[0].ip).toBe('6.6.6.6');
    expect(rows[0].threatScore).toBeGreaterThan(rows[1].threatScore);
  });

  it('is stable across repeated calls on the same input', () => {
    const events = [ev({ ip: '7.7.7.7' }), ev({ type: 'xss', ip: '8.8.8.8' })];
    expect(topSources(events)).toEqual(topSources(events));
  });

  it('aggregates distinct types, tactics, max severity and last-seen per source', () => {
    const rows = topSources([
      ev({ type: 'port_scan', ip: '9.9.9.9', ago: 2 * HOUR }),
      ev({ type: 'data_exfiltration', ip: '9.9.9.9', ago: HOUR })
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      ip: '9.9.9.9',
      eventCount: 2,
      distinctTypes: 2,
      distinctTactics: 2,
      severity: 'critical',
      lastSeen: NOW - HOUR
    });
  });

  it('honours the limit', () => {
    const events = Array.from({ length: 20 }, (_, i) => ev({ ip: `203.0.113.${i + 1}` }));
    expect(topSources(events, 3)).toHaveLength(3);
    expect(topSources(events)).toHaveLength(8);
  });
});

describe('geoDistribution', () => {
  it('counts by country, highest first, breaking ties by name', () => {
    const rows = geoDistribution([
      ev({ country: 'Iran' }),
      ev({ country: 'Iran' }),
      ev({ country: 'Brazil' }),
      ev({ country: 'Algeria' })
    ]);
    expect(rows).toEqual([
      { country: 'Iran', count: 2 },
      { country: 'Algeria', count: 1 },
      { country: 'Brazil', count: 1 }
    ]);
  });

  it('honours the limit and handles an empty input', () => {
    expect(geoDistribution([], 5)).toEqual([]);
    expect(geoDistribution([ev({ country: 'A' }), ev({ country: 'B' })], 1)).toHaveLength(1);
  });
});

describe('TIME_WINDOWS', () => {
  it('exposes the four supported spans in ascending order', () => {
    const values = Object.values(TIME_WINDOWS);
    expect(values).toEqual([...values].sort((a, b) => a - b));
    expect(TIME_WINDOWS['7d']).toBe(7 * 24 * HOUR);
  });
});
