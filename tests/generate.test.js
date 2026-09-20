import { describe, expect, it } from 'vitest';
import {
  generateEvents,
  isReservedIpv4,
  mulberry32,
  pick,
  randomPublicIpv4
} from '../src/generate.js';
import { ATTACK_TYPES } from '../src/rules.js';

describe('mulberry32', () => {
  it('produces the same sequence for the same seed', () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    expect([a(), a(), a()]).toEqual([b(), b(), b()]);
  });

  it('produces a different sequence for a different seed', () => {
    expect(mulberry32(1)()).not.toBe(mulberry32(2)());
  });

  it('stays inside [0, 1)', () => {
    const rng = mulberry32(7);
    for (let i = 0; i < 500; i += 1) {
      const v = rng();
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1);
    }
  });
});

describe('isReservedIpv4', () => {
  it.each([
    '10.0.0.1',
    '127.0.0.1',
    '172.16.5.4',
    '172.31.255.254',
    '192.168.1.1',
    '169.254.10.1',
    '100.64.0.1',
    '198.18.0.1',
    '0.1.2.3',
    '224.0.0.1',
    '255.255.255.255'
  ])('rejects reserved address %s', (ip) => {
    expect(isReservedIpv4(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '203.0.113.7', '198.51.100.9', '172.32.0.1', '100.128.0.1'])(
    'accepts routable address %s',
    (ip) => {
      expect(isReservedIpv4(ip)).toBe(false);
    }
  );

  it('rejects malformed input', () => {
    expect(isReservedIpv4('not-an-ip')).toBe(true);
    expect(isReservedIpv4('1.2.3')).toBe(true);
    expect(isReservedIpv4('1.2.3.300')).toBe(true);
  });
});

describe('randomPublicIpv4', () => {
  it('never returns a reserved address across many draws', () => {
    const rng = mulberry32(2026);
    for (let i = 0; i < 2000; i += 1) {
      expect(isReservedIpv4(randomPublicIpv4(rng))).toBe(false);
    }
  });

  it('falls back to TEST-NET-3 when the generator only yields reserved space', () => {
    // rng() === 0 => 1.0.0.1 is routable, so force the loopback band instead.
    const stuck = () => 127 / 223;
    expect(randomPublicIpv4(stuck)).toBe('203.0.113.7');
  });
});

describe('pick', () => {
  it('selects by index derived from the generator', () => {
    expect(pick(['a', 'b', 'c', 'd'], () => 0)).toBe('a');
    expect(pick(['a', 'b', 'c', 'd'], () => 0.99)).toBe('d');
  });
});

describe('generateEvents', () => {
  const now = Date.parse('2026-03-01T12:00:00.000Z');

  it('is reproducible for a given seed and clock', () => {
    const a = generateEvents({ count: 50, now, rng: mulberry32(99) });
    const b = generateEvents({ count: 50, now, rng: mulberry32(99) });
    expect(a).toEqual(b);
  });

  it('emits the requested number of events, newest first', () => {
    const events = generateEvents({ count: 120, now, rng: mulberry32(5) });
    expect(events).toHaveLength(120);
    for (let i = 1; i < events.length; i += 1) {
      expect(events[i - 1].timestamp).toBeGreaterThanOrEqual(events[i].timestamp);
    }
  });

  it('keeps every timestamp inside the requested window', () => {
    const windowMs = 60 * 60 * 1000;
    const events = generateEvents({ count: 200, now, windowMs, rng: mulberry32(11) });
    for (const e of events) {
      expect(e.timestamp).toBeLessThanOrEqual(now);
      expect(e.timestamp).toBeGreaterThanOrEqual(now - windowMs);
    }
  });

  it('emits only known attack types with routable source addresses', () => {
    const events = generateEvents({ count: 400, now, rng: mulberry32(13) });
    for (const e of events) {
      expect(ATTACK_TYPES).toContain(e.type);
      expect(isReservedIpv4(e.sourceIp)).toBe(false);
      expect(e.severity).toBeTruthy();
      expect(e.technique).toMatch(/^T\d{4}$/);
    }
  });

  it('produces multi-vector campaign actors rather than relying on random collisions', () => {
    const events = generateEvents({ count: 400, now, rng: mulberry32(17), campaignActors: 4 });
    const typesByIp = new Map();
    for (const e of events) {
      if (!typesByIp.has(e.sourceIp)) typesByIp.set(e.sourceIp, new Set());
      typesByIp.get(e.sourceIp).add(e.type);
    }
    const multiVector = [...typesByIp.values()].filter((s) => s.size >= 3);
    expect(multiVector.length).toBeGreaterThanOrEqual(1);
  });

  it('produces no campaign actors when asked for none', () => {
    const events = generateEvents({ count: 60, now, rng: mulberry32(3), campaignActors: 0 });
    expect(events).toHaveLength(60);
  });

  it('returns an empty array for a count of zero', () => {
    expect(generateEvents({ count: 0, now, rng: mulberry32(1) })).toEqual([]);
  });
});
