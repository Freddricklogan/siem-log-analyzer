/**
 * Synthetic log generation.
 *
 * Everything is injectable: the clock (`now`) and the random source (`rng`).
 * That makes generated batches reproducible in tests and in the demo, and it
 * keeps this module free of `Date.now()` / `Math.random()` side effects.
 */

import { DETECTION_RULES, getRule } from './rules.js';

/**
 * Small, fast, seedable PRNG (mulberry32). Deterministic across engines.
 * @param {number} seed
 * @returns {() => number} uniform in [0, 1)
 */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const COUNTRIES = [
  'United States', 'China', 'Russia', 'Brazil', 'India', 'Germany', 'Iran',
  'Netherlands', 'Romania', 'Nigeria', 'Ukraine', 'Vietnam', 'Indonesia',
  'Turkey', 'South Korea'
];

/**
 * IPv4 ranges that must never be presented as an external attacker: RFC1918
 * private space, loopback, link-local, CGNAT, multicast/reserved, and 0.0.0.0/8.
 * The original demo happily labelled 127.x and 10.x addresses as foreign threats.
 *
 * @param {string} ip dotted-quad
 * @returns {boolean}
 */
export function isReservedIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts;
  if (a === 0 || a === 127 || a >= 224) return true;          // this-net, loopback, multicast/reserved
  if (a === 10) return true;                                   // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true;            // 172.16.0.0/12
  if (a === 192 && b === 168) return true;                     // 192.168.0.0/16
  if (a === 169 && b === 254) return true;                     // 169.254.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true;           // 100.64.0.0/10 CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true;        // benchmarking
  return false;
}

/**
 * Draw a routable public IPv4 address.
 * @param {() => number} rng
 */
export function randomPublicIpv4(rng) {
  for (let attempt = 0; attempt < 64; attempt += 1) {
    const ip = [
      1 + Math.floor(rng() * 222),
      Math.floor(rng() * 256),
      Math.floor(rng() * 256),
      1 + Math.floor(rng() * 254)
    ].join('.');
    if (!isReservedIpv4(ip)) return ip;
  }
  return '203.0.113.7'; // TEST-NET-3 fallback; deterministic, never reserved
}

/** @param {any[]} arr @param {() => number} rng */
export function pick(arr, rng) {
  return arr[Math.floor(rng() * arr.length)];
}

/**
 * Generate a batch of normalized security events.
 *
 * A fraction of sources are "campaign" actors that emit several attack types
 * from one IP, so the correlation engine has something real to find instead of
 * relying on random collisions between 500 events and 2^32 possible addresses.
 *
 * @param {object} [options]
 * @param {number} [options.count=320]     Number of events to emit.
 * @param {number} [options.now]           Epoch ms treated as "now".
 * @param {number} [options.windowMs]      How far back events are spread.
 * @param {() => number} [options.rng]     Random source.
 * @param {number} [options.campaignActors=4] Number of multi-vector source IPs.
 * @returns {Array<{
 *   id: string, timestamp: number, type: string, name: string, ruleId: string,
 *   severity: string, technique: string, tactic: string, message: string,
 *   sourceIp: string, source: string, country: string, destinationPort: number
 * }>} Sorted newest first.
 */
export function generateEvents(options = {}) {
  const {
    count = 320,
    now = 0,
    windowMs = 24 * 60 * 60 * 1000,
    rng = Math.random,
    campaignActors = 4
  } = options;

  const actors = [];
  for (let i = 0; i < campaignActors; i += 1) {
    actors.push({
      ip: randomPublicIpv4(rng),
      country: pick(COUNTRIES, rng),
      // Each campaign actor follows a plausible kill chain.
      chain: pick(
        [
          ['port_scan', 'sql_injection', 'privilege_escalation', 'data_exfiltration'],
          ['brute_force', 'privilege_escalation', 'malware_c2'],
          ['port_scan', 'xss', 'malware_c2'],
          ['brute_force', 'ddos']
        ],
        rng
      )
    });
  }

  const events = [];
  for (let i = 0; i < count; i += 1) {
    const useActor = actors.length > 0 && rng() < 0.28;
    let rule;
    let sourceIp;
    let country;

    if (useActor) {
      const actor = pick(actors, rng);
      rule = getRule(pick(actor.chain, rng));
      sourceIp = actor.ip;
      country = actor.country;
    } else {
      rule = pick(DETECTION_RULES, rng);
      sourceIp = randomPublicIpv4(rng);
      country = pick(COUNTRIES, rng);
    }

    events.push({
      id: `evt-${now.toString(36)}-${i.toString(36)}`,
      timestamp: Math.round(now - rng() * windowMs),
      type: rule.type,
      name: rule.name,
      ruleId: rule.id,
      severity: rule.severity,
      technique: rule.mitre.technique,
      tactic: rule.mitre.tactic,
      message: pick(rule.messages, rng),
      sourceIp,
      source: pick(rule.sources, rng),
      country,
      destinationPort: pick([22, 25, 53, 80, 389, 443, 445, 3306, 3389, 8080], rng)
    });
  }

  return events.sort((a, b) => b.timestamp - a.timestamp);
}
