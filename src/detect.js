import { tokens } from './exec-shell.js';
/**
 * Filtering, aggregation and scoring over normalized events.
 * Pure: every function takes its inputs explicitly, including `now`.
 */

import { compareSeverity, computeThreatScore, getRule, SEVERITY_ORDER, TYPE_COLORS } from './rules.js';

/** Supported analysis windows, in milliseconds. */
export const TIME_WINDOWS = Object.freeze({
  '1h': 60 * 60 * 1000,
  '6h': 6 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000
});

/**
 * @param {Array<object>} events
 * @param {{ severity?: string, type?: string, ip?: string, window?: string }} criteria
 * @param {number} now epoch ms
 */
export function filterEvents(events, criteria = {}, now = Date.now()) {
  const { severity = 'all', type = 'all', ip = '', window = '24h' } = criteria;
  const span = TIME_WINDOWS[window] ?? TIME_WINDOWS['24h'];
  const cutoff = now - span;
  const needle = ip.trim();

  return events.filter((event) => {
    if (severity !== 'all' && event.severity !== severity) return false;
    if (type !== 'all' && event.type !== type) return false;
    if (needle && !event.sourceIp.includes(needle)) return false;
    if (event.timestamp < cutoff || event.timestamp > now) return false;
    return true;
  });
}

/**
 * Headline counts for the KPI strip and the report header.
 * @param {Array<object>} events
 */
export function summarize(events) {
  const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  const sources = new Set();
  const countries = new Set();

  for (const event of events) {
    if (event.severity in bySeverity) bySeverity[event.severity] += 1;
    sources.add(event.sourceIp);
    countries.add(event.country);
  }

  return {
    total: events.length,
    bySeverity,
    uniqueSources: sources.size,
    uniqueCountries: countries.size
  };
}

/**
 * Pick a bucket size that yields a readable number of points for a window.
 * @param {string} windowKey
 * @returns {number} bucket width in ms
 */
export function bucketSizeFor(windowKey) {
  switch (windowKey) {
    case '1h':
      return 5 * 60 * 1000;
    case '6h':
      return 30 * 60 * 1000;
    case '7d':
      return 6 * 60 * 60 * 1000;
    case '24h':
    default:
      return 60 * 60 * 1000;
  }
}

/**
 * Chronological severity timeline.
 *
 * The original demo bucketed by `getHours()` alone, so 09:00 on Monday and
 * 09:00 on Thursday landed in the same bucket and the x-axis was ordered by
 * hour-of-day rather than by time. This buckets on absolute epoch boundaries
 * and always returns a dense, ascending series covering the whole window —
 * empty buckets included, so gaps read as gaps instead of disappearing.
 *
 * @param {Array<object>} events
 * @param {number} now epoch ms
 * @param {string} windowKey
 * @returns {{ start: number, counts: Record<string, number>, total: number }[]}
 */
export function bucketTimeline(events, now, windowKey = '24h') {
  const span = TIME_WINDOWS[windowKey] ?? TIME_WINDOWS['24h'];
  const size = bucketSizeFor(windowKey);
  // `end` is the bucket that contains `now`; `start` is a full `span` earlier,
  // so an event exactly at the window edge still lands in bucket 0 rather than
  // being dropped by an off-by-one.
  const end = Math.floor(now / size) * size;
  const start = end - span;
  const bucketCount = Math.round(span / size) + 1;

  const buckets = [];
  for (let i = 0; i < bucketCount; i += 1) {
    buckets.push({
      start: start + i * size,
      counts: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])),
      total: 0
    });
  }

  for (const event of events) {
    const index = Math.floor((event.timestamp - start) / size);
    if (index < 0 || index >= buckets.length) continue;
    const bucket = buckets[index];
    if (event.severity in bucket.counts) bucket.counts[event.severity] += 1;
    bucket.total += 1;
  }

  return buckets;
}

/**
 * Attack-type distribution with a stable colour per type.
 * The original demo assigned colours positionally, so a type's colour changed
 * whenever the set of present types changed.
 *
 * @param {Array<object>} events
 */
export function attackDistribution(events) {
  const counts = new Map();
  for (const event of events) {
    counts.set(event.type, (counts.get(event.type) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([type, count]) => ({
      type,
      name: getRule(type)?.name ?? type,
      count,
      color: TYPE_COLORS[type] ?? tokens().muted
    }))
    .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type));
}

/**
 * Aggregate per source IP and rank by a deterministic threat score.
 *
 * @param {Array<object>} events
 * @param {number} [limit=8]
 */
export function topSources(events, limit = 8) {
  /** @type {Map<string, {ip:string,country:string,eventCount:number,types:Set<string>,tactics:Set<string>,severity:string,lastSeen:number}>} */
  const bySource = new Map();

  for (const event of events) {
    let row = bySource.get(event.sourceIp);
    if (!row) {
      row = {
        ip: event.sourceIp,
        country: event.country,
        eventCount: 0,
        types: new Set(),
        tactics: new Set(),
        severity: 'low',
        lastSeen: 0
      };
      bySource.set(event.sourceIp, row);
    }
    row.eventCount += 1;
    row.types.add(event.type);
    row.tactics.add(event.tactic);
    if (compareSeverity(event.severity, row.severity) > 0) row.severity = event.severity;
    if (event.timestamp > row.lastSeen) row.lastSeen = event.timestamp;
  }

  return [...bySource.values()]
    .map((row) => ({
      ip: row.ip,
      country: row.country,
      eventCount: row.eventCount,
      distinctTypes: row.types.size,
      distinctTactics: row.tactics.size,
      severity: row.severity,
      lastSeen: row.lastSeen,
      threatScore: computeThreatScore({
        severity: row.severity,
        eventCount: row.eventCount,
        distinctTypes: row.types.size,
        distinctTactics: row.tactics.size
      })
    }))
    .sort(
      (a, b) =>
        b.threatScore - a.threatScore ||
        b.eventCount - a.eventCount ||
        a.ip.localeCompare(b.ip)
    )
    .slice(0, limit);
}

/**
 * Event counts by origin country, highest first.
 * @param {Array<object>} events @param {number} [limit=8]
 */
export function geoDistribution(events, limit = 8) {
  const counts = new Map();
  for (const event of events) {
    counts.set(event.country, (counts.get(event.country) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count || a.country.localeCompare(b.country))
    .slice(0, limit);
}
