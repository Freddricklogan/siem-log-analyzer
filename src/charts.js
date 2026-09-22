import { tokens } from './exec-shell.js';
/**
 * Chart.js binding layer (DOM-facing).
 *
 * Chart.js is loaded from jsDelivr, version-pinned with an SRI hash. If the CDN
 * is unreachable — offline, a locked-down corporate proxy, CI — this module
 * falls back to the byte-identical copy vendored at `vendor/chart.min.js`, so
 * the demo never degrades to a blank dashboard. See ADR-3 in the README.
 */

const VENDOR_FALLBACK = 'vendor/chart.min.js';

const AXIS_COLOR = tokens().muted;
const GRID_COLOR = 'rgba(34, 48, 77, 0.8)';

const SEVERITY_SERIES = [
  { key: 'critical', label: 'Critical', color: tokens().danger },
  { key: 'high', label: 'High', color: tokens().warn },
  { key: 'medium', label: 'Medium', color: tokens().accent },
  { key: 'low', label: 'Low', color: tokens().muted }
];

let loadPromise = null;

/** Inject a local script tag and resolve once it has executed. */
function injectFallback() {
  return new Promise((resolve, reject) => {
    const tag = document.createElement('script');
    tag.src = VENDOR_FALLBACK;
    tag.addEventListener('load', () => resolve());
    tag.addEventListener('error', () => reject(new Error('vendored Chart.js failed to load')));
    document.head.append(tag);
  });
}

/**
 * Resolve to the global `Chart` constructor, loading the vendored fallback if
 * the CDN copy is absent. Resolves to `null` when charting is unavailable, so
 * callers can degrade gracefully instead of throwing.
 *
 * @returns {Promise<any|null>}
 */
export function loadChartLibrary() {
  if (loadPromise) return loadPromise;
  loadPromise = (async () => {
    if (typeof window !== 'undefined' && window.Chart) return window.Chart;
    try {
      await injectFallback();
    } catch {
      return null;
    }
    return (typeof window !== 'undefined' && window.Chart) || null;
  })();
  return loadPromise;
}

/** @param {number} ms @param {string} windowKey */
function bucketLabel(ms, windowKey) {
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  if (windowKey === '7d') {
    return `${d.getMonth() + 1}/${d.getDate()} ${hh}:00`;
  }
  return `${hh}:${mm}`;
}

/**
 * Build the two dashboard charts. Returns a controller with `update()` and
 * `destroy()`, or a no-op controller when Chart.js is unavailable.
 *
 * @param {{ timelineCanvas: HTMLCanvasElement, distributionCanvas: HTMLCanvasElement }} targets
 */
export async function createCharts(targets) {
  const Chart = await loadChartLibrary();
  if (!Chart) {
    return { available: false, update() {}, destroy() {} };
  }

  const timeline = new Chart(targets.timelineCanvas, {
    type: 'line',
    data: {
      labels: [],
      datasets: SEVERITY_SERIES.map((s) => ({
        label: s.label,
        data: [],
        borderColor: s.color,
        backgroundColor: `${s.color}33`,
        borderWidth: 2,
        pointRadius: 0,
        fill: true,
        tension: 0.25
      }))
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { labels: { color: AXIS_COLOR, boxWidth: 12, font: { size: 11 } } } },
      scales: {
        x: {
          stacked: true,
          ticks: { color: AXIS_COLOR, maxTicksLimit: 10, font: { size: 10 } },
          grid: { color: GRID_COLOR }
        },
        y: {
          stacked: true,
          beginAtZero: true,
          ticks: { color: AXIS_COLOR, precision: 0, font: { size: 10 } },
          grid: { color: GRID_COLOR }
        }
      }
    }
  });

  const distribution = new Chart(targets.distributionCanvas, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: AXIS_COLOR, boxWidth: 12, padding: 10, font: { size: 11 } }
        }
      }
    }
  });

  return {
    available: true,
    /**
     * @param {{ buckets: Array<object>, windowKey: string, distribution: Array<object> }} data
     */
    update({ buckets, windowKey, distribution: dist }) {
      timeline.data.labels = buckets.map((b) => bucketLabel(b.start, windowKey));
      SEVERITY_SERIES.forEach((series, i) => {
        timeline.data.datasets[i].data = buckets.map((b) => b.counts[series.key]);
      });
      timeline.update('none');

      distribution.data.labels = dist.map((d) => d.name);
      distribution.data.datasets[0].data = dist.map((d) => d.count);
      distribution.data.datasets[0].backgroundColor = dist.map((d) => d.color);
      distribution.update('none');
    },
    destroy() {
      timeline.destroy();
      distribution.destroy();
    }
  };
}
