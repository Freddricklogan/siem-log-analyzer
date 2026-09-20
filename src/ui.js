/**
 * Rendering layer. The only module allowed to touch the DOM directly.
 *
 * Everything is built with `createElement` + `textContent`; no interpolated
 * `innerHTML` anywhere, so no string can ever be re-parsed as markup.
 */

/** @param {string} tag @param {object} [props] @param {Array<Node|string|null>} [kids] */
function el(tag, props = {}, kids = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = String(value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
}

/** @param {HTMLElement} host @param {Node[]} nodes */
function replace(host, nodes) {
  host.replaceChildren(...nodes);
}

/** @param {string} severity */
export function severityChip(severity) {
  return el('span', { class: `severity severity--${severity}`, text: severity });
}

/** @param {number} ms */
function clockTime(ms) {
  const d = new Date(ms);
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((n) => String(n).padStart(2, '0'))
    .join(':');
}

/** @param {HTMLElement} host @param {Array<{country:string,count:number}>} rows */
export function renderGeo(host, rows) {
  if (!rows.length) {
    replace(host, [el('p', { class: 'empty', text: 'No events in the selected window.' })]);
    return;
  }
  replace(
    host,
    rows.map((row) =>
      el('div', { class: 'geo__cell' }, [
        el('div', { class: 'geo__count', text: row.count }),
        el('div', { class: 'geo__name', text: row.country })
      ])
    )
  );
}

/** @param {HTMLElement} host @param {Array<object>} rows */
export function renderTopSources(host, rows) {
  if (!rows.length) {
    replace(host, [
      el('tr', {}, [el('td', { colspan: '5', class: 'empty', text: 'No sources in window.' })])
    ]);
    return;
  }
  replace(
    host,
    rows.map((row) =>
      el('tr', {}, [
        el('td', { class: 'mono', text: row.ip }),
        el('td', { text: row.country }),
        el('td', { text: row.eventCount }),
        el('td', { text: row.threatScore }),
        el('td', {}, [severityChip(row.severity)])
      ])
    )
  );
}

/** @param {HTMLElement} host @param {Array<object>} matrix */
export function renderMitre(host, matrix) {
  if (!matrix.length) {
    replace(host, [el('p', { class: 'empty', text: 'No techniques observed in this window.' })]);
    return;
  }
  replace(
    host,
    matrix.map((tactic) =>
      el('div', { class: 'tactic' }, [
        el('div', { class: 'tactic__name', text: `${tactic.tactic} · ${tactic.count} events` }),
        ...tactic.techniques.map((t) =>
          el('div', { class: 'technique' }, [
            el('span', { class: 'technique__id', text: t.id }),
            el('span', { text: t.name }),
            el('span', { class: 'technique__count', text: `${t.count}` })
          ])
        )
      ])
    )
  );
}

/** @param {HTMLElement} host @param {Array<object>} findings */
export function renderCorrelations(host, findings) {
  if (!findings.length) {
    replace(host, [
      el('p', {
        class: 'empty',
        text: 'No multi-event correlations fired. Widen the filters or ingest another batch.'
      })
    ]);
    return;
  }
  replace(
    host,
    findings.map((f) =>
      el('article', { class: `finding finding--${f.severity}` }, [
        el('div', { class: 'finding__head' }, [
          severityChip(f.severity),
          el('h3', { class: 'finding__title', text: `${f.rule} — ${f.title}` })
        ]),
        el('p', { class: 'finding__detail', text: f.detail }),
        f.evidence.length
          ? el(
              'ul',
              { class: 'finding__evidence' },
              f.evidence.map((line) => el('li', { text: line }))
            )
          : null
      ])
    )
  );
}

/** @param {HTMLElement} host @param {Array<object>} events @param {number} [limit=60] */
export function renderFeed(host, events, limit = 60) {
  if (!events.length) {
    replace(host, [el('p', { class: 'empty', text: 'No events match the current filters.' })]);
    return;
  }
  replace(
    host,
    events.slice(0, limit).map((e) =>
      el('div', { class: 'feed__row' }, [
        el('span', { class: 'feed__time', text: clockTime(e.timestamp) }),
        severityChip(e.severity),
        el('span', { class: 'feed__source', text: e.source }),
        el('span', { class: 'feed__msg' }, [
          `${e.message} `,
          el('span', { class: 'feed__ip', text: `[${e.sourceIp}:${e.destinationPort}]` })
        ])
      ])
    )
  );
}

/** @param {HTMLElement} host @param {string} report */
export function renderReport(host, report) {
  host.textContent = report;
}
