# Case Study — SIEM Log Analyzer

**Repository:** [siem-log-analyzer](https://github.com/Freddricklogan/siem-log-analyzer) · **Live demo:** [freddricklogan.github.io/siem-log-analyzer](https://freddricklogan.github.io/siem-log-analyzer/) · **Author:** Freddrick Logan

---

## 1. Who has this problem

A security lead at a mid-sized university or public agency who inherited a log pipeline but not a detection strategy. The SIEM licence is paid for, the logs are flowing, and the dashboard shows thousands of events a day — yet nobody on the team can say which of those events would matter if an attacker were inside the network right now. The same situation exists at any organisation whose security function is two or three people wearing several hats.

## 2. The problem, as a scenario

It is 4:40 on a Friday. An analyst sees a burst of failed logins from a single external address, followed by one success, followed by a PowerShell process on a finance workstation. Each event is visible. None of them is connected to the others. The analyst has to hold the sequence in her head, decide whether it is a kill chain or three coincidences, and explain the decision to a director who does not read logs. The SIEM has a rule for brute force and a rule for suspicious PowerShell, but no concept that the two belong to one incident, and no shared vocabulary — such as MITRE ATT&CK — for saying what stage the attacker has reached.

## 3. What it costs to leave it alone

Slow detection is the expensive part of a breach. Industry studies that track time-to-identify and time-to-contain, such as IBM's annual *Cost of a Data Breach* report ([ibm.com/reports/data-breach](https://www.ibm.com/reports/data-breach)) and Verizon's *Data Breach Investigations Report* ([verizon.com/business/resources/reports/dbir](https://www.verizon.com/business/resources/reports/dbir/)), consistently show that incidents discovered late cost materially more than those caught early, and that credential abuse remains among the most common initial paths in. For a university the exposure is concrete: student records, research data, and federal compliance obligations. Alert fatigue compounds this — analysts who see hundreds of uncorrelated alerts learn to ignore them, and the one that matters gets ignored with the rest.

## 4. The approach, and the alternative I rejected

I built a detection-engineering sandbox that runs entirely in the browser: events are normalised, scored against detection rules, mapped to ATT&CK techniques, and then correlated into multi-stage incidents. The user can change the rules, watch the incident count move, and export an incident report an executive can read.

The alternative was to wire a real log source to a hosted back end. I rejected it for this project for two reasons. First, a portfolio demo that needs credentials or a running server is a demo nobody opens. Second, the hard part of this problem is not ingestion — commercial SIEMs already do that well — it is the detection and correlation logic, and that logic can be exercised faithfully on synthetic telemetry. Keeping it client-side also meant the demo could be secured properly: a strict Content Security Policy, pinned dependencies with integrity hashes, no inline scripts.

## 5. What the code does today

Real: the normalisation pipeline, eight detection rules, six correlation rules, the ATT&CK technique mapping, severity scoring, time-bucketed trend analysis, filtering, and incident export. All of it is unit-tested pure logic separated from the rendering layer.

Simulated: the telemetry. Every event is produced by a seeded pseudo-random generator so runs are reproducible; there is no ingestion pipeline and no real network data. The page says so on screen.

Worth knowing: rebuilding this exposed three defects in the earlier version — the threat score was a random number rather than a computed one, the timeline bucketed by hour-of-day so events from different days collapsed together, and an off-by-one dropped events at the window edge. All three are fixed and covered by tests, and the full list is in the repository's audit file.

## 6. Evidence

Measured in continuous integration on the current main branch: 95 unit tests passing, 99.8% statement coverage, lint and HTML validation clean, CodeQL and dependency scanning enabled. Headless-browser smoke test: zero console errors, guided tour opens and closes correctly. Security posture: Content Security Policy with `default-src 'none'`, Subresource Integrity on the one external library, and a vendored fallback so the page still works if the CDN is unreachable.

## 7. What it would take to run this in production

The detection and correlation core is the reusable part. To operate it for real, an organisation would need: a log source (syslog, Windows Event Forwarding, or a cloud provider's audit trail) and a normaliser for that schema; a rule format — I would adopt Sigma ([sigmahq.io](https://sigmahq.io)) rather than keep a bespoke one; a persistence layer for incidents; authentication and role separation between analysts and viewers; and alert routing to a ticketing or chat tool. For a small team on a single log source, that is a focused engagement measured in weeks, not quarters, because the judgement-heavy logic already exists and is tested.

## 8. Limits and next steps

The rule set is small and illustrative, not a production catalogue. Correlation is rule-based and does not learn from analyst feedback. Telemetry volume is demo-scale; a real deployment would need streaming evaluation rather than in-memory batches. Planned next steps are Sigma rule import, an OpenTelemetry log format, and a WebAssembly parser for large files.

## 9. Who should look at this

**Hiring manager:** evidence that I can take a security concept from idea to a tested, secured, documented artefact without a team behind me.
**Consulting client:** a working conversation-starter for "what should our detections actually be?" — bring your own scenarios and we can model them here before touching your SIEM.
**Engineer:** read `src/` for the pure detection and correlation logic and `tests/` for how it is verified; the audit file shows what a careful review of a demo codebase looks like.
