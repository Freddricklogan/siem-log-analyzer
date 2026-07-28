<h1 align="center">SIEM Log Analyzer</h1>

<p align="center">
  <em>A security operations dashboard for real-time threat detection — log correlation, MITRE ATT&CK mapping, and alert triage.</em>
</p>

<p align="center">
  <a href="https://freddricklogan.github.io/siem-log-analyzer/"><img src="https://img.shields.io/badge/Live_Demo-Open_App-e63946?style=for-the-badge&logo=github" alt="Live Demo"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Domain-Security_Operations-1d3557" alt="SecOps">
  <img src="https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/badge/JavaScript-Vanilla_ES6-f7df1e?logo=javascript&logoColor=black" alt="JavaScript">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License">
</p>

---

## Overview

**SIEM Log Analyzer** is an interactive Security Information and Event Management dashboard that
simulates the day-to-day of a Security Operations Center: streaming logs are parsed, correlated into
alerts, scored by severity, and mapped to adversary techniques in the **MITRE ATT&CK** framework so an
analyst can move from raw noise to an actionable incident quickly.

It demonstrates the analytical workflow behind threat detection — not just a pretty dashboard, but the
correlation logic and framing (kill-chain, ATT&CK tactics/techniques) that real detection engineering
depends on.

> **▶ [Launch the live demo](https://freddricklogan.github.io/siem-log-analyzer/)**

---

## Why this project

| Skill demonstrated | Where it shows up |
|:--|:--|
| **Security operations / blue team** | SOC-style alerting, triage, and incident correlation |
| **Threat intelligence framing** | Detections mapped to MITRE ATT&CK tactics and techniques |
| **Detection logic** | Rule-based correlation of events into prioritized alerts |
| **Data visualization** | Real-time severity, volume, and trend charts |
| **Front-end engineering** | Responsive, dependency-light dashboard |

---

## Features

- Real-time log ingestion and event stream
- Rule-based **alert correlation** with severity scoring
- **MITRE ATT&CK** technique mapping for detected activity
- Incident timeline and triage view
- Live charts for alert volume, severity distribution, and trends

---

## Tech stack

- **Language:** Vanilla JavaScript (ES6+)
- **Visualization:** Chart.js
- **Runtime:** 100% client-side — no backend, no install

---

## Run locally

```bash
git clone https://github.com/Freddricklogan/siem-log-analyzer.git
cd siem-log-analyzer
python3 -m http.server 8000
# then visit http://localhost:8000
```

---

## Author

**Freddrick Logan** — Educational Technologist & Technology Leader
[GitHub](https://github.com/Freddricklogan) · [LinkedIn](https://www.linkedin.com/in/freddricklogan/)

## License

Released under the [MIT License](LICENSE).
