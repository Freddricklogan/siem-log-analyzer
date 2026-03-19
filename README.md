# SIEM Log Analyzer

An interactive Security Information and Event Management dashboard for real-time threat detection, log analysis, and incident correlation. Built as a single-page application with no backend dependencies.

## Features

### Threat Detection & Classification
- Real-time analysis of simulated security events across six attack categories
- Severity classification: Critical, High, Medium, Low
- Attack types: Brute Force, SQL Injection, XSS, Port Scanning, DDoS, Privilege Escalation

### Interactive Dashboard
- **Threat Timeline** — Event frequency over time, segmented by severity
- **Attack Distribution** — Breakdown of attack types with interactive charts
- **Geographic Origins** — Threat source countries ranked by event volume
- **Top Attacking IPs** — Source IPs ranked by threat score with severity indicators

### MITRE ATT&CK Mapping
- Automatic mapping of detected threats to MITRE ATT&CK techniques
- Tactic classification (Initial Access, Credential Access, Discovery, etc.)
- Event counts per technique for prioritization

### Alert Correlation Engine
- Groups related events across multiple dimensions
- Detects multi-vector attacks from single sources
- Identifies credential compromise chains (brute force + privilege escalation)
- Correlates distributed attack patterns

### Filtering & Analysis
- Filter by severity, attack type, source IP, and time range
- Real-time dashboard updates as filters change
- Live event feed with color-coded severity indicators

### Incident Reporting
- Export formatted incident reports with executive summary
- Attack breakdown with MITRE technique references
- Top threat sources with geographic attribution
- Actionable remediation recommendations

## Technologies

- **JavaScript** — Event generation, correlation engine, and analytics
- **Chart.js** — Timeline and distribution visualizations
- **HTML5/CSS3** — Responsive dashboard layout
- **Client-Side Only** — No server or database required

## How to Use

1. Open `index.html` in any modern browser
2. Click **Generate Sample Data** to create realistic security events
3. Use the filter controls to drill down by severity, attack type, IP, or time range
4. Review the correlation engine for grouped threat patterns
5. Click **Export Report** to generate a formatted incident summary

## Use Cases

- **Security Operations** — SOC analyst training and workflow demonstration
- **Incident Response** — Practice threat triage and correlation analysis
- **Security Education** — Teaching SIEM concepts and the MITRE ATT&CK framework
- **Portfolio Demonstration** — Showcase security analytics and visualization skills

## License

MIT License
