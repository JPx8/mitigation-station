# Mitigation Station

> AI-powered SOC triage assistant that maps security alerts to MITRE ATT&CK techniques and generates prioritized remediation playbooks.

Paste any security alert — from Microsoft Sentinel, SentinelOne, Splunk, raw logs, or an EDR dashboard — and get back a structured threat report with technique mapping, IOC extraction, VirusTotal lookups, threat intelligence, and a one-click PDF export.

Part of the [MS Sentinel SOC Lab](https://github.com/JPx8/ms-sentinel-soc-lab) project.

---

## Features

- **Alert Analysis** — Claude extracts incident metadata (user, device, timestamp) and identifies MITRE ATT&CK techniques with confidence ratings
- **Overview Dashboard** — Severity badge, threat name, technique count, and executive summary at a glance
- **IOC Extraction** — Hashes, IPs, domains, and processes pulled from the alert body
- **VirusTotal Integration** — Live malicious/total scores when a VT API key is provided, direct search links otherwise
- **MITRE ATT&CK Context** — Official detection guidance and mitigations from the ATT&CK framework for every technique
- **AI Remediation Checklists** — Immediate / Short-Term / Long-Term action items per technique with KQL detection rules
- **Threat-Specific Remediation** — Steps tailored to the exact threat (not generic MITRE advice)
- **Threat Intelligence** — Background, scale, targeted industries, and OSINT links
- **PDF Export** — Formatted threat report ready to share with your team

## Tech Stack

- **UI:** Streamlit
- **AI:** Anthropic Claude (`claude-sonnet-4-6`)
- **Threat Intel:** MITRE ATT&CK Enterprise framework
- **IOC Enrichment:** VirusTotal API v3
- **PDF:** ReportLab

## Quick Start

### 1. Clone and install
```bash
git clone https://github.com/JPx8/mitigation-station
cd mitigation-station
pip install -r requirements.txt
```

### 2. Download MITRE ATT&CK data (~44MB)
```bash
# PowerShell
Invoke-WebRequest "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" -OutFile "data\enterprise-attack.json"

# bash / zsh
curl -L https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -o data/enterprise-attack.json
```

### 3. Get API keys
- **Anthropic (required):** [console.anthropic.com](https://console.anthropic.com) → API Keys → Create Key
- **VirusTotal (optional):** [virustotal.com](https://virustotal.com) → sign up → profile → API Key

### 4. Run
```bash
python -m streamlit run src/app.py
```

Opens at **http://localhost:8501** — paste your Anthropic key in the sidebar, drop in an alert, click **Analyze**.

## Project Structure

```
mitigation-station/
├── src/
│   ├── app.py              # Streamlit UI
│   ├── claude_analyzer.py  # Claude API integration
│   ├── mitre_loader.py     # MITRE ATT&CK indexer
│   └── pdf_generator.py    # PDF report generator
├── data/
│   └── enterprise-attack.json  # MITRE data (download separately)
├── assets/
├── requirements.txt
├── .env.example
└── README.md
```

## Example Workflow

1. **Paste alert** into the main text box (or click *Load Example Alert*)
2. **Analyze** — Claude extracts metadata, techniques, IOCs, and severity
3. **Review Overview** — User, device, time of incident, severity, threat name
4. **Check IOCs** — click VirusTotal links to pivot on hashes and IPs
5. **Expand MITRE techniques** — color-coded by confidence (red → high, yellow → medium, green → low)
6. **Follow remediation** — tick off the AI-generated checklist and threat-specific steps
7. **Export PDF** — share with your team

## Deployment

### Streamlit Community Cloud
1. Push repo to GitHub (already done)
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your repo, point to `src/app.py`
4. Add `ANTHROPIC_API_KEY` and optionally `VT_API_KEY` under **Secrets**
5. Note: MITRE data must be downloaded at startup — add a `.streamlit/setup.sh` or embed in app startup

## Roadmap

- [ ] Sigma rule generation per technique
- [ ] Direct Microsoft Sentinel API integration (pull alerts automatically)
- [ ] Multi-alert batch mode
- [ ] Historical analysis dashboard
- [ ] Slack / Teams notification hooks

## Contributing

Issues and PRs welcome. For major changes, open an issue first to discuss.

## License

MIT

## Acknowledgements

- [MITRE ATT&CK](https://attack.mitre.org/) for the threat framework
- [Anthropic](https://anthropic.com/) for Claude
- [VirusTotal](https://virustotal.com/) for IOC enrichment
