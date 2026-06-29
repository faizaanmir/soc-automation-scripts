# SOC Automation Scripts

A collection of Python scripts for automating repetitive SOC tasks: alert triage, IOC enrichment, incident reporting, and watchlist management. Built from real MSSP SOC operations experience across Microsoft Sentinel, IBM QRadar, and Splunk environments.

---

## Scripts

| Script | Category | Description |
|---|---|---|
| [`alert-triage/sentinel_alert_triage.py`](alert-triage/sentinel_alert_triage.py) | Triage | Pulls open Sentinel incidents, enriches IPs/domains via TI APIs, outputs prioritized triage list |
| [`alert-triage/false_positive_tagger.py`](alert-triage/false_positive_tagger.py) | Triage | Tags and logs recurring false positive patterns with suppression suggestions |
| [`enrichment/bulk_ioc_enricher.py`](enrichment/bulk_ioc_enricher.py) | Enrichment | Bulk enriches IOCs from a file via VirusTotal and AbuseIPDB (see ioc-enrichment-tool for full version) |
| [`reporting/incident_report_generator.py`](reporting/incident_report_generator.py) | Reporting | Generates structured incident reports in Markdown from a JSON incident summary |
| [`reporting/shift_handover_generator.py`](reporting/shift_handover_generator.py) | Reporting | Generates a shift handover report from open incidents and pending actions |
| [`utils/watchlist_manager.py`](utils/watchlist_manager.py) | Utilities | Manage Sentinel watchlists — add/remove/query IOCs via the Azure REST API |

---

## Setup

```bash
git clone https://github.com/faizaanmir/soc-automation-scripts.git
cd soc-automation-scripts
pip install -r requirements.txt
cp config.example.ini config.ini
# Edit config.ini with your API keys and workspace details
```

---

## Configuration

`config.ini` holds all credentials and workspace settings:

```ini
[azure]
tenant_id       = YOUR_TENANT_ID
client_id       = YOUR_CLIENT_ID
client_secret   = YOUR_CLIENT_SECRET
subscription_id = YOUR_SUBSCRIPTION_ID
resource_group  = YOUR_RESOURCE_GROUP
workspace_name  = YOUR_SENTINEL_WORKSPACE

[virustotal]
api_key = YOUR_VT_API_KEY

[abuseipdb]
api_key = YOUR_ABUSEIPDB_API_KEY
```

---

## Requirements

- Python 3.8+
- See `requirements.txt`

---

## Disclaimer

These scripts are for authorized use in environments you have permission to access. Never hardcode credentials — always use `config.ini` or environment variables.

---

*Author: Faizaan Sajjad — Security Specialist, Orange Cyber Defense*
