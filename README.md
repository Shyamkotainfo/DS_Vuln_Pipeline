# Vulnerability Intelligence — Medallion Pipeline

End-to-end Medallion Architecture pipeline for Databricks on GCP Cloud Storage.

## Architecture

```
Raw APIs/Feeds → Bronze (Delta) → Silver (Delta) → Gold (Delta) → KPIs & Dashboards
```

## Data Sources

| Source | Description | Join Key |
|---|---|---|
| **NVD** | CVE details, CVSS scores, CWE | `cve_id` (primary) |
| **CISA KEV** | Known Exploited Vulnerabilities | `cve_id` |
| **EPSS** | Exploit Prediction Scores | `cve_id` |
| **ExploitDB** | Public exploit index | `cve_ids[]` (extracted from codes) |
| **Metasploit** | Exploit module metadata | `cve_ids[]` (extracted from references) |

## Folder Structure

```
pipeline/
├── config.py                           # GCS paths, schemas, API config
├── utils/
│   └── synthetic_generator.py          # 1GB/day synthetic data with CVE integrity
├── bronze/
│   ├── bronze_nvd.py                   # NVD API → Delta
│   ├── bronze_cisa.py                  # CISA JSON → Delta
│   ├── bronze_epss.py                  # EPSS CSV.GZ → Delta
│   ├── bronze_exploitdb.py             # ExploitDB CSV → Delta
│   └── bronze_metasploit.py            # Metasploit JSON → Delta
├── silver/
│   ├── silver_nvd.py                   # Flatten JSON, extract CVSS, dedup
│   ├── silver_cisa.py                  # Parse dates, boolean conversion
│   ├── silver_epss.py                  # Cast scores, validate ranges
│   ├── silver_exploitdb.py             # Extract CVEs from codes
│   └── silver_metasploit.py            # Extract CVEs from references
├── gold/
│   ├── gold_vulnerability_master.py    # Join all 5 tables on CVE ID
│   ├── gold_risk_scoring.py            # Weighted composite risk score
│   ├── gold_trend_analytics.py         # Daily/weekly/monthly trends
│   └── gold_exploit_readiness.py       # Weaponization analysis
├── kpis/
│   └── kpi_dashboard.py                # KPI metrics + SQL views
└── orchestrator.py                     # Run full pipeline (daily job)
```

## Quick Start

1. **Configure**: Update `GCS_BUCKET` in `pipeline/config.py`
2. **Import**: Upload `pipeline/` folder to Databricks workspace
3. **Run**: Execute `pipeline/orchestrator.py` on a cluster with Delta Lake
4. **Schedule**: Create a daily Databricks Workflow job pointing to `orchestrator.py`

## Gold Layer Tables

| Table | Description |
|---|---|
| `gold_vulnerability_master` | Denormalized fact table (all 5 sources joined) |
| `gold_risk_scoring` | Composite risk scores with tiers (Critical/High/Medium/Low) |
| `gold_trend_analytics` | Time-series aggregations (daily/weekly/monthly) |
| `gold_exploit_readiness` | Weaponization levels and time-to-exploit metrics |
| `gold_kpis` | Dashboard-ready KPI values |

## Dashboard SQL Views

- `vw_latest_kpis` — Current KPI values
- `vw_top_risks` — Top 100 riskiest CVEs
- `vw_daily_trends` — Daily vulnerability trends
- `vw_weaponization` — Exploit weaponization distribution
