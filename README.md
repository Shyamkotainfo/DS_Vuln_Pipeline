# Vulnerability Intelligence — Medallion Pipeline

End-to-end Medallion Architecture pipeline for Databricks using **Unity Catalog managed tables**.

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
├── config.py                           # Unity Catalog setup, API config
├── utils/
│   └── synthetic_generator.py          # Synthetic data generator for large volumes
├── bronze/
│   ├── bronze_nvd.py                   # NVD API → Unity Catalog Delta
│   ├── bronze_cisa.py                  # CISA JSON → Unity Catalog Delta
│   ├── bronze_epss.py                  # EPSS CSV.GZ → Unity Catalog Delta
│   ├── bronze_exploitdb.py             # ExploitDB CSV → Unity Catalog Delta
│   └── bronze_metasploit.py            # Metasploit JSON → Unity Catalog Delta
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

1. **Configure Unity Catalog**: Define your desired `CATALOG` and `SCHEMA` in `pipeline/config.py`. By default, it will automatically create and use `vulnerability_intelligence.pipeline`.
2. **Import Repo**: Add this Git repository to your Databricks Workspace (under Repo/Workspace).
3. **Run**: Execute `pipeline/orchestrator.py` on a cluster. Unity Catalog tables will automatically be provisioned, and data will be ingested.
4. **Schedule**: Create a daily Databricks Workflow job executing `orchestrator.py` to keep the warehouse up to date.

## Gold Layer Tables

| Table | Description |
|---|---|
| `gold_vulnerability_master` | Denormalized fact table (all 5 sources joined) |
| `gold_risk_scoring` | Composite risk scores with tiers (Critical/High/Medium/Low) |
| `gold_trend_analytics` | Time-series aggregations (daily/weekly/monthly) |
| `gold_exploit_readiness` | Weaponization levels and time-to-exploit metrics |
| `gold_kpis` | Dashboard-ready KPI values |

## Dashboard SQL Views

Generated automatically in your Unity Catalog schema:
- `vw_latest_kpis` — Current KPI values
- `vw_top_risks` — Top 100 riskiest CVEs
- `vw_daily_trends` — Daily vulnerability trends
- `vw_weaponization` — Exploit weaponization distribution
