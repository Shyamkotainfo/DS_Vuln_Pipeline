# Databricks notebook source
# MAGIC %md
# MAGIC # Pipeline Orchestrator
# MAGIC Runs the full Medallion pipeline: Bronze → Silver → Gold → KPIs.
# MAGIC Configure this as a daily Databricks Workflow job.

# COMMAND ----------

from datetime import datetime

# COMMAND ----------

# ============================================================
# Pipeline Configuration
# ============================================================

PIPELINE_START = datetime.utcnow()
print(f"🚀 Pipeline started at {PIPELINE_START.isoformat()}")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Phase 1: Bronze Layer — Raw Ingestion

# COMMAND ----------

print("=" * 60)
print("  PHASE 1: BRONZE LAYER")
print("=" * 60)

# COMMAND ----------

# MAGIC %run ./bronze/bronze_master

# COMMAND ----------

print("✅ Phase 1 Complete: All 5 Bronze tables ingested")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Phase 2: Silver Layer — Cleaning & Transformation

# COMMAND ----------

print("=" * 60)
print("  PHASE 2: SILVER LAYER")
print("=" * 60)

# COMMAND ----------

# MAGIC %run ./silver/silver_nvd

# COMMAND ----------

# MAGIC %run ./silver/silver_cisa

# COMMAND ----------

# MAGIC %run ./silver/silver_epss

# COMMAND ----------

# MAGIC %run ./silver/silver_exploitdb

# COMMAND ----------

# MAGIC %run ./silver/silver_metasploit

# COMMAND ----------

print("✅ Phase 2 Complete: All 5 Silver tables cleaned")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Phase 3: Gold Layer — Business Aggregates

# COMMAND ----------

print("=" * 60)
print("  PHASE 3: GOLD LAYER")
print("=" * 60)

# COMMAND ----------

# MAGIC %run ./gold/gold_vulnerability_master

# COMMAND ----------

# MAGIC %run ./gold/gold_risk_scoring

# COMMAND ----------

# MAGIC %run ./gold/gold_trend_analytics

# COMMAND ----------

# MAGIC %run ./gold/gold_exploit_readiness

# COMMAND ----------

print("✅ Phase 3 Complete: All Gold tables built")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Phase 4: KPIs & Dashboard Views

# COMMAND ----------

print("=" * 60)
print("  PHASE 4: KPIs & DASHBOARDS")
print("=" * 60)

# COMMAND ----------

# MAGIC %run ./kpis/kpi_dashboard

# COMMAND ----------

print("✅ Phase 4 Complete: KPIs computed & views created")
print("=" * 60)

# COMMAND ----------

# ============================================================
# Pipeline Summary
# ============================================================

PIPELINE_END = datetime.utcnow()
duration = (PIPELINE_END - PIPELINE_START).total_seconds()

print("=" * 60)
print("  🎉 PIPELINE COMPLETE")
print("=" * 60)
print(f"  Started:  {PIPELINE_START.isoformat()}")
print(f"  Finished: {PIPELINE_END.isoformat()}")
print(f"  Duration: {duration:.0f} seconds ({duration/60:.1f} minutes)")
print("=" * 60)
print()
print("  📊 Tables Created:")
print("  ─────────────────")
print("  Bronze: bronze_nvd, bronze_cisa, bronze_epss, bronze_exploitdb, bronze_metasploit")
print("  Silver: silver_nvd, silver_cisa, silver_epss, silver_exploitdb, silver_metasploit")
print("  Gold:   gold_vulnerability_master, gold_risk_scoring, gold_trend_analytics, gold_exploit_readiness")
print("  KPIs:   gold_kpis")
print()
print("  📈 Dashboard Views:")
print("  ───────────────────")
print("  vw_latest_kpis, vw_top_risks, vw_daily_trends, vw_weaponization")
print("=" * 60)
