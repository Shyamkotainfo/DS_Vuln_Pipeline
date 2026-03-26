# Databricks notebook source
# MAGIC %md
# MAGIC # KPI Dashboard
# MAGIC Computes business-level KPIs from Gold tables and creates SQL views
# MAGIC for Databricks SQL dashboard consumption.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from datetime import datetime, timedelta

# COMMAND ----------

# ============================================================
# Read Gold Tables
# ============================================================

df_master = spark.read.format("delta").load(GOLD_TABLES["vulnerability_master"])
df_risk = spark.read.format("delta").load(GOLD_TABLES["risk_scoring"])
df_readiness = spark.read.format("delta").load(GOLD_TABLES["exploit_readiness"])

print(f"Master: {df_master.count()} | Risk: {df_risk.count()} | Readiness: {df_readiness.count()}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 1: Executive Summary Metrics

# COMMAND ----------

# ============================================================
# KPI 1: Executive Summary
# ============================================================

NOW = datetime.utcnow()
today = NOW.date()
week_ago = today - timedelta(days=7)
month_ago = today - timedelta(days=30)

total_cves = df_master.count()
new_today = df_master.filter(F.col("published_ts").cast(DateType()) == str(today)).count()
new_this_week = df_master.filter(F.col("published_ts").cast(DateType()) >= str(week_ago)).count()
new_this_month = df_master.filter(F.col("published_ts").cast(DateType()) >= str(month_ago)).count()

avg_cvss = df_master.agg(F.avg("cvss_v31_base_score")).collect()[0][0] or 0.0
avg_epss = df_master.agg(F.avg("epss_score")).collect()[0][0] or 0.0

critical_count = df_risk.filter(F.col("risk_tier") == "CRITICAL").count()
high_count = df_risk.filter(F.col("risk_tier") == "HIGH").count()

exploitable_pct = (df_master.filter(F.col("has_public_exploit")).count() / max(total_cves, 1)) * 100
kev_pct = (df_master.filter(F.col("in_cisa_kev")).count() / max(total_cves, 1)) * 100
ransomware_count = df_master.filter(F.col("is_ransomware_related")).count()

print("=" * 60)
print("      VULNERABILITY INTELLIGENCE KPIs")
print("=" * 60)
print(f"  Total Active CVEs:           {total_cves:>10,}")
print(f"  New CVEs Today:              {new_today:>10,}")
print(f"  New This Week:               {new_this_week:>10,}")
print(f"  New This Month:              {new_this_month:>10,}")
print(f"  ─────────────────────────────────────")
print(f"  Average CVSS Score:          {avg_cvss:>10.2f}")
print(f"  Average EPSS Score:          {avg_epss:>10.5f}")
print(f"  ─────────────────────────────────────")
print(f"  Critical Risk CVEs:          {critical_count:>10,}")
print(f"  High Risk CVEs:              {high_count:>10,}")
print(f"  % Exploitable:               {exploitable_pct:>9.1f}%")
print(f"  % In CISA KEV:               {kev_pct:>9.1f}%")
print(f"  Ransomware-Related:          {ransomware_count:>10,}")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 2: Top 10 Riskiest CVEs

# COMMAND ----------

# ============================================================
# KPI 2: Top 10 Riskiest Vulnerabilities
# ============================================================

df_top10 = df_risk \
    .orderBy(F.col("composite_risk_score").desc()) \
    .select(
        "priority_rank",
        "cve_id",
        F.round("composite_risk_score", 3).alias("risk_score"),
        "risk_tier",
        "cvss_v31_base_score",
        "epss_score",
        "in_cisa_kev",
        "has_public_exploit",
        "has_msf_module",
        "vendor_project",
        "product",
    ) \
    .limit(10)

print("Top 10 Riskiest Vulnerabilities:")
df_top10.show(truncate=False)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 3: Weaponization Summary

# COMMAND ----------

# ============================================================
# KPI 3: Weaponization Level Distribution
# ============================================================

df_weapon = df_readiness.groupBy("weaponization_level").agg(
    F.count("cve_id").alias("cve_count"),
    F.avg("cvss_v31_base_score").alias("avg_cvss"),
    F.avg("epss_score").alias("avg_epss"),
).orderBy(F.col("cve_count").desc())

print("Weaponization Distribution:")
df_weapon.show(truncate=False)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 4: Vendor/Product Risk Breakdown

# COMMAND ----------

# ============================================================
# KPI 4: Top Vendors by Risk
# ============================================================

df_vendor_risk = df_master \
    .filter(F.col("vendor_project").isNotNull()) \
    .groupBy("vendor_project") \
    .agg(
        F.count("cve_id").alias("total_cves"),
        F.avg("cvss_v31_base_score").alias("avg_cvss"),
        F.sum(F.when(F.col("in_cisa_kev"), 1).otherwise(0)).alias("kev_count"),
        F.sum(F.when(F.col("has_public_exploit"), 1).otherwise(0)).alias("exploitable"),
    ) \
    .orderBy(F.col("total_cves").desc()) \
    .limit(15)

print("Top 15 Vendors by CVE Count:")
df_vendor_risk.show(truncate=False)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 5: CWE Weakness Analysis

# COMMAND ----------

# ============================================================
# KPI 5: Top Weakness Types
# ============================================================

df_cwe_summary = df_master \
    .filter(F.col("primary_cwe").isNotNull() & (F.col("primary_cwe") != "NVD-CWE-noinfo")) \
    .groupBy("primary_cwe") \
    .agg(
        F.count("cve_id").alias("cve_count"),
        F.avg("cvss_v31_base_score").alias("avg_cvss"),
        F.avg("epss_score").alias("avg_epss"),
        F.sum(F.when(F.col("has_public_exploit"), 1).otherwise(0)).alias("exploitable"),
    ) \
    .withColumn("exploit_rate_pct", F.round(F.col("exploitable") / F.col("cve_count") * 100, 1)) \
    .orderBy(F.col("cve_count").desc()) \
    .limit(15)

print("Top 15 CWE Weaknesses:")
df_cwe_summary.show(truncate=False)

# COMMAND ----------

# ============================================================
# KPI Summary Table (for dashboard widgets)
# ============================================================

NOW = datetime.utcnow()
kpi_data = [
    ("total_active_cves", float(total_cves)),
    ("new_cves_today", float(new_today)),
    ("new_cves_this_week", float(new_this_week)),
    ("new_cves_this_month", float(new_this_month)),
    ("avg_cvss_score", round(avg_cvss, 2)),
    ("avg_epss_score", round(avg_epss, 5)),
    ("critical_risk_count", float(critical_count)),
    ("high_risk_count", float(high_count)),
    ("exploitable_pct", round(exploitable_pct, 1)),
    ("cisa_kev_pct", round(kev_pct, 1)),
    ("ransomware_related_count", float(ransomware_count)),
]

df_kpis = spark.createDataFrame(kpi_data, ["kpi_name", "kpi_value"]) \
    .withColumn("computed_at", F.current_timestamp()) \
    .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
    .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
    .withColumn("day", F.lit(NOW.day).cast(IntegerType()))

GOLD_KPI_PATH = GOLD_TABLES["kpis"]

df_kpis.write.format("delta").mode("append") \
    .partitionBy("year", "month", "day") \
    .save(GOLD_KPI_PATH)

print(f"✅ KPIs written to {GOLD_KPI_PATH}")

# COMMAND ----------

# ============================================================
# Register SQL Views for Databricks SQL Dashboards
# ============================================================

spark.sql(f"CREATE TABLE IF NOT EXISTS gold_kpis USING DELTA LOCATION '{GOLD_KPI_PATH}'")
spark.sql(f"CREATE TABLE IF NOT EXISTS gold_vulnerability_master USING DELTA LOCATION '{GOLD_TABLES['vulnerability_master']}'")
spark.sql(f"CREATE TABLE IF NOT EXISTS gold_risk_scoring USING DELTA LOCATION '{GOLD_TABLES['risk_scoring']}'")
spark.sql(f"CREATE TABLE IF NOT EXISTS gold_trend_analytics USING DELTA LOCATION '{GOLD_TABLES['trend_analytics']}'")
spark.sql(f"CREATE TABLE IF NOT EXISTS gold_exploit_readiness USING DELTA LOCATION '{GOLD_TABLES['exploit_readiness']}'")

# SQL views for common dashboard queries
spark.sql("""
    CREATE OR REPLACE VIEW vw_latest_kpis AS
    SELECT kpi_name, kpi_value, computed_at
    FROM gold_kpis
    WHERE (kpi_name, computed_at) IN (
        SELECT kpi_name, MAX(computed_at) FROM gold_kpis GROUP BY kpi_name
    )
""")

spark.sql("""
    CREATE OR REPLACE VIEW vw_top_risks AS
    SELECT cve_id, composite_risk_score, risk_tier,
           cvss_v31_base_score, epss_score,
           in_cisa_kev, has_public_exploit, has_msf_module,
           vendor_project, product, description_en
    FROM gold_risk_scoring
    WHERE priority_rank <= 100
    ORDER BY composite_risk_score DESC
""")

spark.sql("""
    CREATE OR REPLACE VIEW vw_daily_trends AS
    SELECT period AS date, new_cves, avg_cvss, avg_epss,
           cisa_kev_count, exploitable_count
    FROM gold_trend_analytics
    WHERE trend_type = 'daily'
    ORDER BY period DESC
""")

spark.sql("""
    CREATE OR REPLACE VIEW vw_weaponization AS
    SELECT weaponization_level, COUNT(*) as count,
           AVG(cvss_v31_base_score) as avg_cvss,
           AVG(epss_score) as avg_epss
    FROM gold_exploit_readiness
    GROUP BY weaponization_level
""")

print("✅ All SQL views created for dashboard consumption")
