# Databricks notebook source
# MAGIC %md
# MAGIC # KPI Dashboard
# MAGIC Computes business-level KPIs from Gold tables with proper `WHERE` conditions.
# MAGIC - **Daily refresh**: Only processes data from latest Gold run
# MAGIC - **Date filtering**: Uses partition pruning and date predicates
# MAGIC - **Incremental KPI history**: Appends daily snapshots for trend tracking

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from datetime import datetime, timedelta

# COMMAND ----------

# ============================================================
# Date Boundaries for WHERE Conditions
# ============================================================

NOW = datetime.utcnow()
TODAY = NOW.date()
YESTERDAY = TODAY - timedelta(days=1)
WEEK_AGO = TODAY - timedelta(days=7)
MONTH_AGO = TODAY - timedelta(days=30)
QUARTER_AGO = TODAY - timedelta(days=90)
YEAR_AGO = TODAY - timedelta(days=365)

TODAY_STR = str(TODAY)
YESTERDAY_STR = str(YESTERDAY)
WEEK_AGO_STR = str(WEEK_AGO)
MONTH_AGO_STR = str(MONTH_AGO)
QUARTER_AGO_STR = str(QUARTER_AGO)
YEAR_AGO_STR = str(YEAR_AGO)

print(f"KPI Computation Date: {TODAY_STR}")
print(f"Date Ranges: today={TODAY_STR}, week_ago={WEEK_AGO_STR}, month_ago={MONTH_AGO_STR}, quarter_ago={QUARTER_AGO_STR}")

# COMMAND ----------

# ============================================================
# Read Gold Tables (with partition pruning)
# ============================================================

# Full master for total counts
df_master = spark.read.format("delta").load(GOLD_TABLES["vulnerability_master"])

# Risk scoring — filter to latest computed batch only
df_risk = spark.read.format("delta").load(GOLD_TABLES["risk_scoring"]) \
    .filter(
        (F.col("year") == NOW.year) &
        (F.col("month") == NOW.month) &
        (F.col("day") == NOW.day)
    )

# Exploit readiness — latest batch
df_readiness = spark.read.format("delta").load(GOLD_TABLES["exploit_readiness"]) \
    .filter(
        (F.col("year") == NOW.year) &
        (F.col("month") == NOW.month) &
        (F.col("day") == NOW.day)
    )

print(f"Master: {df_master.count()} | Risk (today): {df_risk.count()} | Readiness (today): {df_readiness.count()}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 1: Executive Summary with Date-Filtered Metrics

# COMMAND ----------

# ============================================================
# KPI 1: Executive Summary — WITH WHERE CONDITIONS
# ============================================================

total_cves = df_master.count()

# New CVEs today — WHERE published date = today
new_today = df_master.filter(
    F.col("published_ts").cast(DateType()) == TODAY_STR
).count()

# New CVEs this week — WHERE published date >= 7 days ago
new_this_week = df_master.filter(
    F.col("published_ts").cast(DateType()) >= WEEK_AGO_STR
).count()

# New CVEs this month — WHERE published date >= 30 days ago
new_this_month = df_master.filter(
    F.col("published_ts").cast(DateType()) >= MONTH_AGO_STR
).count()

# New CVEs this quarter — WHERE published date >= 90 days ago
new_this_quarter = df_master.filter(
    F.col("published_ts").cast(DateType()) >= QUARTER_AGO_STR
).count()

# Average CVSS — WHERE score > 0 (exclude unscored)
avg_cvss = df_master.filter(
    F.col("cvss_v31_base_score") > 0
).agg(F.avg("cvss_v31_base_score")).collect()[0][0] or 0.0

# Average EPSS — WHERE score > 0 (exclude unscored)
avg_epss = df_master.filter(
    F.col("epss_score") > 0
).agg(F.avg("epss_score")).collect()[0][0] or 0.0

# Critical/High from today's risk run — WHERE risk_tier IN (...)
critical_count = df_risk.filter(F.col("risk_tier") == "CRITICAL").count()
high_count = df_risk.filter(F.col("risk_tier") == "HIGH").count()
medium_count = df_risk.filter(F.col("risk_tier") == "MEDIUM").count()
low_count = df_risk.filter(F.col("risk_tier") == "LOW").count()

# Exploitability — WHERE has_public_exploit = true
exploitable_count = df_master.filter(F.col("has_public_exploit") == True).count()
exploitable_pct = (exploitable_count / max(total_cves, 1)) * 100

# CISA KEV — WHERE in_cisa_kev = true
kev_count = df_master.filter(F.col("in_cisa_kev") == True).count()
kev_pct = (kev_count / max(total_cves, 1)) * 100

# Ransomware — WHERE is_ransomware_related = true
ransomware_count = df_master.filter(F.col("is_ransomware_related") == True).count()

# Metasploit — WHERE has_msf_module = true
msf_count = df_master.filter(F.col("has_msf_module") == True).count()

# High EPSS (>0.5) — WHERE epss_score > 0.5
high_epss = df_master.filter(F.col("epss_score") > 0.5).count()

# Unpatched critical — WHERE cvss >= 9.0 AND vulnStatus != 'Rejected'
unpatched_critical = df_master.filter(
    (F.col("cvss_v31_base_score") >= 9.0) &
    (F.col("vulnStatus") != "Rejected") &
    (F.col("vulnStatus") != "Analyzed")
).count()

print("=" * 60)
print(f"  VULNERABILITY INTELLIGENCE KPIs — {TODAY_STR}")
print("=" * 60)
print(f"  Total Active CVEs:           {total_cves:>10,}")
print(f"  New CVEs Today:              {new_today:>10,}")
print(f"  New This Week:               {new_this_week:>10,}")
print(f"  New This Month:              {new_this_month:>10,}")
print(f"  New This Quarter:            {new_this_quarter:>10,}")
print(f"  ─────────────────────────────────────")
print(f"  Avg CVSS (scored only):      {avg_cvss:>10.2f}")
print(f"  Avg EPSS (scored only):      {avg_epss:>10.5f}")
print(f"  High EPSS (>0.5):            {high_epss:>10,}")
print(f"  ─────────────────────────────────────")
print(f"  CRITICAL Risk:               {critical_count:>10,}")
print(f"  HIGH Risk:                   {high_count:>10,}")
print(f"  MEDIUM Risk:                 {medium_count:>10,}")
print(f"  LOW Risk:                    {low_count:>10,}")
print(f"  ─────────────────────────────────────")
print(f"  Exploitable (public):        {exploitable_count:>10,} ({exploitable_pct:.1f}%)")
print(f"  Metasploit Modules:          {msf_count:>10,}")
print(f"  CISA KEV Listed:             {kev_count:>10,} ({kev_pct:.1f}%)")
print(f"  Ransomware-Related:          {ransomware_count:>10,}")
print(f"  Unpatched Critical (≥9.0):   {unpatched_critical:>10,}")
print("=" * 60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 2: Top 10 Riskiest CVEs (Today's Scoring)

# COMMAND ----------

# ============================================================
# KPI 2: Top 10 — WHERE today's risk run AND score > 0.5
# ============================================================

df_top10 = df_risk \
    .filter(F.col("composite_risk_score") > 0.5) \
    .orderBy(F.col("composite_risk_score").desc()) \
    .select(
        "priority_rank", "cve_id",
        F.round("composite_risk_score", 3).alias("risk_score"),
        "risk_tier", "cvss_v31_base_score", "epss_score",
        "in_cisa_kev", "has_public_exploit", "has_msf_module",
        "vendor_project", "product",
    ) \
    .limit(10)

print("Top 10 Riskiest Vulnerabilities (today's run, score > 0.5):")
df_top10.show(truncate=False)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 3: Weaponization Summary (Today's Analysis)

# COMMAND ----------

# ============================================================
# KPI 3: Weaponization — WHERE today's readiness analysis
# ============================================================

df_weapon = df_readiness \
    .filter(F.col("weaponization_level").isNotNull()) \
    .groupBy("weaponization_level") \
    .agg(
        F.count("cve_id").alias("cve_count"),
        F.round(F.avg("cvss_v31_base_score"), 2).alias("avg_cvss"),
        F.round(F.avg("epss_score"), 5).alias("avg_epss"),
        F.sum(F.when(F.col("in_cisa_kev"), 1).otherwise(0)).alias("in_kev"),
    ) \
    .withColumn("pct_of_total", F.round(F.col("cve_count") / F.lit(max(df_readiness.count(), 1)) * 100, 1)) \
    .orderBy(F.col("cve_count").desc())

print("Weaponization Distribution (today's run):")
df_weapon.show(truncate=False)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 4: Vendor Risk — WHERE vendor has ≥5 CVEs AND at least 1 exploitable

# COMMAND ----------

# ============================================================
# KPI 4: Vendor Risk — WHERE vendor_project IS NOT NULL
#                       AND total_cves >= 5
#                       AND at least 1 exploitable CVE
# ============================================================

df_vendor_risk = df_master \
    .filter(
        (F.col("vendor_project").isNotNull()) &
        (F.col("vendor_project") != "")
    ) \
    .groupBy("vendor_project") \
    .agg(
        F.count("cve_id").alias("total_cves"),
        F.round(F.avg("cvss_v31_base_score"), 2).alias("avg_cvss"),
        F.round(F.avg("epss_score"), 5).alias("avg_epss"),
        F.sum(F.when(F.col("in_cisa_kev"), 1).otherwise(0)).alias("kev_count"),
        F.sum(F.when(F.col("has_public_exploit"), 1).otherwise(0)).alias("exploitable"),
        F.sum(F.when(F.col("has_msf_module"), 1).otherwise(0)).alias("msf_modules"),
        F.sum(F.when(F.col("cvss_v31_severity") == "CRITICAL", 1).otherwise(0)).alias("critical_cves"),
    ) \
    .filter(
        (F.col("total_cves") >= 5) &
        (F.col("exploitable") >= 1)
    ) \
    .withColumn("exploit_rate_pct", F.round(F.col("exploitable") / F.col("total_cves") * 100, 1)) \
    .orderBy(F.col("kev_count").desc(), F.col("total_cves").desc()) \
    .limit(20)

print("Top 20 Vendors by Risk (≥5 CVEs, ≥1 exploit):")
df_vendor_risk.show(truncate=False)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 5: CWE Weakness Analysis — WHERE CWE is valid

# COMMAND ----------

# ============================================================
# KPI 5: CWE — WHERE primary_cwe IS NOT NULL
#               AND primary_cwe NOT IN ('NVD-CWE-noinfo', 'NVD-CWE-Other')
#               AND cve_count >= 10
# ============================================================

df_cwe_summary = df_master \
    .filter(
        (F.col("primary_cwe").isNotNull()) &
        (~F.col("primary_cwe").isin("NVD-CWE-noinfo", "NVD-CWE-Other", ""))
    ) \
    .groupBy("primary_cwe") \
    .agg(
        F.count("cve_id").alias("cve_count"),
        F.round(F.avg("cvss_v31_base_score"), 2).alias("avg_cvss"),
        F.round(F.avg("epss_score"), 5).alias("avg_epss"),
        F.sum(F.when(F.col("has_public_exploit"), 1).otherwise(0)).alias("exploitable"),
        F.sum(F.when(F.col("in_cisa_kev"), 1).otherwise(0)).alias("in_kev"),
    ) \
    .filter(F.col("cve_count") >= 10) \
    .withColumn("exploit_rate_pct", F.round(F.col("exploitable") / F.col("cve_count") * 100, 1)) \
    .orderBy(F.col("cve_count").desc()) \
    .limit(15)

print("Top 15 CWE Weaknesses (≥10 CVEs, valid CWE only):")
df_cwe_summary.show(truncate=False)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 6: Recent Critical Alerts — Last 7 Days

# COMMAND ----------

# ============================================================
# KPI 6: Critical Alerts — WHERE published in last 7 days
#                           AND (cvss >= 9.0 OR in_cisa_kev = true OR epss > 0.7)
# ============================================================

df_recent_critical = df_master \
    .filter(
        (F.col("published_ts").cast(DateType()) >= WEEK_AGO_STR) &
        (
            (F.col("cvss_v31_base_score") >= 9.0) |
            (F.col("in_cisa_kev") == True) |
            (F.col("epss_score") > 0.7)
        )
    ) \
    .select(
        "cve_id",
        "description_en",
        "cvss_v31_base_score",
        "cvss_v31_severity",
        "epss_score",
        "in_cisa_kev",
        "has_public_exploit",
        "has_msf_module",
        "is_ransomware_related",
        "published_ts",
        "vendor_project",
        "product",
    ) \
    .orderBy(F.col("cvss_v31_base_score").desc(), F.col("epss_score").desc())

print(f"🚨 Critical Alerts (last 7 days): {df_recent_critical.count()} CVEs")
df_recent_critical.limit(20).show(truncate=60)

# COMMAND ----------

# MAGIC %md
# MAGIC ## KPI 7: Month-over-Month Comparison

# COMMAND ----------

# ============================================================
# KPI 7: MoM Comparison — WHERE current month vs previous month
# ============================================================

PREV_MONTH_START = (TODAY.replace(day=1) - timedelta(days=1)).replace(day=1)
CURRENT_MONTH_START = TODAY.replace(day=1)

this_month_cves = df_master.filter(
    F.col("published_ts").cast(DateType()) >= str(CURRENT_MONTH_START)
).count()

last_month_cves = df_master.filter(
    (F.col("published_ts").cast(DateType()) >= str(PREV_MONTH_START)) &
    (F.col("published_ts").cast(DateType()) < str(CURRENT_MONTH_START))
).count()

mom_change = ((this_month_cves - last_month_cves) / max(last_month_cves, 1)) * 100

this_month_critical = df_master.filter(
    (F.col("published_ts").cast(DateType()) >= str(CURRENT_MONTH_START)) &
    (F.col("cvss_v31_severity") == "CRITICAL")
).count()

last_month_critical = df_master.filter(
    (F.col("published_ts").cast(DateType()) >= str(PREV_MONTH_START)) &
    (F.col("published_ts").cast(DateType()) < str(CURRENT_MONTH_START)) &
    (F.col("cvss_v31_severity") == "CRITICAL")
).count()

print(f"Month-over-Month Comparison:")
print(f"  Current month CVEs:  {this_month_cves:>8,}")
print(f"  Last month CVEs:     {last_month_cves:>8,}")
print(f"  MoM Change:          {mom_change:>7.1f}%")
print(f"  Current month CRIT:  {this_month_critical:>8,}")
print(f"  Last month CRIT:     {last_month_critical:>8,}")

# COMMAND ----------

# ============================================================
# Write KPI Snapshot (daily append for historical tracking)
# ============================================================

kpi_data = [
    ("total_active_cves", float(total_cves), "count", "all_time"),
    ("new_cves_today", float(new_today), "count", "daily"),
    ("new_cves_this_week", float(new_this_week), "count", "weekly"),
    ("new_cves_this_month", float(new_this_month), "count", "monthly"),
    ("new_cves_this_quarter", float(new_this_quarter), "count", "quarterly"),
    ("avg_cvss_scored", round(avg_cvss, 2), "score", "all_time"),
    ("avg_epss_scored", round(avg_epss, 5), "score", "all_time"),
    ("high_epss_count", float(high_epss), "count", "all_time"),
    ("critical_risk_count", float(critical_count), "count", "all_time"),
    ("high_risk_count", float(high_count), "count", "all_time"),
    ("medium_risk_count", float(medium_count), "count", "all_time"),
    ("low_risk_count", float(low_count), "count", "all_time"),
    ("exploitable_count", float(exploitable_count), "count", "all_time"),
    ("exploitable_pct", round(exploitable_pct, 1), "percentage", "all_time"),
    ("msf_module_count", float(msf_count), "count", "all_time"),
    ("cisa_kev_count", float(kev_count), "count", "all_time"),
    ("cisa_kev_pct", round(kev_pct, 1), "percentage", "all_time"),
    ("ransomware_related_count", float(ransomware_count), "count", "all_time"),
    ("unpatched_critical", float(unpatched_critical), "count", "all_time"),
    ("mom_change_pct", round(mom_change, 1), "percentage", "monthly"),
]

df_kpis = spark.createDataFrame(
    kpi_data, ["kpi_name", "kpi_value", "kpi_type", "time_window"]
) \
    .withColumn("computed_at", F.current_timestamp()) \
    .withColumn("computed_date", F.lit(TODAY_STR).cast(DateType())) \
    .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
    .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
    .withColumn("day", F.lit(NOW.day).cast(IntegerType()))

GOLD_KPI_PATH = GOLD_TABLES["kpis"]

df_kpis.write.format("delta").mode("append") \
    .partitionBy("year", "month", "day") \
    .save(GOLD_KPI_PATH)

print(f"✅ {len(kpi_data)} KPIs written to {GOLD_KPI_PATH} for {TODAY_STR}")

# COMMAND ----------

# ============================================================
# Register SQL Views — ALL with WHERE Conditions
# ============================================================

spark.sql(f"CREATE TABLE IF NOT EXISTS gold_kpis USING DELTA LOCATION '{GOLD_KPI_PATH}'")
spark.sql(f"CREATE TABLE IF NOT EXISTS gold_vulnerability_master USING DELTA LOCATION '{GOLD_TABLES['vulnerability_master']}'")
spark.sql(f"CREATE TABLE IF NOT EXISTS gold_risk_scoring USING DELTA LOCATION '{GOLD_TABLES['risk_scoring']}'")
spark.sql(f"CREATE TABLE IF NOT EXISTS gold_trend_analytics USING DELTA LOCATION '{GOLD_TABLES['trend_analytics']}'")
spark.sql(f"CREATE TABLE IF NOT EXISTS gold_exploit_readiness USING DELTA LOCATION '{GOLD_TABLES['exploit_readiness']}'")

# COMMAND ----------

# ============================================================
# View 1: Latest KPIs — WHERE latest computed_date only
# ============================================================

spark.sql("""
    CREATE OR REPLACE VIEW vw_latest_kpis AS
    SELECT kpi_name, kpi_value, kpi_type, time_window, computed_at, computed_date
    FROM gold_kpis
    WHERE computed_date = (SELECT MAX(computed_date) FROM gold_kpis)
""")

# COMMAND ----------

# ============================================================
# View 2: KPI History (last 30 days) — WHERE computed_date >= 30d ago
# ============================================================

spark.sql(f"""
    CREATE OR REPLACE VIEW vw_kpi_history AS
    SELECT kpi_name, kpi_value, kpi_type, computed_date
    FROM gold_kpis
    WHERE computed_date >= DATE_SUB(CURRENT_DATE(), 30)
    ORDER BY computed_date DESC, kpi_name
""")

# COMMAND ----------

# ============================================================
# View 3: Top 100 Risks — WHERE score > 0.5 AND latest run
# ============================================================

spark.sql("""
    CREATE OR REPLACE VIEW vw_top_risks AS
    SELECT cve_id, composite_risk_score, risk_tier,
           cvss_v31_base_score, epss_score, epss_percentile,
           in_cisa_kev, is_ransomware_related,
           has_public_exploit, exploit_count,
           has_msf_module, msf_module_count,
           vendor_project, product, description_en,
           published_ts, days_since_published, primary_cwe
    FROM gold_risk_scoring
    WHERE composite_risk_score > 0.5
      AND (year, month, day) = (
          SELECT year, month, day FROM gold_risk_scoring
          ORDER BY year DESC, month DESC, day DESC LIMIT 1
      )
    ORDER BY composite_risk_score DESC
    LIMIT 100
""")

# COMMAND ----------

# ============================================================
# View 4: Daily Trends (last 90 days) — WHERE trend_type = 'daily'
# ============================================================

spark.sql("""
    CREATE OR REPLACE VIEW vw_daily_trends AS
    SELECT period AS date, new_cves, avg_cvss, avg_epss,
           cisa_kev_count, exploitable_count
    FROM gold_trend_analytics
    WHERE trend_type = 'daily'
      AND period >= DATE_SUB(CURRENT_DATE(), 90)
    ORDER BY period DESC
""")

# COMMAND ----------

# ============================================================
# View 5: Monthly Trends (last 2 years) — WHERE trend_type = 'monthly'
# ============================================================

spark.sql("""
    CREATE OR REPLACE VIEW vw_monthly_trends AS
    SELECT period AS month, new_cves, avg_cvss, avg_epss,
           cisa_kev_count, exploitable_count
    FROM gold_trend_analytics
    WHERE trend_type = 'monthly'
      AND period >= DATE_SUB(CURRENT_DATE(), 730)
    ORDER BY period DESC
""")

# COMMAND ----------

# ============================================================
# View 6: Weaponization — WHERE latest run, grouped
# ============================================================

spark.sql("""
    CREATE OR REPLACE VIEW vw_weaponization AS
    SELECT weaponization_level,
           COUNT(*) as cve_count,
           ROUND(AVG(cvss_v31_base_score), 2) as avg_cvss,
           ROUND(AVG(epss_score), 5) as avg_epss,
           SUM(CASE WHEN in_cisa_kev THEN 1 ELSE 0 END) as in_kev
    FROM gold_exploit_readiness
    WHERE (year, month, day) = (
        SELECT year, month, day FROM gold_exploit_readiness
        ORDER BY year DESC, month DESC, day DESC LIMIT 1
    )
    GROUP BY weaponization_level
    ORDER BY cve_count DESC
""")

# COMMAND ----------

# ============================================================
# View 7: Critical Alerts — WHERE last 7 days AND high severity
# ============================================================

spark.sql("""
    CREATE OR REPLACE VIEW vw_critical_alerts AS
    SELECT cve_id, description_en,
           cvss_v31_base_score, cvss_v31_severity,
           epss_score, in_cisa_kev,
           has_public_exploit, has_msf_module,
           is_ransomware_related,
           published_ts, vendor_project, product
    FROM gold_vulnerability_master
    WHERE published_ts >= DATE_SUB(CURRENT_DATE(), 7)
      AND (
          cvss_v31_base_score >= 9.0
          OR in_cisa_kev = true
          OR epss_score > 0.7
      )
    ORDER BY cvss_v31_base_score DESC, epss_score DESC
""")

# COMMAND ----------

# ============================================================
# View 8: Vendor Risk Dashboard — WHERE vendor has significant exposure
# ============================================================

spark.sql("""
    CREATE OR REPLACE VIEW vw_vendor_risk AS
    SELECT vendor_project,
           COUNT(cve_id) as total_cves,
           ROUND(AVG(cvss_v31_base_score), 2) as avg_cvss,
           SUM(CASE WHEN in_cisa_kev THEN 1 ELSE 0 END) as kev_count,
           SUM(CASE WHEN has_public_exploit THEN 1 ELSE 0 END) as exploitable,
           SUM(CASE WHEN has_msf_module THEN 1 ELSE 0 END) as msf_modules,
           SUM(CASE WHEN cvss_v31_severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_cves,
           ROUND(SUM(CASE WHEN has_public_exploit THEN 1 ELSE 0 END) * 100.0 / COUNT(cve_id), 1) as exploit_rate_pct
    FROM gold_vulnerability_master
    WHERE vendor_project IS NOT NULL
      AND vendor_project != ''
    GROUP BY vendor_project
    HAVING COUNT(cve_id) >= 5
       AND SUM(CASE WHEN has_public_exploit THEN 1 ELSE 0 END) >= 1
    ORDER BY kev_count DESC, total_cves DESC
    LIMIT 50
""")

# COMMAND ----------

print("✅ All 8 SQL views created with WHERE conditions:")
print("  1. vw_latest_kpis        — WHERE latest computed_date")
print("  2. vw_kpi_history        — WHERE last 30 days")
print("  3. vw_top_risks          — WHERE score > 0.5, latest run")
print("  4. vw_daily_trends       — WHERE daily, last 90 days")
print("  5. vw_monthly_trends     — WHERE monthly, last 2 years")
print("  6. vw_weaponization      — WHERE latest run")
print("  7. vw_critical_alerts    — WHERE last 7 days, high severity")
print("  8. vw_vendor_risk        — WHERE vendor ≥5 CVEs, ≥1 exploit")
