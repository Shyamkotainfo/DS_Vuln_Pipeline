# Databricks notebook source
# MAGIC %md
# MAGIC # Gold Layer — Trend Analytics
# MAGIC Time-series aggregations for vulnerability trends.
# MAGIC Daily/weekly/monthly counts, EPSS trends, new vs modified CVEs.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from delta.tables import DeltaTable
from datetime import datetime

# COMMAND ----------

# ============================================================
# Read Gold Master
# ============================================================

df_master = spark.table(GOLD_TABLES["vulnerability_master"])
print(f"Master rows: {df_master.count()}")

# COMMAND ----------

# ============================================================
# Daily Trends
# ============================================================

df_daily = df_master \
    .withColumn("publish_date", F.col("published_ts").cast(DateType())) \
    .groupBy("publish_date") \
    .agg(
        F.count("cve_id").alias("new_cves"),
        F.avg("cvss_v31_base_score").alias("avg_cvss"),
        F.avg("epss_score").alias("avg_epss"),
        F.sum(F.when(F.col("in_cisa_kev"), 1).otherwise(0)).alias("cisa_kev_count"),
        F.sum(F.when(F.col("has_public_exploit"), 1).otherwise(0)).alias("exploitable_count"),
        F.sum(F.when(F.col("has_msf_module"), 1).otherwise(0)).alias("msf_count"),
        F.sum(F.when(F.col("cvss_v31_severity") == "CRITICAL", 1).otherwise(0)).alias("critical_count"),
        F.sum(F.when(F.col("cvss_v31_severity") == "HIGH", 1).otherwise(0)).alias("high_count"),
    ) \
    .orderBy("publish_date")

print(f"Daily trend rows: {df_daily.count()}")

# COMMAND ----------

# ============================================================
# Weekly Trends
# ============================================================

df_weekly = df_master \
    .withColumn("publish_date", F.col("published_ts").cast(DateType())) \
    .withColumn("week_start", F.date_trunc("week", F.col("publish_date"))) \
    .groupBy("week_start") \
    .agg(
        F.count("cve_id").alias("new_cves"),
        F.avg("cvss_v31_base_score").alias("avg_cvss"),
        F.avg("epss_score").alias("avg_epss"),
        F.sum(F.when(F.col("in_cisa_kev"), 1).otherwise(0)).alias("cisa_kev_count"),
        F.sum(F.when(F.col("has_public_exploit"), 1).otherwise(0)).alias("exploitable_count"),
        F.countDistinct(F.when(F.col("primary_cwe").isNotNull(), F.col("primary_cwe"))).alias("unique_cwes"),
    ) \
    .orderBy("week_start")

print(f"Weekly trend rows: {df_weekly.count()}")

# COMMAND ----------

# ============================================================
# Monthly Trends
# ============================================================

df_monthly = df_master \
    .withColumn("publish_date", F.col("published_ts").cast(DateType())) \
    .withColumn("month_start", F.date_trunc("month", F.col("publish_date"))) \
    .groupBy("month_start") \
    .agg(
        F.count("cve_id").alias("new_cves"),
        F.avg("cvss_v31_base_score").alias("avg_cvss"),
        F.avg("epss_score").alias("avg_epss"),
        F.sum(F.when(F.col("in_cisa_kev"), 1).otherwise(0)).alias("cisa_kev_count"),
        F.sum(F.when(F.col("has_public_exploit"), 1).otherwise(0)).alias("exploitable_count"),
        F.sum(F.when(F.col("has_msf_module"), 1).otherwise(0)).alias("msf_count"),
        F.sum(F.when(F.col("cvss_v31_severity") == "CRITICAL", 1).otherwise(0)).alias("critical_count"),
        F.sum(F.when(F.col("cvss_v31_severity") == "HIGH", 1).otherwise(0)).alias("high_count"),
        F.sum(F.when(F.col("cvss_v31_severity") == "MEDIUM", 1).otherwise(0)).alias("medium_count"),
        F.sum(F.when(F.col("cvss_v31_severity") == "LOW", 1).otherwise(0)).alias("low_count"),
    ) \
    .orderBy("month_start")

print(f"Monthly trend rows: {df_monthly.count()}")

# COMMAND ----------

# ============================================================
# Severity Distribution Over Time (by year)
# ============================================================

df_severity_by_year = df_master \
    .withColumn("pub_year", F.year(F.col("published_ts"))) \
    .groupBy("pub_year", "cvss_v31_severity") \
    .agg(F.count("cve_id").alias("cve_count")) \
    .orderBy("pub_year", "cvss_v31_severity")

# COMMAND ----------

# ============================================================
# CWE Trends (Top weaknesses over time)
# ============================================================

df_cwe_trend = df_master \
    .filter(F.col("primary_cwe").isNotNull()) \
    .withColumn("pub_year", F.year(F.col("published_ts"))) \
    .groupBy("pub_year", "primary_cwe") \
    .agg(
        F.count("cve_id").alias("cve_count"),
        F.avg("cvss_v31_base_score").alias("avg_cvss"),
    ) \
    .orderBy("pub_year", F.col("cve_count").desc())

# COMMAND ----------

# ============================================================
# Write Trend Tables
# ============================================================

NOW = datetime.utcnow()
TABLE_NAME = GOLD_TABLES["trend_analytics"]

# Combine into a union-friendly format with a trend_type discriminator
df_daily_out = df_daily \
    .withColumn("trend_type", F.lit("daily")) \
    .withColumn("period", F.col("publish_date").cast(StringType())) \
    .select("trend_type", "period", "new_cves", "avg_cvss", "avg_epss",
            "cisa_kev_count", "exploitable_count")

df_weekly_out = df_weekly \
    .withColumn("trend_type", F.lit("weekly")) \
    .withColumn("period", F.col("week_start").cast(StringType())) \
    .select("trend_type", "period", "new_cves", "avg_cvss", "avg_epss",
            "cisa_kev_count", "exploitable_count")

df_monthly_out = df_monthly \
    .withColumn("trend_type", F.lit("monthly")) \
    .withColumn("period", F.col("month_start").cast(StringType())) \
    .select("trend_type", "period", "new_cves", "avg_cvss", "avg_epss",
            "cisa_kev_count", "exploitable_count")

df_trends = df_daily_out.unionByName(df_weekly_out).unionByName(df_monthly_out) \
    .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
    .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
    .withColumn("day", F.lit(NOW.day).cast(IntegerType())) \
    .withColumn("_computed_at", F.current_timestamp())

df_trends.write.format("delta").mode("overwrite") \
    .partitionBy("year", "month", "day") \
    .option("overwriteSchema", "true") \
    .saveAsTable(TABLE_NAME)

print(f"✅ {TABLE_NAME} written — {df_trends.count()} rows")
