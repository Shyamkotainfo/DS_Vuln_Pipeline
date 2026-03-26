# Databricks notebook source
# MAGIC %md
# MAGIC # Gold Layer — Risk Scoring
# MAGIC Computes composite risk scores from the Vulnerability Master table.
# MAGIC Score = weighted combination of CVSS, EPSS, CISA KEV, exploit availability.

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

df_master = spark.read.format("delta").load(GOLD_TABLES["vulnerability_master"])
print(f"Master table rows: {df_master.count()}")

# COMMAND ----------

# ============================================================
# Composite Risk Score Calculation
# ============================================================
# Weights (total = 1.0):
#   CVSS Base Score (normalized 0-1):  0.30
#   EPSS Score (already 0-1):          0.25
#   CISA KEV Flag:                     0.20
#   Has Public Exploit:                0.10
#   Has Metasploit Module:             0.10
#   Ransomware Related:                0.05

df_scored = df_master.withColumn(
    "cvss_normalized", F.col("cvss_v31_base_score") / 10.0
)

df_scored = df_scored.withColumn(
    "composite_risk_score",
    F.round(
        (F.col("cvss_normalized") * 0.30) +
        (F.col("epss_score") * 0.25) +
        (F.when(F.col("in_cisa_kev"), 1.0).otherwise(0.0) * 0.20) +
        (F.when(F.col("has_public_exploit"), 1.0).otherwise(0.0) * 0.10) +
        (F.when(F.col("has_msf_module"), 1.0).otherwise(0.0) * 0.10) +
        (F.when(F.col("is_ransomware_related"), 1.0).otherwise(0.0) * 0.05),
        4
    )
)

# Risk tiers
df_scored = df_scored.withColumn(
    "risk_tier",
    F.when(F.col("composite_risk_score") >= 0.75, "CRITICAL")
     .when(F.col("composite_risk_score") >= 0.50, "HIGH")
     .when(F.col("composite_risk_score") >= 0.25, "MEDIUM")
     .otherwise("LOW")
)

# Priority rank (lower = higher priority)
df_scored = df_scored.withColumn(
    "priority_rank",
    F.dense_rank().over(
        F.Window.orderBy(F.col("composite_risk_score").desc())
    )
)

# COMMAND ----------

# ============================================================
# Select Risk Scoring Columns
# ============================================================

NOW = datetime.utcnow()

df_risk = df_scored.select(
    "cve_id",
    "description_en",
    "cvss_v31_base_score",
    "cvss_v31_severity",
    "epss_score",
    "epss_percentile",
    "in_cisa_kev",
    "is_ransomware_related",
    "has_public_exploit",
    "exploit_count",
    "has_msf_module",
    "msf_module_count",
    "composite_risk_score",
    "risk_tier",
    "priority_rank",
    "published_ts",
    "days_since_published",
    "primary_cwe",
    "vendor_project",
    "product",
).withColumn("_scored_at", F.current_timestamp()) \
 .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
 .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
 .withColumn("day", F.lit(NOW.day).cast(IntegerType()))

print(f"Risk scored rows: {df_risk.count()}")
print(f"\nRisk tier distribution:")
df_risk.groupBy("risk_tier").count().orderBy("risk_tier").show()

# COMMAND ----------

# ============================================================
# Write Gold Risk Scoring — Delta MERGE
# ============================================================

GOLD_PATH = GOLD_TABLES["risk_scoring"]

if DeltaTable.isDeltaTable(spark, GOLD_PATH):
    delta_table = DeltaTable.forPath(spark, GOLD_PATH)
    delta_table.alias("t").merge(
        df_risk.alias("s"), "t.cve_id = s.cve_id"
    ).whenMatchedUpdateAll().whenNotMatchedInsertAll().execute()
    print("✅ MERGE into gold_risk_scoring complete")
else:
    df_risk.write.format("delta").mode("overwrite") \
        .partitionBy("year", "month", "day") \
        .save(GOLD_PATH)
    print("✅ Initial gold_risk_scoring write complete")

# COMMAND ----------

spark.sql(f"""
    CREATE TABLE IF NOT EXISTS gold_risk_scoring
    USING DELTA
    LOCATION '{GOLD_PATH}'
""")

spark.sql(f"OPTIMIZE delta.`{GOLD_PATH}` ZORDER BY (composite_risk_score)")
print("✅ gold_risk_scoring optimized")
