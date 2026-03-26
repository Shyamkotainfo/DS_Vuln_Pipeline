# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer — EPSS
# MAGIC Cleans EPSS Bronze data: casts scores to double, validates CVE format, deduplicates.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from pyspark.sql.window import Window

# COMMAND ----------

# ============================================================
# Read Bronze
# ============================================================

BRONZE_PATH = BRONZE_TABLES["epss"]
SILVER_PATH = SILVER_TABLES["epss"]

df_bronze = spark.read.format("delta").load(BRONZE_PATH)
print(f"Bronze EPSS rows: {df_bronze.count()}")

# COMMAND ----------

# ============================================================
# Transformations
# ============================================================

df = df_bronze

# 1. Standardize CVE ID
df = df.withColumn("cve_id", F.upper(F.trim(F.col("cve"))))

# 2. Cast score fields to double
df = df.withColumn("epss_score", F.col("epss").cast(DoubleType()))
df = df.withColumn("epss_percentile", F.col("percentile").cast(DoubleType()))

# 3. Parse score date
df = df.withColumn("score_date", F.to_date("date", "yyyy-MM-dd"))

# 4. Clamp scores to [0.0, 1.0]
df = df.withColumn("epss_score", F.when(F.col("epss_score") > 1.0, 1.0).when(F.col("epss_score") < 0.0, 0.0).otherwise(F.col("epss_score")))
df = df.withColumn("epss_percentile", F.when(F.col("epss_percentile") > 1.0, 1.0).when(F.col("epss_percentile") < 0.0, 0.0).otherwise(F.col("epss_percentile")))

# COMMAND ----------

# ============================================================
# Data Quality
# ============================================================

# Remove invalid CVEs
df = df.filter(F.col("cve_id").isNotNull() & F.col("cve_id").rlike(r"^CVE-\d{4}-\d{4,}$"))

# Remove null scores
df = df.filter(F.col("epss_score").isNotNull())

# Deduplicate: keep latest score per CVE per date
w = Window.partitionBy("cve_id", "score_date").orderBy(F.col("_ingested_at").desc())
df = df.withColumn("_rn", F.row_number().over(w)).filter(F.col("_rn") == 1).drop("_rn")

print(f"Silver EPSS rows after cleaning: {df.count()}")

# COMMAND ----------

# ============================================================
# Select Silver Columns
# ============================================================

df_silver = df.select(
    "cve_id",
    "epss_score",
    "epss_percentile",
    "score_date",
    "_ingested_at",
    "_source",
    "_batch_id",
    "year",
    "month",
    "day",
)

# COMMAND ----------

# ============================================================
# Write Silver Delta
# ============================================================

df_silver.write \
    .format("delta") \
    .mode("overwrite") \
    .partitionBy("year", "month", "day") \
    .option("overwriteSchema", "true") \
    .save(SILVER_PATH)

print(f"✅ Silver EPSS written to {SILVER_PATH}")

# COMMAND ----------

spark.sql(f"""
    CREATE TABLE IF NOT EXISTS silver_epss
    USING DELTA
    LOCATION '{SILVER_PATH}'
""")

count = spark.read.format("delta").load(SILVER_PATH).count()
print(f"✅ silver_epss registered — Total rows: {count}")
