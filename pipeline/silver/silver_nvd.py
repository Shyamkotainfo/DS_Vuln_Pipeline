# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer — NVD
# MAGIC Cleans and flattens NVD Bronze data for analytics readiness.
# MAGIC - Flattens JSON `descriptions` → `description_en`
# MAGIC - Extracts CVSS v3.1 base score and severity
# MAGIC - Parses timestamps, deduplicates by CVE ID

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from datetime import datetime

# COMMAND ----------

# ============================================================
# Read Bronze
# ============================================================

BRONZE_PATH = BRONZE_TABLES["nvd"]
SILVER_PATH = SILVER_TABLES["nvd"]

df_bronze = spark.read.format("delta").load(BRONZE_PATH)
print(f"Bronze NVD rows: {df_bronze.count()}")
df_bronze.printSchema()

# COMMAND ----------

# ============================================================
# Transformations
# ============================================================

# 1. Parse JSON fields
df = df_bronze

# 2. Extract English description from descriptions JSON array
# descriptions: [{"lang":"en","value":"..."},{"lang":"es","value":"..."}]
df = df.withColumn(
    "description_en",
    F.get_json_object(F.col("descriptions"), "$[0].value")
)

# 3. Extract CVSS v3.1 metrics
df = df.withColumn(
    "cvss_v31_base_score",
    F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.baseScore").cast(DoubleType())
)
df = df.withColumn(
    "cvss_v31_severity",
    F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.baseSeverity")
)
df = df.withColumn(
    "cvss_v31_vector",
    F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.vectorString")
)
df = df.withColumn(
    "cvss_v31_attack_vector",
    F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.attackVector")
)
df = df.withColumn(
    "cvss_v31_attack_complexity",
    F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.attackComplexity")
)

# 4. Extract primary weakness (CWE)
df = df.withColumn(
    "primary_cwe",
    F.get_json_object(F.col("weaknesses"), "$[0].description[0].value")
)

# 5. Parse timestamps
df = df.withColumn("published_ts", F.to_timestamp("published"))
df = df.withColumn("last_modified_ts", F.to_timestamp("lastModified"))

# 6. Standardize CVE ID
df = df.withColumn("cve_id", F.upper(F.trim(F.col("id"))))

# COMMAND ----------

# ============================================================
# Data Quality: Dedup, Nulls, Validation
# ============================================================

# Remove rows without CVE ID
df = df.filter(F.col("cve_id").isNotNull() & (F.col("cve_id") != ""))

# Validate CVE format: CVE-YYYY-NNNNN
df = df.filter(F.col("cve_id").rlike(r"^CVE-\d{4}-\d{4,}$"))

# Deduplicate: keep latest version per CVE ID
from pyspark.sql.window import Window
w = Window.partitionBy("cve_id").orderBy(F.col("last_modified_ts").desc(), F.col("_ingested_at").desc())
df = df.withColumn("_row_num", F.row_number().over(w)).filter(F.col("_row_num") == 1).drop("_row_num")

# Fill nulls for score
df = df.fillna({"cvss_v31_base_score": 0.0, "cvss_v31_severity": "UNKNOWN"})

print(f"Silver NVD rows after cleaning: {df.count()}")

# COMMAND ----------

# ============================================================
# Select Silver Columns
# ============================================================

df_silver = df.select(
    "cve_id",
    "sourceIdentifier",
    "published_ts",
    "last_modified_ts",
    "vulnStatus",
    "description_en",
    "cvss_v31_base_score",
    "cvss_v31_severity",
    "cvss_v31_vector",
    "cvss_v31_attack_vector",
    "cvss_v31_attack_complexity",
    "primary_cwe",
    "references",
    "_ingested_at",
    "_source",
    "_batch_id",
    "year",
    "month",
    "day",
)

df_silver.printSchema()

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

print(f"✅ Silver NVD written to {SILVER_PATH}")

# COMMAND ----------

# Register table
spark.sql(f"""
    CREATE TABLE IF NOT EXISTS silver_nvd
    USING DELTA
    LOCATION '{SILVER_PATH}'
""")

count = spark.read.format("delta").load(SILVER_PATH).count()
print(f"✅ silver_nvd registered — Total rows: {count}")
