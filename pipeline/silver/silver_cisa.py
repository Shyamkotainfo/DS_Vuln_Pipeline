# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer — CISA KEV
# MAGIC Cleans CISA KEV Bronze data: parses dates, standardizes booleans, deduplicates.

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

BRONZE_PATH = BRONZE_TABLES["cisa"]
SILVER_PATH = SILVER_TABLES["cisa"]

df_bronze = spark.read.format("delta").load(BRONZE_PATH)
print(f"Bronze CISA rows: {df_bronze.count()}")

# COMMAND ----------

# ============================================================
# Transformations
# ============================================================

df = df_bronze

# 1. Standardize CVE ID
df = df.withColumn("cve_id", F.upper(F.trim(F.col("cveID"))))

# 2. Parse dates
df = df.withColumn("date_added", F.to_date("dateAdded", "yyyy-MM-dd"))
df = df.withColumn("due_date", F.to_date("dueDate", "yyyy-MM-dd"))
df = df.withColumn("date_released", F.to_date("dateReleased", "yyyy-MM-dd"))

# 3. Standardize ransomware boolean
df = df.withColumn(
    "is_ransomware_related",
    F.when(F.lower(F.col("knownRansomwareCampaignUse")) == "known", F.lit(True))
     .otherwise(F.lit(False))
)

# 4. Clean text fields
df = df.withColumn("vendor_project", F.trim(F.col("vendorProject")))
df = df.withColumn("product", F.trim(F.col("product")))
df = df.withColumn("vulnerability_name", F.trim(F.col("vulnerabilityName")))
df = df.withColumn("short_description", F.trim(F.col("shortDescription")))
df = df.withColumn("required_action", F.trim(F.col("requiredAction")))

# COMMAND ----------

# ============================================================
# Data Quality
# ============================================================

# Remove invalid CVEs
df = df.filter(F.col("cve_id").isNotNull() & F.col("cve_id").rlike(r"^CVE-\d{4}-\d{4,}$"))

# Deduplicate: keep latest per CVE
w = Window.partitionBy("cve_id").orderBy(F.col("_ingested_at").desc())
df = df.withColumn("_rn", F.row_number().over(w)).filter(F.col("_rn") == 1).drop("_rn")

print(f"Silver CISA rows after cleaning: {df.count()}")

# COMMAND ----------

# ============================================================
# Select Silver Columns
# ============================================================

df_silver = df.select(
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "short_description",
    "required_action",
    "due_date",
    "is_ransomware_related",
    "notes",
    "date_released",
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

print(f"✅ Silver CISA written to {SILVER_PATH}")

# COMMAND ----------

spark.sql(f"""
    CREATE TABLE IF NOT EXISTS silver_cisa
    USING DELTA
    LOCATION '{SILVER_PATH}'
""")

count = spark.read.format("delta").load(SILVER_PATH).count()
print(f"✅ silver_cisa registered — Total rows: {count}")
