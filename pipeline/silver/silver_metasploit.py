# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer — Metasploit
# MAGIC Cleans Metasploit Bronze data: extracts CVE IDs from references,
# MAGIC normalizes rank/platform, parses dates, deduplicates.

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

BRONZE_PATH = BRONZE_TABLES["metasploit"]
SILVER_PATH = SILVER_TABLES["metasploit"]

df_bronze = spark.read.format("delta").load(BRONZE_PATH)
print(f"Bronze Metasploit rows: {df_bronze.count()}")

# COMMAND ----------

# ============================================================
# Transformations
# ============================================================

df = df_bronze

# 1. Extract CVE IDs from references JSON array
# references: ["CVE-2021-1234","EDB-12345","URL-https://..."]
# Parse JSON array and filter for CVE patterns
df = df.withColumn(
    "refs_array",
    F.from_json(F.col("references"), ArrayType(StringType()))
)

df = df.withColumn(
    "cve_ids",
    F.expr("filter(refs_array, x -> x rlike '^CVE-[0-9]{4}-[0-9]+$')")
)

df = df.withColumn("cve_count", F.size(F.col("cve_ids")))

# 2. Normalize rank to numeric
rank_map = {
    "excellent": 7, "great": 6, "good": 5,
    "normal": 4, "average": 3, "low": 2, "manual": 1
}
rank_expr = F.col("rank")
for label, val in rank_map.items():
    rank_expr = F.when(F.lower(F.col("rank")) == label, F.lit(val)).otherwise(rank_expr)
df = df.withColumn("rank_numeric", rank_expr.cast(IntegerType()))
df = df.withColumn("rank_label", F.lower(F.trim(F.col("rank"))))

# 3. Parse dates
df = df.withColumn("disclosure_date_dt", F.to_date("disclosure_date", "yyyy-MM-dd"))
# mod_time may be "2023-01-01 12:00:00 +0000"
df = df.withColumn("mod_time_ts", F.to_timestamp(F.substring("mod_time", 1, 19), "yyyy-MM-dd HH:mm:ss"))

# 4. Parse platform JSON array
df = df.withColumn(
    "platforms",
    F.from_json(F.col("platform"), ArrayType(StringType()))
)

# 5. Module type
df = df.withColumn("module_type", F.lower(F.trim(F.col("type"))))

# 6. Parse author
df = df.withColumn(
    "authors",
    F.from_json(F.col("author"), ArrayType(StringType()))
)

# COMMAND ----------

# ============================================================
# Data Quality
# ============================================================

# Remove rows without fullname
df = df.filter(F.col("fullname").isNotNull() & (F.col("fullname") != ""))

# Deduplicate by fullname
w = Window.partitionBy("fullname").orderBy(F.col("_ingested_at").desc())
df = df.withColumn("_rn", F.row_number().over(w)).filter(F.col("_rn") == 1).drop("_rn")

print(f"Silver Metasploit rows after cleaning: {df.count()}")

# COMMAND ----------

# ============================================================
# Select Silver Columns
# ============================================================

df_silver = df.select(
    "fullname",
    "name",
    "title",
    "module_type",
    "platforms",
    "rank_label",
    "rank_numeric",
    "disclosure_date_dt",
    "mod_time_ts",
    "description",
    "authors",
    "cve_ids",
    "cve_count",
    "rport",
    "check",
    "post_auth",
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

print(f"✅ Silver Metasploit written to {SILVER_PATH}")

# COMMAND ----------

spark.sql(f"""
    CREATE TABLE IF NOT EXISTS silver_metasploit
    USING DELTA
    LOCATION '{SILVER_PATH}'
""")

count = spark.read.format("delta").load(SILVER_PATH).count()
print(f"✅ silver_metasploit registered — Total rows: {count}")
