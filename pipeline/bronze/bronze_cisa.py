# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer — CISA KEV (Known Exploited Vulnerabilities)
# MAGIC Ingests raw CISA KEV catalog into a Unity Catalog Delta table.
# MAGIC Partitioned by `year/month/day`.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

# MAGIC %run ../utils/synthetic_generator

# COMMAND ----------

import requests
import json
import uuid
from datetime import datetime
from pyspark.sql import functions as F
from pyspark.sql.types import *

# COMMAND ----------

def extract_cisa_data():
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    url = SOURCES["cisa"]["url"]
    print(f"Fetching CISA data from {url}...")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        catalog_version = data.get("catalogVersion")
        date_released = data.get("dateReleased")
        count = data.get("count")
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"Total CISA KEV records: {len(vulnerabilities)}")
        records = []
        for vuln in vulnerabilities:
            vuln["catalogVersion"] = catalog_version
            vuln["dateReleased"] = date_released
            vuln["count"] = str(count)
            records.append(vuln)
        return records
    except Exception as e:
        print(f"Error extracting CISA data: {e}")
        return []

# COMMAND ----------

TABLE_NAME = BRONZE_TABLES["cisa"]
BATCH_ID = str(uuid.uuid4())
NOW = datetime.utcnow()
print(f"Bronze CISA — Target: {TABLE_NAME}")

# COMMAND ----------

raw_records = extract_cisa_data()
print(f"Extracted {len(raw_records)} CISA records")

# COMMAND ----------

if raw_records:
    df_raw = spark.createDataFrame(raw_records)
else:
    df_raw = spark.createDataFrame([], BRONZE_SCHEMAS["cisa"])

df_bronze = df_raw \
    .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
    .withColumn("_source", F.lit("cisa_api")) \
    .withColumn("_batch_id", F.lit(BATCH_ID)) \
    .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
    .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
    .withColumn("day", F.lit(NOW.day).cast(IntegerType()))

print(f"Raw record count: {df_bronze.count()}")

# COMMAND ----------

# Synthetic data augmentation if needed
raw_size_bytes = df_bronze.count() * 500
target_bytes = SYNTHETIC_CONFIG["target_daily_bytes"] * 0.10

if raw_size_bytes < target_bytes:
    print(f"Raw ~{raw_size_bytes/(1024*1024):.1f} MB < target — adding synthetic")
    synth_data = generate_all_synthetic(spark, target_bytes=SYNTHETIC_CONFIG["target_daily_bytes"])
    df_synth = synth_data["cisa"] \
        .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
        .withColumn("_source", F.lit("synthetic")) \
        .withColumn("_batch_id", F.lit(BATCH_ID)) \
        .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
        .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
        .withColumn("day", F.lit(NOW.day).cast(IntegerType()))
    df_bronze = df_bronze.unionByName(df_synth, allowMissingColumns=True)
    print(f"After augmentation: {df_bronze.count()} records")

# COMMAND ----------

# Write to Unity Catalog managed table
df_bronze.write \
    .format("delta") \
    .mode("append") \
    .partitionBy("year", "month", "day") \
    .saveAsTable(TABLE_NAME)

print(f"✅ {TABLE_NAME} written — {df_bronze.count()} rows")

# COMMAND ----------

# Verify
count = spark.table(TABLE_NAME).count()
print(f"✅ {TABLE_NAME} — Total rows: {count}")
