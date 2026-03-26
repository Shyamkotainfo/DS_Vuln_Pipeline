# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer — EPSS (Exploit Prediction Scoring System)
# MAGIC Ingests EPSS scores into Unity Catalog Delta table.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

# MAGIC %run ../utils/synthetic_generator

# COMMAND ----------

import requests
import csv
import gzip
import re
import uuid
from datetime import datetime
from pyspark.sql import functions as F
from pyspark.sql.types import *

# COMMAND ----------

def extract_epss_data():
    url = SOURCES["epss"]["url"]
    print(f"Fetching EPSS data from {url}...")
    try:
        response = requests.get(url, timeout=60, stream=True)
        response.raise_for_status()
        records = []
        score_date = None
        with gzip.open(response.raw, mode='rt', encoding='utf-8') as f:
            fieldnames = None
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    match = re.search(r'score_date:(\d{4}-\d{2}-\d{2})', line)
                    if match:
                        score_date = match.group(1)
                else:
                    fieldnames = line.split(',')
                    break
            if not fieldnames:
                print("EPSS header not found.")
                return [], None
            print(f"EPSS score date: {score_date}")
            reader = csv.DictReader(f, fieldnames=fieldnames)
            for row in reader:
                row['date'] = score_date or datetime.utcnow().strftime("%Y-%m-%d")
                records.append(row)
        print(f"Parsed {len(records)} EPSS records")
        return records, score_date
    except Exception as e:
        print(f"Error extracting EPSS data: {e}")
        return [], None

# COMMAND ----------

TABLE_NAME = BRONZE_TABLES["epss"]
BATCH_ID = str(uuid.uuid4())
NOW = datetime.utcnow()

# COMMAND ----------

raw_records, score_date = extract_epss_data()
print(f"Extracted {len(raw_records)} EPSS records for date: {score_date}")

# COMMAND ----------

if raw_records:
    df_raw = spark.createDataFrame(raw_records)
else:
    df_raw = spark.createDataFrame([], BRONZE_SCHEMAS["epss"])

df_bronze = df_raw \
    .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
    .withColumn("_source", F.lit("epss_api")) \
    .withColumn("_batch_id", F.lit(BATCH_ID)) \
    .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
    .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
    .withColumn("day", F.lit(NOW.day).cast(IntegerType()))

# COMMAND ----------

raw_size_bytes = df_bronze.count() * 100
target_bytes = SYNTHETIC_CONFIG["target_daily_bytes"] * 0.30

if raw_size_bytes < target_bytes:
    print(f"Raw ~{raw_size_bytes/(1024*1024):.1f} MB < target — adding synthetic")
    synth_data = generate_all_synthetic(spark, target_bytes=SYNTHETIC_CONFIG["target_daily_bytes"])
    df_synth = synth_data["epss"] \
        .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
        .withColumn("_source", F.lit("synthetic")) \
        .withColumn("_batch_id", F.lit(BATCH_ID)) \
        .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
        .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
        .withColumn("day", F.lit(NOW.day).cast(IntegerType()))
    df_bronze = df_bronze.unionByName(df_synth, allowMissingColumns=True)

# COMMAND ----------

df_bronze.write \
    .format("delta") \
    .mode("append") \
    .partitionBy("year", "month", "day") \
    .saveAsTable(TABLE_NAME)

print(f"✅ {TABLE_NAME} written — {spark.table(TABLE_NAME).count()} rows")
