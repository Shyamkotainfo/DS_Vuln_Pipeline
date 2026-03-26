# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer — EPSS (Exploit Prediction Scoring System)
# MAGIC Ingests EPSS probability scores from Cyentia CSV feed into Delta table.
# MAGIC Partitioned by `year/month/day`.

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

# ============================================================
# EPSS Extraction
# ============================================================

def extract_epss_data():
    """Fetch and parse EPSS scores from compressed CSV."""
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
                    # Header line
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

# ============================================================
# Main Bronze Ingestion
# ============================================================

TABLE_PATH = BRONZE_TABLES["epss"]
BATCH_ID = str(uuid.uuid4())
NOW = datetime.utcnow()

print(f"Bronze EPSS — Target: {TABLE_PATH}")

# COMMAND ----------

# Step 1: Extract
raw_records, score_date = extract_epss_data()
print(f"Extracted {len(raw_records)} EPSS records for date: {score_date}")

# COMMAND ----------

# Step 2: Convert to DataFrame & add metadata
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

print(f"Raw record count: {df_bronze.count()}")

# COMMAND ----------

# Step 3: Synthetic augmentation
raw_size_bytes = df_bronze.count() * 100
target_bytes = SYNTHETIC_CONFIG["target_daily_bytes"] * 0.30  # EPSS = 30%

if raw_size_bytes < target_bytes:
    print(f"Raw ~{raw_size_bytes/(1024*1024):.1f} MB < target {target_bytes/(1024*1024):.1f} MB — adding synthetic")
    synth_data = generate_all_synthetic(spark, target_bytes=SYNTHETIC_CONFIG["target_daily_bytes"])
    df_synth = synth_data["epss"] \
        .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
        .withColumn("_source", F.lit("synthetic")) \
        .withColumn("_batch_id", F.lit(BATCH_ID)) \
        .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
        .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
        .withColumn("day", F.lit(NOW.day).cast(IntegerType()))
    df_bronze = df_bronze.unionByName(df_synth, allowMissingColumns=True)
    print(f"After augmentation: {df_bronze.count()} records")
else:
    print(f"Data volume sufficient: ~{raw_size_bytes/(1024*1024):.1f} MB")

# COMMAND ----------

# Step 4: Write to Delta
df_bronze.write \
    .format("delta") \
    .mode("append") \
    .partitionBy("year", "month", "day") \
    .save(TABLE_PATH)

print(f"✅ Bronze EPSS written to {TABLE_PATH}")

# COMMAND ----------

# Step 5: Register table
spark.sql(f"""
    CREATE TABLE IF NOT EXISTS bronze_epss
    USING DELTA
    LOCATION '{TABLE_PATH}'
""")

count = spark.read.format("delta").load(TABLE_PATH).count()
print(f"✅ bronze_epss registered — Total rows: {count}")
