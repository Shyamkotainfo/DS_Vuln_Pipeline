# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer — NVD (National Vulnerability Database)
# MAGIC Ingests raw CVE data from NVD REST API 2.0 into a Delta table.
# MAGIC Partitioned by `year/month/day`. Includes synthetic data augmentation.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

# MAGIC %run ../utils/synthetic_generator

# COMMAND ----------

import requests
import time
import json
import uuid
from datetime import datetime, timedelta
from pyspark.sql import functions as F
from pyspark.sql.types import *

# COMMAND ----------

# ============================================================
# NVD API Extraction
# ============================================================

def fetch_nvd_page(start_index=0, limit=2000, since=None, end=None, api_key=None):
    """Fetch a single page from NVD API."""
    base_url = SOURCES["nvd"]["url"]
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {"resultsPerPage": limit, "startIndex": start_index}
    if since:
        params["lastModStartDate"] = since
    if end:
        params["lastModEndDate"] = end

    try:
        response = requests.get(base_url, headers=headers, params=params, timeout=60)
        if response.status_code == 429:
            print(f"Rate limit hit at index {start_index}. Sleeping 10s...")
            time.sleep(10)
            return fetch_nvd_page(start_index, limit, since, end, api_key)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", []), data.get("totalResults", 0)
    except Exception as e:
        print(f"Error fetching NVD at index {start_index}: {e}")
        return [], 0


def extract_nvd_data(since=None, api_key=None):
    """Extract all NVD CVE data. Handles 120-day API window limit."""
    start_date = datetime.fromisoformat(since) if since else datetime(1999, 1, 1)
    end_date = datetime.utcnow()
    delay = SOURCES["nvd"]["rate_limit_delay"] if api_key else SOURCES["nvd"]["rate_limit_delay_no_key"]
    batch_size = SOURCES["nvd"]["batch_size"]
    
    all_records = []
    
    # Chunk into 119-day windows (NVD max is 120)
    current_start = start_date
    while current_start < end_date:
        current_end = min(current_start + timedelta(days=119), end_date)
        start_str = current_start.isoformat()
        end_str = current_end.isoformat()
        
        print(f"NVD window: {start_str} → {end_str}")
        
        # Get total count first
        _, total = fetch_nvd_page(0, 1, start_str, end_str, api_key)
        if total == 0:
            current_start = current_end
            continue
        
        print(f"  → {total} CVEs in this window")
        
        for offset in range(0, total, batch_size):
            vulns, _ = fetch_nvd_page(offset, batch_size, start_str, end_str, api_key)
            for v in vulns:
                cve = v.get("cve", {})
                all_records.append({
                    "id": cve.get("id"),
                    "sourceIdentifier": cve.get("sourceIdentifier"),
                    "published": cve.get("published"),
                    "lastModified": cve.get("lastModified"),
                    "vulnStatus": cve.get("vulnStatus"),
                    "cveTags": json.dumps(cve.get("cveTags", [])),
                    "descriptions": json.dumps(cve.get("descriptions", [])),
                    "metrics": json.dumps(cve.get("metrics", {})),
                    "weaknesses": json.dumps(cve.get("weaknesses", [])),
                    "configurations": json.dumps(cve.get("configurations", [])),
                    "references": json.dumps(cve.get("references", [])),
                })
            time.sleep(delay)
        
        current_start = current_end
    
    return all_records

# COMMAND ----------

# ============================================================
# Main Bronze Ingestion
# ============================================================

# Configuration
API_KEY = SOURCES["nvd"].get("api_key")
TABLE_PATH = BRONZE_TABLES["nvd"]
BATCH_ID = str(uuid.uuid4())
NOW = datetime.utcnow()

print(f"Bronze NVD — Target: {TABLE_PATH}")
print(f"Batch ID: {BATCH_ID}")
print(f"API Key: {'configured' if API_KEY else 'not set'}")

# COMMAND ----------

# ============================================================
# Step 1: Extract raw data from NVD API
# ============================================================

# For incremental: check last ingested date
try:
    existing_df = spark.read.format("delta").load(TABLE_PATH)
    last_modified = existing_df.agg(F.max("lastModified")).collect()[0][0]
    print(f"Incremental mode — since: {last_modified}")
except:
    last_modified = None
    print("Full load mode — no existing data found")

raw_records = extract_nvd_data(since=last_modified, api_key=API_KEY)
print(f"Extracted {len(raw_records)} NVD records from API")

# COMMAND ----------

# ============================================================
# Step 2: Convert to DataFrame & add metadata
# ============================================================

if raw_records:
    df_raw = spark.createDataFrame(raw_records)
else:
    # Empty DataFrame with schema
    df_raw = spark.createDataFrame([], BRONZE_SCHEMAS["nvd"])

# Add ingestion metadata
df_bronze = df_raw \
    .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
    .withColumn("_source", F.lit("nvd_api")) \
    .withColumn("_batch_id", F.lit(BATCH_ID)) \
    .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
    .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
    .withColumn("day", F.lit(NOW.day).cast(IntegerType()))

print(f"Raw record count: {df_bronze.count()}")

# COMMAND ----------

# ============================================================
# Step 3: Synthetic Data Augmentation (if < 1 GB)
# ============================================================

# Estimate current data size
raw_size_bytes = df_bronze.count() * 2000  # ~2KB per NVD record estimate
target_bytes = SYNTHETIC_CONFIG["target_daily_bytes"] * 0.35  # NVD's share is 35%

if raw_size_bytes < target_bytes:
    print(f"Raw data ~{raw_size_bytes/(1024*1024):.1f} MB < target {target_bytes/(1024*1024):.1f} MB")
    print("Generating synthetic NVD data...")
    
    synth_data = generate_all_synthetic(spark, target_bytes=SYNTHETIC_CONFIG["target_daily_bytes"])
    df_synth = synth_data["nvd"] \
        .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
        .withColumn("_source", F.lit("synthetic")) \
        .withColumn("_batch_id", F.lit(BATCH_ID)) \
        .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
        .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
        .withColumn("day", F.lit(NOW.day).cast(IntegerType()))
    
    df_bronze = df_bronze.unionByName(df_synth, allowMissingColumns=True)
    print(f"After synthetic augmentation: {df_bronze.count()} total records")
else:
    print(f"Data volume sufficient: ~{raw_size_bytes/(1024*1024):.1f} MB")

# COMMAND ----------

# ============================================================
# Step 4: Write to Delta with partitioning
# ============================================================

df_bronze.write \
    .format("delta") \
    .mode("append") \
    .partitionBy("year", "month", "day") \
    .save(TABLE_PATH)

print(f"✅ Bronze NVD written to {TABLE_PATH}")
print(f"   Partitioned by year={NOW.year}/month={NOW.month}/day={NOW.day}")

# COMMAND ----------

# ============================================================
# Step 5: Register as table (optional, for SQL access)
# ============================================================

spark.sql(f"""
    CREATE TABLE IF NOT EXISTS bronze_nvd
    USING DELTA
    LOCATION '{TABLE_PATH}'
""")

# Verify
count = spark.read.format("delta").load(TABLE_PATH).count()
print(f"✅ bronze_nvd registered — Total rows: {count}")
