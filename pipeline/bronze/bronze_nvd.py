# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer — NVD (National Vulnerability Database)
# MAGIC Ingests raw CVE data from NVD REST API 2.0 into Unity Catalog Delta table.

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

def fetch_nvd_page(start_index=0, limit=2000, since=None, end=None, api_key=None):
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
            print(f"Rate limit hit. Sleeping 10s...")
            time.sleep(10)
            return fetch_nvd_page(start_index, limit, since, end, api_key)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", []), data.get("totalResults", 0)
    except Exception as e:
        print(f"Error fetching NVD at index {start_index}: {e}")
        return [], 0

def extract_nvd_data(since=None, api_key=None):
    start_date = datetime.fromisoformat(since) if since else datetime(1999, 1, 1)
    end_date = datetime.utcnow()
    delay = SOURCES["nvd"]["rate_limit_delay"] if api_key else SOURCES["nvd"]["rate_limit_delay_no_key"]
    batch_size = SOURCES["nvd"]["batch_size"]
    all_records = []
    current_start = start_date
    while current_start < end_date:
        current_end = min(current_start + timedelta(days=119), end_date)
        start_str = current_start.isoformat()
        end_str = current_end.isoformat()
        print(f"NVD window: {start_str} → {end_str}")
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

TABLE_NAME = BRONZE_TABLES["nvd"]
API_KEY = SOURCES["nvd"].get("api_key")
BATCH_ID = str(uuid.uuid4())
NOW = datetime.utcnow()

print(f"Bronze NVD — Target: {TABLE_NAME}")
print(f"API Key: {'configured' if API_KEY else 'not set (slower rate limit)'}")

# COMMAND ----------

# Incremental: check last ingested date
try:
    last_modified = spark.table(TABLE_NAME).agg(F.max("lastModified")).collect()[0][0]
    print(f"Incremental mode — since: {last_modified}")
except:
    last_modified = None
    print("Full load mode — no existing data found")

raw_records = extract_nvd_data(since=last_modified, api_key=API_KEY)
print(f"Extracted {len(raw_records)} NVD records from API")

# COMMAND ----------

if raw_records:
    df_raw = spark.createDataFrame(raw_records)
else:
    df_raw = spark.createDataFrame([], BRONZE_SCHEMAS["nvd"])

df_bronze = df_raw \
    .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
    .withColumn("_source", F.lit("nvd_api")) \
    .withColumn("_batch_id", F.lit(BATCH_ID)) \
    .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
    .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
    .withColumn("day", F.lit(NOW.day).cast(IntegerType()))

# COMMAND ----------

raw_size_bytes = df_bronze.count() * 2000
target_bytes = SYNTHETIC_CONFIG["target_daily_bytes"] * 0.35

if raw_size_bytes < target_bytes:
    print(f"Adding synthetic NVD data...")
    synth_data = generate_all_synthetic(spark, target_bytes=SYNTHETIC_CONFIG["target_daily_bytes"])
    df_synth = synth_data["nvd"] \
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
