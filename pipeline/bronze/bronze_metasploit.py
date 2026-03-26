# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Layer — Metasploit
# MAGIC Ingests Metasploit module metadata into Unity Catalog Delta table.

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

def extract_metasploit_data():
    url = SOURCES["metasploit"]["url"]
    print(f"Fetching Metasploit data from {url}...")
    try:
        response = requests.get(url, timeout=120)
        response.raise_for_status()
        data = response.json()
        records = []
        for fullname, metadata in data.items():
            records.append({
                "fullname": fullname,
                "name": metadata.get("name", ""),
                "title": metadata.get("title", ""),
                "aliases": json.dumps(metadata.get("aliases", [])),
                "rank": str(metadata.get("rank", "")),
                "disclosure_date": metadata.get("disclosure_date", ""),
                "type": metadata.get("type", ""),
                "platform": json.dumps(metadata.get("platform", [])),
                "arch": json.dumps(metadata.get("arch", [])),
                "rport": str(metadata.get("rport", "")),
                "autofilter_ports": json.dumps(metadata.get("autofilter_ports", [])),
                "autofilter_services": json.dumps(metadata.get("autofilter_services", [])),
                "targets": json.dumps(metadata.get("targets", [])),
                "mod_time": metadata.get("mod_time", ""),
                "path": metadata.get("path", ""),
                "is_install_path": str(metadata.get("is_install_path", "")),
                "ref_name": metadata.get("ref_name", ""),
                "check": str(metadata.get("check", "")),
                "post_auth": str(metadata.get("post_auth", "")),
                "default_credential": str(metadata.get("default_credential", "")),
                "notes": json.dumps(metadata.get("notes", {})),
                "session_types": json.dumps(metadata.get("session_types", [])),
                "needs_cleanup": str(metadata.get("needs_cleanup", "")),
                "actions": json.dumps(metadata.get("actions", [])),
                "author": json.dumps(metadata.get("author", [])),
                "description": metadata.get("description", ""),
                "references": json.dumps(metadata.get("references", [])),
            })
        print(f"Parsed {len(records)} Metasploit modules")
        return records
    except Exception as e:
        print(f"Error extracting Metasploit data: {e}")
        return []

# COMMAND ----------

TABLE_NAME = BRONZE_TABLES["metasploit"]
BATCH_ID = str(uuid.uuid4())
NOW = datetime.utcnow()

# COMMAND ----------

raw_records = extract_metasploit_data()

# COMMAND ----------

if raw_records:
    df_raw = spark.createDataFrame(raw_records)
else:
    df_raw = spark.createDataFrame([], BRONZE_SCHEMAS["metasploit"])

df_bronze = df_raw \
    .withColumn("_ingested_at", F.lit(NOW).cast(TimestampType())) \
    .withColumn("_source", F.lit("metasploit_github")) \
    .withColumn("_batch_id", F.lit(BATCH_ID)) \
    .withColumn("year", F.lit(NOW.year).cast(IntegerType())) \
    .withColumn("month", F.lit(NOW.month).cast(IntegerType())) \
    .withColumn("day", F.lit(NOW.day).cast(IntegerType()))

# COMMAND ----------

raw_size_bytes = df_bronze.count() * 1500
target_bytes = SYNTHETIC_CONFIG["target_daily_bytes"] * 0.15

if raw_size_bytes < target_bytes:
    print(f"Adding synthetic Metasploit data...")
    synth_data = generate_all_synthetic(spark, target_bytes=SYNTHETIC_CONFIG["target_daily_bytes"])
    df_synth = synth_data["metasploit"] \
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
