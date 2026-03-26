# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer — NVD
# MAGIC Cleans and flattens NVD Bronze data. Extracts CVSS v3.1 scores, deduplicates.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from pyspark.sql.window import Window

# COMMAND ----------

df_bronze = spark.table(BRONZE_TABLES["nvd"])
print(f"Bronze NVD rows: {df_bronze.count()}")

# COMMAND ----------

df = df_bronze
df = df.withColumn("description_en", F.get_json_object(F.col("descriptions"), "$[0].value"))
df = df.withColumn("cvss_v31_base_score", F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.baseScore").cast(DoubleType()))
df = df.withColumn("cvss_v31_severity", F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.baseSeverity"))
df = df.withColumn("cvss_v31_vector", F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.vectorString"))
df = df.withColumn("cvss_v31_attack_vector", F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.attackVector"))
df = df.withColumn("cvss_v31_attack_complexity", F.get_json_object(F.col("metrics"), "$.cvssMetricV31[0].cvssData.attackComplexity"))
df = df.withColumn("primary_cwe", F.get_json_object(F.col("weaknesses"), "$[0].description[0].value"))
df = df.withColumn("published_ts", F.to_timestamp("published"))
df = df.withColumn("last_modified_ts", F.to_timestamp("lastModified"))
df = df.withColumn("cve_id", F.upper(F.trim(F.col("id"))))

# COMMAND ----------

df = df.filter(F.col("cve_id").isNotNull() & F.col("cve_id").rlike(r"^CVE-\d{4}-\d{4,}$"))
w = Window.partitionBy("cve_id").orderBy(F.col("last_modified_ts").desc(), F.col("_ingested_at").desc())
df = df.withColumn("_row_num", F.row_number().over(w)).filter(F.col("_row_num") == 1).drop("_row_num")
df = df.fillna({"cvss_v31_base_score": 0.0, "cvss_v31_severity": "UNKNOWN"})
print(f"Silver NVD rows: {df.count()}")

# COMMAND ----------

df_silver = df.select(
    "cve_id", "sourceIdentifier", "published_ts", "last_modified_ts", "vulnStatus",
    "description_en", "cvss_v31_base_score", "cvss_v31_severity", "cvss_v31_vector",
    "cvss_v31_attack_vector", "cvss_v31_attack_complexity", "primary_cwe", "references",
    "_ingested_at", "_source", "_batch_id", "year", "month", "day",
)

TABLE_NAME = SILVER_TABLES["nvd"]
df_silver.write.format("delta").mode("overwrite").option("overwriteSchema", "true") \
    .partitionBy("year", "month", "day").saveAsTable(TABLE_NAME)
print(f"✅ {TABLE_NAME} — {spark.table(TABLE_NAME).count()} rows")
