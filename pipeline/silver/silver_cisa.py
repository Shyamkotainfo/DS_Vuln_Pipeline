# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer — CISA KEV
# MAGIC Cleans CISA KEV: parses dates, boolean flags, deduplicates.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from pyspark.sql.window import Window

# COMMAND ----------

df = spark.table(BRONZE_TABLES["cisa"])
df = df.withColumn("cve_id", F.upper(F.trim(F.col("cveID"))))
df = df.withColumn("date_added", F.to_date("dateAdded", "yyyy-MM-dd"))
df = df.withColumn("due_date", F.to_date("dueDate", "yyyy-MM-dd"))
df = df.withColumn("date_released", F.to_date("dateReleased", "yyyy-MM-dd"))
df = df.withColumn("is_ransomware_related", F.when(F.lower(F.col("knownRansomwareCampaignUse")) == "known", True).otherwise(False))
df = df.withColumn("vendor_project", F.trim(F.col("vendorProject")))
df = df.withColumn("product", F.trim(F.col("product")))
df = df.withColumn("vulnerability_name", F.trim(F.col("vulnerabilityName")))
df = df.withColumn("short_description", F.trim(F.col("shortDescription")))
df = df.withColumn("required_action", F.trim(F.col("requiredAction")))

# COMMAND ----------

df = df.filter(F.col("cve_id").isNotNull() & F.col("cve_id").rlike(r"^CVE-\d{4}-\d{4,}$"))
w = Window.partitionBy("cve_id").orderBy(F.col("_ingested_at").desc())
df = df.withColumn("_rn", F.row_number().over(w)).filter(F.col("_rn") == 1).drop("_rn")

# COMMAND ----------

df_silver = df.select(
    "cve_id", "vendor_project", "product", "vulnerability_name", "date_added",
    "short_description", "required_action", "due_date", "is_ransomware_related",
    "notes", "date_released", "_ingested_at", "_source", "_batch_id", "year", "month", "day",
)

TABLE_NAME = SILVER_TABLES["cisa"]
df_silver.write.format("delta").mode("overwrite").option("overwriteSchema", "true") \
    .partitionBy("year", "month", "day").saveAsTable(TABLE_NAME)
print(f"✅ {TABLE_NAME} — {spark.table(TABLE_NAME).count()} rows")
