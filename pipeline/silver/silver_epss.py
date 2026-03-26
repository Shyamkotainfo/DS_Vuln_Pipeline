# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer — EPSS
# MAGIC Casts scores to double, validates CVE format, deduplicates.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from pyspark.sql.window import Window

# COMMAND ----------

df = spark.table(BRONZE_TABLES["epss"])
df = df.withColumn("cve_id", F.upper(F.trim(F.col("cve"))))
df = df.withColumn("epss_score", F.col("epss").cast(DoubleType()))
df = df.withColumn("epss_percentile", F.col("percentile").cast(DoubleType()))
df = df.withColumn("score_date", F.to_date("date", "yyyy-MM-dd"))
df = df.withColumn("epss_score", F.when(F.col("epss_score") > 1.0, 1.0).when(F.col("epss_score") < 0.0, 0.0).otherwise(F.col("epss_score")))
df = df.withColumn("epss_percentile", F.when(F.col("epss_percentile") > 1.0, 1.0).when(F.col("epss_percentile") < 0.0, 0.0).otherwise(F.col("epss_percentile")))

# COMMAND ----------

df = df.filter(F.col("cve_id").isNotNull() & F.col("cve_id").rlike(r"^CVE-\d{4}-\d{4,}$") & F.col("epss_score").isNotNull())
w = Window.partitionBy("cve_id", "score_date").orderBy(F.col("_ingested_at").desc())
df = df.withColumn("_rn", F.row_number().over(w)).filter(F.col("_rn") == 1).drop("_rn")

# COMMAND ----------

df_silver = df.select("cve_id", "epss_score", "epss_percentile", "score_date",
                       "_ingested_at", "_source", "_batch_id", "year", "month", "day")

TABLE_NAME = SILVER_TABLES["epss"]
df_silver.write.format("delta").mode("overwrite").option("overwriteSchema", "true") \
    .partitionBy("year", "month", "day").saveAsTable(TABLE_NAME)
print(f"✅ {TABLE_NAME} — {spark.table(TABLE_NAME).count()} rows")
