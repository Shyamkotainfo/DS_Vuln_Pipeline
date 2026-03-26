# Databricks notebook source
# MAGIC %md
# MAGIC # Silver Layer — Metasploit
# MAGIC Extracts CVE IDs from references, normalizes rank/platform, deduplicates.

# COMMAND ----------

# MAGIC %run ../config

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.types import *
from pyspark.sql.window import Window

# COMMAND ----------

df = spark.table(BRONZE_TABLES["metasploit"])
df = df.withColumn("refs_array", F.from_json(F.col("references"), ArrayType(StringType())))
df = df.withColumn("cve_ids", F.expr("filter(refs_array, x -> x rlike '^CVE-[0-9]{4}-[0-9]+$')"))
df = df.withColumn("cve_count", F.size(F.col("cve_ids")))

rank_map = {"excellent": 7, "great": 6, "good": 5, "normal": 4, "average": 3, "low": 2, "manual": 1}
rank_expr = F.col("rank")
for label, val in rank_map.items():
    rank_expr = F.when(F.lower(F.col("rank")) == label, F.lit(val)).otherwise(rank_expr)
df = df.withColumn("rank_numeric", rank_expr.cast(IntegerType()))
df = df.withColumn("rank_label", F.lower(F.trim(F.col("rank"))))
df = df.withColumn("disclosure_date_dt", F.to_date("disclosure_date", "yyyy-MM-dd"))
df = df.withColumn("mod_time_ts", F.to_timestamp(F.substring("mod_time", 1, 19), "yyyy-MM-dd HH:mm:ss"))
df = df.withColumn("platforms", F.from_json(F.col("platform"), ArrayType(StringType())))
df = df.withColumn("module_type", F.lower(F.trim(F.col("type"))))
df = df.withColumn("authors", F.from_json(F.col("author"), ArrayType(StringType())))

# COMMAND ----------

df = df.filter(F.col("fullname").isNotNull() & (F.col("fullname") != ""))
w = Window.partitionBy("fullname").orderBy(F.col("_ingested_at").desc())
df = df.withColumn("_rn", F.row_number().over(w)).filter(F.col("_rn") == 1).drop("_rn")

# COMMAND ----------

df_silver = df.select("fullname", "name", "title", "module_type", "platforms", "rank_label",
                       "rank_numeric", "disclosure_date_dt", "mod_time_ts", "description",
                       "authors", "cve_ids", "cve_count", "rport", "check", "post_auth",
                       "_ingested_at", "_source", "_batch_id", "year", "month", "day")

TABLE_NAME = SILVER_TABLES["metasploit"]
df_silver.write.format("delta").mode("overwrite").option("overwriteSchema", "true") \
    .partitionBy("year", "month", "day").saveAsTable(TABLE_NAME)
print(f"✅ {TABLE_NAME} — {spark.table(TABLE_NAME).count()} rows")
