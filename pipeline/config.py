# Databricks notebook source
# MAGIC %md
# MAGIC # Pipeline Configuration
# MAGIC Central configuration for the Medallion Architecture pipeline.
# MAGIC Update `GCS_BUCKET` and `CATALOG`/`DATABASE` to match your environment.

# COMMAND ----------

# ============================================================
# GCS & Delta Lake Configuration
# ============================================================

# -- Update this to your GCP Cloud Storage bucket --
GCS_BUCKET = "gs://observability_data_pipeline"

# Base paths for each layer
BASE_PATH = f"{GCS_BUCKET}/vulnerability_pipeline"
BRONZE_PATH = f"{BASE_PATH}/bronze"
SILVER_PATH = f"{BASE_PATH}/silver"
GOLD_PATH   = f"{BASE_PATH}/gold"

# Unity Catalog (optional — set to None if not using UC)
CATALOG  = "vulnerability_catalog"
DATABASE = "vuln_db"

# COMMAND ----------

# ============================================================
# Table Names
# ============================================================

BRONZE_TABLES = {
    "nvd":        f"{BRONZE_PATH}/nvd",
    "cisa":       f"{BRONZE_PATH}/cisa",
    "epss":       f"{BRONZE_PATH}/epss",
    "exploitdb":  f"{BRONZE_PATH}/exploitdb",
    "metasploit": f"{BRONZE_PATH}/metasploit",
}

SILVER_TABLES = {
    "nvd":        f"{SILVER_PATH}/nvd",
    "cisa":       f"{SILVER_PATH}/cisa",
    "epss":       f"{SILVER_PATH}/epss",
    "exploitdb":  f"{SILVER_PATH}/exploitdb",
    "metasploit": f"{SILVER_PATH}/metasploit",
}

GOLD_TABLES = {
    "vulnerability_master": f"{GOLD_PATH}/vulnerability_master",
    "risk_scoring":         f"{GOLD_PATH}/risk_scoring",
    "trend_analytics":      f"{GOLD_PATH}/trend_analytics",
    "exploit_readiness":    f"{GOLD_PATH}/exploit_readiness",
    "kpis":                 f"{GOLD_PATH}/kpis",
}

# COMMAND ----------

# ============================================================
# API / Source URLs
# ============================================================

SOURCES = {
    "nvd": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "api_key": None,  # Set below after try/except
        "rate_limit_delay": 0.6,   # seconds between calls with API key
        "rate_limit_delay_no_key": 6.0,
        "batch_size": 2000,
        "max_workers": 5,
    },
    "cisa": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    },
    "epss": {
        "url": "https://epss.cyentia.com/epss_scores-current.csv.gz",
    },
    "exploitdb": {
        "csv_url": "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    },
    "metasploit": {
        "url": "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
    },
}

# Try to load NVD API key from Databricks secrets (optional)
try:
    SOURCES["nvd"]["api_key"] = dbutils.secrets.get(scope="vuln-pipeline", key="nvd-api-key")
    print("✅ NVD API key loaded from secrets")
except Exception:
    SOURCES["nvd"]["api_key"] = None
    print("ℹ️ NVD API key not configured — using public rate limit (6s delay)")

# COMMAND ----------

# ============================================================
# Synthetic Data Configuration
# ============================================================

SYNTHETIC_CONFIG = {
    "target_daily_bytes": 1 * 1024 * 1024 * 1024,  # 1 GB
    "cve_id_range_start": 2002,
    "cve_id_range_end": 2026,
    "max_cve_seq": 99999,
}

# COMMAND ----------

# ============================================================
# Schema Definitions (PySpark StructType)
# ============================================================

from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType, DoubleType,
    BooleanType, ArrayType, MapType, TimestampType, DateType, LongType
)

BRONZE_SCHEMAS = {
    "cisa": StructType([
        StructField("cveID", StringType(), True),
        StructField("vendorProject", StringType(), True),
        StructField("product", StringType(), True),
        StructField("vulnerabilityName", StringType(), True),
        StructField("dateAdded", StringType(), True),
        StructField("shortDescription", StringType(), True),
        StructField("requiredAction", StringType(), True),
        StructField("dueDate", StringType(), True),
        StructField("knownRansomwareCampaignUse", StringType(), True),
        StructField("notes", StringType(), True),
        StructField("catalogVersion", StringType(), True),
        StructField("dateReleased", StringType(), True),
        StructField("count", StringType(), True),
        StructField("_ingested_at", TimestampType(), True),
        StructField("_source", StringType(), True),
        StructField("_batch_id", StringType(), True),
        StructField("year", IntegerType(), True),
        StructField("month", IntegerType(), True),
        StructField("day", IntegerType(), True),
    ]),

    "epss": StructType([
        StructField("cve", StringType(), True),
        StructField("epss", StringType(), True),
        StructField("percentile", StringType(), True),
        StructField("date", StringType(), True),
        StructField("_ingested_at", TimestampType(), True),
        StructField("_source", StringType(), True),
        StructField("_batch_id", StringType(), True),
        StructField("year", IntegerType(), True),
        StructField("month", IntegerType(), True),
        StructField("day", IntegerType(), True),
    ]),

    "exploitdb": StructType([
        StructField("id", StringType(), True),
        StructField("file", StringType(), True),
        StructField("description", StringType(), True),
        StructField("date_published", StringType(), True),
        StructField("author", StringType(), True),
        StructField("platform", StringType(), True),
        StructField("type", StringType(), True),
        StructField("port", StringType(), True),
        StructField("codes", StringType(), True),
        StructField("_ingested_at", TimestampType(), True),
        StructField("_source", StringType(), True),
        StructField("_batch_id", StringType(), True),
        StructField("year", IntegerType(), True),
        StructField("month", IntegerType(), True),
        StructField("day", IntegerType(), True),
    ]),

    "metasploit": StructType([
        StructField("fullname", StringType(), True),
        StructField("name", StringType(), True),
        StructField("title", StringType(), True),
        StructField("aliases", StringType(), True),
        StructField("rank", StringType(), True),
        StructField("disclosure_date", StringType(), True),
        StructField("type", StringType(), True),
        StructField("platform", StringType(), True),
        StructField("arch", StringType(), True),
        StructField("rport", StringType(), True),
        StructField("autofilter_ports", StringType(), True),
        StructField("autofilter_services", StringType(), True),
        StructField("targets", StringType(), True),
        StructField("mod_time", StringType(), True),
        StructField("path", StringType(), True),
        StructField("is_install_path", StringType(), True),
        StructField("ref_name", StringType(), True),
        StructField("check", StringType(), True),
        StructField("post_auth", StringType(), True),
        StructField("default_credential", StringType(), True),
        StructField("notes", StringType(), True),
        StructField("session_types", StringType(), True),
        StructField("needs_cleanup", StringType(), True),
        StructField("actions", StringType(), True),
        StructField("author", StringType(), True),
        StructField("description", StringType(), True),
        StructField("references", StringType(), True),
        StructField("_ingested_at", TimestampType(), True),
        StructField("_source", StringType(), True),
        StructField("_batch_id", StringType(), True),
        StructField("year", IntegerType(), True),
        StructField("month", IntegerType(), True),
        StructField("day", IntegerType(), True),
    ]),

    "nvd": StructType([
        StructField("id", StringType(), True),
        StructField("sourceIdentifier", StringType(), True),
        StructField("published", StringType(), True),
        StructField("lastModified", StringType(), True),
        StructField("vulnStatus", StringType(), True),
        StructField("cveTags", StringType(), True),
        StructField("descriptions", StringType(), True),
        StructField("metrics", StringType(), True),
        StructField("weaknesses", StringType(), True),
        StructField("configurations", StringType(), True),
        StructField("references", StringType(), True),
        StructField("_ingested_at", TimestampType(), True),
        StructField("_source", StringType(), True),
        StructField("_batch_id", StringType(), True),
        StructField("year", IntegerType(), True),
        StructField("month", IntegerType(), True),
        StructField("day", IntegerType(), True),
    ]),
}
