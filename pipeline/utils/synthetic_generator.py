# Databricks notebook source
# MAGIC %md
# MAGIC # Synthetic Data Generator
# MAGIC Generates realistic synthetic vulnerability data to ensure ≥1 GB daily ingestion.
# MAGIC Maintains referential integrity across all 5 datasets via shared CVE IDs.

# COMMAND ----------

import random
import string
import json
import uuid
from datetime import datetime, timedelta
from pyspark.sql import SparkSession
from pyspark.sql.types import *
import pyspark.sql.functions as F

# COMMAND ----------

# ============================================================
# CVE ID Pool Generator
# Generates a shared pool of CVE IDs used across ALL datasets
# to maintain referential integrity for Gold-layer joins.
# ============================================================

class CVEPoolGenerator:
    """Generates a consistent pool of CVE IDs for cross-dataset integrity."""

    def __init__(self, seed=42):
        self.rng = random.Random(seed)
        self.pool = []

    def generate_pool(self, size=50000):
        """Generate a pool of unique CVE IDs."""
        cve_set = set()
        while len(cve_set) < size:
            year = self.rng.randint(2002, 2026)
            seq = self.rng.randint(1, 99999)
            cve_id = f"CVE-{year}-{seq:05d}"
            cve_set.add(cve_id)
        self.pool = sorted(list(cve_set))
        return self.pool

    def sample(self, n):
        """Sample n CVE IDs from the pool."""
        return self.rng.sample(self.pool, min(n, len(self.pool)))

# COMMAND ----------

# ============================================================
# Domain-Specific Generators
# ============================================================

VENDORS = [
    "Microsoft", "Google", "Apple", "Apache", "Cisco", "Oracle", "IBM",
    "Adobe", "VMware", "Red Hat", "Linux", "SAP", "Siemens", "Fortinet",
    "Palo Alto Networks", "Juniper", "F5", "Citrix", "Dell", "HP",
    "Atlassian", "Zoom", "Slack", "Salesforce", "Qualcomm", "Intel",
    "AMD", "NVIDIA", "WordPress", "Drupal", "Jenkins", "GitLab",
]

PRODUCTS = [
    "Windows Server 2019", "Chrome", "Safari", "HTTP Server", "IOS XE",
    "WebLogic Server", "DB2", "Acrobat Reader", "ESXi", "Enterprise Linux",
    "Kernel", "NetWeaver", "SIMATIC", "FortiOS", "PAN-OS", "Junos OS",
    "BIG-IP", "ADC", "PowerEdge", "ProLiant", "Confluence", "Meetings",
    "Desktop App", "CRM", "Snapdragon", "Core i9", "Ryzen", "GeForce",
    "Plugin Manager", "Core CMS", "Pipeline", "Runner",
]

PLATFORMS = [
    "windows", "linux", "macos", "android", "ios", "multiple",
    "unix", "hardware", "freebsd", "solaris", "aix",
]

EXPLOIT_TYPES = ["local", "remote", "webapps", "dos", "shellcode"]

WEAKNESS_TYPES = [
    "CWE-79", "CWE-89", "CWE-20", "CWE-22", "CWE-78", "CWE-119",
    "CWE-200", "CWE-264", "CWE-287", "CWE-352", "CWE-399", "CWE-416",
    "CWE-502", "CWE-611", "CWE-776", "CWE-918", "CWE-94", "CWE-77",
]

VULN_STATUSES = ["Analyzed", "Modified", "Awaiting Analysis", "Undergoing Analysis", "Rejected"]

MSF_TYPES = ["exploit", "auxiliary", "post", "payload", "encoder", "nop"]
MSF_RANKS = ["excellent", "great", "good", "normal", "average", "low", "manual"]
MSF_PLATFORMS_LIST = ["Windows", "Linux", "Unix", "macOS", "Android", "Multi"]

# COMMAND ----------

def _random_date(rng, start_year=2015, end_year=2026):
    """Generate a random date between start_year and end_year."""
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 3, 26)
    delta = (end - start).days
    return start + timedelta(days=rng.randint(0, max(delta, 1)))


def _random_description(rng):
    """Generate a realistic-sounding vulnerability description."""
    actions = [
        "allows remote attackers to execute arbitrary code",
        "could allow an authenticated attacker to escalate privileges",
        "enables denial of service via crafted packets",
        "allows unauthorized access to sensitive data",
        "permits cross-site scripting via user-supplied input",
        "allows SQL injection through unvalidated parameters",
        "enables buffer overflow via malformed request",
        "could allow remote code execution without authentication",
        "permits directory traversal leading to information disclosure",
        "allows server-side request forgery via crafted URL",
    ]
    components = [
        "the web management interface", "the REST API endpoint",
        "the authentication module", "the file upload handler",
        "the session management component", "the XML parser",
        "the network stack", "the kernel driver",
        "the database query engine", "the configuration parser",
    ]
    return f"A vulnerability in {rng.choice(components)} {rng.choice(actions)}."

# COMMAND ----------

# ============================================================
# Per-Source Synthetic Data Generators
# ============================================================

def generate_synthetic_nvd(cve_pool, rng, count=50000):
    """Generate synthetic NVD records."""
    records = []
    cves = cve_pool.sample(min(count, len(cve_pool.pool)))
    for cve_id in cves:
        pub_date = _random_date(rng)
        mod_date = pub_date + timedelta(days=rng.randint(0, 365))
        cvss_score = round(rng.uniform(0.0, 10.0), 1)
        records.append({
            "id": cve_id,
            "sourceIdentifier": f"{rng.choice(['cve', 'nvd', 'vendor'])}@nist.gov",
            "published": pub_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModified": mod_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "vulnStatus": rng.choice(VULN_STATUSES),
            "cveTags": json.dumps([]),
            "descriptions": json.dumps([
                {"lang": "en", "value": _random_description(rng)}
            ]),
            "metrics": json.dumps({
                "cvssMetricV31": [{
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": cvss_score,
                        "baseSeverity": (
                            "CRITICAL" if cvss_score >= 9.0 else
                            "HIGH" if cvss_score >= 7.0 else
                            "MEDIUM" if cvss_score >= 4.0 else "LOW"
                        ),
                        "vectorString": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "NETWORK",
                        "attackComplexity": rng.choice(["LOW", "HIGH"]),
                    }
                }]
            }),
            "weaknesses": json.dumps([{
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [{"lang": "en", "value": rng.choice(WEAKNESS_TYPES)}]
            }]),
            "configurations": json.dumps([]),
            "references": json.dumps([{
                "url": f"https://example.com/advisory/{cve_id.lower()}",
                "source": "vendor",
            }]),
        })
    return records


def generate_synthetic_cisa(cve_pool, rng, count=5000):
    """Generate synthetic CISA KEV records (subset of CVEs)."""
    records = []
    cves = cve_pool.sample(min(count, len(cve_pool.pool)))
    for cve_id in cves:
        vendor = rng.choice(VENDORS)
        product = rng.choice(PRODUCTS)
        date_added = _random_date(rng, 2020, 2026)
        due_date = date_added + timedelta(days=rng.choice([14, 21, 30, 60]))
        records.append({
            "cveID": cve_id,
            "vendorProject": vendor,
            "product": product,
            "vulnerabilityName": f"{vendor} {product} {rng.choice(['RCE', 'Privilege Escalation', 'XSS', 'SQLi', 'DoS', 'Info Disclosure'])}",
            "dateAdded": date_added.strftime("%Y-%m-%d"),
            "shortDescription": _random_description(rng),
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": due_date.strftime("%Y-%m-%d"),
            "knownRansomwareCampaignUse": rng.choice(["Known", "Unknown"]),
            "notes": "",
            "catalogVersion": "2024.03.26",
            "dateReleased": "2024-03-26",
            "count": str(count),
        })
    return records


def generate_synthetic_epss(cve_pool, rng, count=50000):
    """Generate synthetic EPSS scores for CVEs."""
    records = []
    cves = cve_pool.sample(min(count, len(cve_pool.pool)))
    score_date = datetime.now().strftime("%Y-%m-%d")
    for cve_id in cves:
        epss_score = round(rng.uniform(0.0, 1.0), 5)
        percentile = round(rng.uniform(0.0, 1.0), 5)
        records.append({
            "cve": cve_id,
            "epss": str(epss_score),
            "percentile": str(percentile),
            "date": score_date,
        })
    return records


def generate_synthetic_exploitdb(cve_pool, rng, count=20000):
    """Generate synthetic ExploitDB records."""
    records = []
    cves = cve_pool.sample(min(count, len(cve_pool.pool)))
    for i, cve_id in enumerate(cves):
        exploit_id = str(40000 + i)
        pub_date = _random_date(rng, 2010, 2026)
        # Each exploit can reference 1-3 CVEs
        num_codes = rng.randint(1, 3)
        code_cves = [cve_id] + cve_pool.sample(min(num_codes - 1, len(cve_pool.pool)))
        codes = ";".join(code_cves[:num_codes])
        records.append({
            "id": exploit_id,
            "file": f"exploits/{rng.choice(PLATFORMS)}/{rng.choice(EXPLOIT_TYPES)}/{exploit_id}.py",
            "description": _random_description(rng),
            "date_published": pub_date.strftime("%Y-%m-%d"),
            "author": f"researcher_{rng.randint(1, 500)}",
            "platform": rng.choice(PLATFORMS),
            "type": rng.choice(EXPLOIT_TYPES),
            "port": str(rng.choice([0, 21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443])),
            "codes": codes,
        })
    return records


def generate_synthetic_metasploit(cve_pool, rng, count=5000):
    """Generate synthetic Metasploit module records."""
    records = []
    cves = cve_pool.sample(min(count, len(cve_pool.pool)))
    for i, cve_id in enumerate(cves):
        msf_type = rng.choice(MSF_TYPES)
        platform = rng.choice(MSF_PLATFORMS_LIST).lower()
        mod_date = _random_date(rng, 2012, 2026)
        disc_date = mod_date - timedelta(days=rng.randint(30, 730))
        # References include CVE + other refs
        refs = [cve_id, f"EDB-{40000 + i}", f"URL-https://example.com/vuln/{cve_id.lower()}"]
        records.append({
            "fullname": f"{msf_type}/{platform}/misc/synth_module_{i}",
            "name": f"synth_module_{i}",
            "title": f"Synthetic {rng.choice(VENDORS)} {rng.choice(PRODUCTS)} {msf_type.title()}",
            "aliases": json.dumps([]),
            "rank": rng.choice(MSF_RANKS),
            "disclosure_date": disc_date.strftime("%Y-%m-%d"),
            "type": msf_type,
            "platform": json.dumps([platform]),
            "arch": json.dumps([rng.choice(["x86", "x64", "armle", ""])]),
            "rport": str(rng.choice([22, 80, 443, 445, 1433, 3306, 3389, 8080])),
            "autofilter_ports": json.dumps([]),
            "autofilter_services": json.dumps([]),
            "targets": json.dumps(["Automatic"]),
            "mod_time": mod_date.strftime("%Y-%m-%d %H:%M:%S +0000"),
            "path": f"/modules/{msf_type}/{platform}/misc/synth_module_{i}.rb",
            "is_install_path": "true",
            "ref_name": f"{msf_type}/{platform}/misc/synth_module_{i}",
            "check": str(rng.choice([True, False])).lower(),
            "post_auth": str(rng.choice([True, False])).lower(),
            "default_credential": str(rng.choice([True, False])).lower(),
            "notes": json.dumps({}),
            "session_types": json.dumps([]),
            "needs_cleanup": str(rng.choice([True, False])).lower(),
            "actions": json.dumps([]),
            "author": json.dumps([f"researcher_{rng.randint(1, 200)}"]),
            "description": _random_description(rng),
            "references": json.dumps(refs),
        })
    return records

# COMMAND ----------

# ============================================================
# Main Synthetic Data Entry Point
# ============================================================

def generate_all_synthetic(spark, target_bytes=1 * 1024 * 1024 * 1024, seed=None):
    """
    Generate synthetic data for all 5 sources.
    Returns dict of {source_name: spark_dataframe}.
    Scales record counts to meet target_bytes.
    """
    if seed is None:
        seed = int(datetime.now().strftime("%Y%m%d"))
    
    rng = random.Random(seed)
    cve_pool = CVEPoolGenerator(seed=seed)
    cve_pool.generate_pool(size=60000)

    # Approximate bytes per record (rough estimates)
    bytes_per_record = {
        "nvd": 2000,
        "cisa": 500,
        "epss": 100,
        "exploitdb": 400,
        "metasploit": 1500,
    }
    
    # Distribution weights (NVD & EPSS are largest)
    weights = {"nvd": 0.35, "cisa": 0.10, "epss": 0.30, "exploitdb": 0.10, "metasploit": 0.15}
    
    counts = {}
    for source, weight in weights.items():
        source_bytes = target_bytes * weight
        counts[source] = max(1000, int(source_bytes / bytes_per_record[source]))
    
    print(f"Synthetic record counts: {counts}")
    
    generators = {
        "nvd": generate_synthetic_nvd,
        "cisa": generate_synthetic_cisa,
        "epss": generate_synthetic_epss,
        "exploitdb": generate_synthetic_exploitdb,
        "metasploit": generate_synthetic_metasploit,
    }
    
    result = {}
    for source, gen_fn in generators.items():
        print(f"Generating synthetic {source} data ({counts[source]} records)...")
        records = gen_fn(cve_pool, rng, count=counts[source])
        df = spark.createDataFrame(records)
        result[source] = df
        print(f"  → {source}: {df.count()} rows, ~{df.count() * bytes_per_record[source] / (1024*1024):.1f} MB estimated")
    
    return result
