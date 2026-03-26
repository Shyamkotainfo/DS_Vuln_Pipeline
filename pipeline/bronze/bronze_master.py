# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze Master — Concurrent Ingestion
# MAGIC Kicks off all 5 Bronze ingestion notebooks simultaneously using thread pools.
# MAGIC This significantly reduces total pipeline execution time.

# COMMAND ----------

from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# COMMAND ----------

# List of all bronze notebooks to execute
bronze_notebooks = [
    "bronze_nvd",
    "bronze_cisa",
    "bronze_epss",
    "bronze_exploitdb",
    "bronze_metasploit"
]

def run_notebook(notebook_name):
    """Executes a Databricks notebook and returns its status."""
    print(f"▶️ Starting {notebook_name}...")
    start_time = time.time()
    try:
        # Run notebook with a 1-hour timeout (3600 seconds)
        # Assuming this master is in the same directory as the bronze notebooks
        result = dbutils.notebook.run(notebook_name, 3600)
        duration = time.time() - start_time
        print(f"✅ Finished {notebook_name} in {duration:.1f}s")
        return {"notebook": notebook_name, "status": "SUCCESS", "error": None}
    except Exception as e:
        duration = time.time() - start_time
        print(f"❌ Failed {notebook_name} after {duration:.1f}s: {str(e)}")
        return {"notebook": notebook_name, "status": "FAILED", "error": str(e)}

# COMMAND ----------

print(f"Launching {len(bronze_notebooks)} Bronze ingestion tasks concurrently...")
start_all = time.time()

results = []
# Use ThreadPoolExecutor to run them in parallel
with ThreadPoolExecutor(max_workers=len(bronze_notebooks)) as executor:
    # Submit all tasks
    future_to_notebook = {
        executor.submit(run_notebook, nb): nb for nb in bronze_notebooks
    }
    
    # Collect results as they complete
    for future in as_completed(future_to_notebook):
        results.append(future.result())

total_duration = time.time() - start_all

# COMMAND ----------

# Print final execution summary
print("=" * 60)
print(f"Bronze Ingestion Summary (Total time: {total_duration:.1f}s)")
print("=" * 60)

failed = 0
for r in results:
    icon = "✅" if r["status"] == "SUCCESS" else "❌"
    print(f"{icon} {r['notebook'].ljust(20)} | {r['status']}")
    if r["status"] == "FAILED":
        failed += 1
        print(f"    Error: {r['error']}")

print("=" * 60)

# Fail the master notebook if any child failed
if failed > 0:
    raise Exception(f"{failed} out of {len(bronze_notebooks)} Bronze notebooks failed. See logs above.")
print("All Bronze data successfully ingested concurrently!")
