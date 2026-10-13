#!/usr/bin/env python3
"""
scripts/export_demo_cache.py
----------------------------
Copy real LLM cache files (cache/INC-*.json) into data/demo_cache/
so that a fresh clone can demo the UI offline.

Usage (from soc-copilot/ directory):
    python scripts/export_demo_cache.py

IMPORTANT: Only run this after you have live cache files from a real LLM call
(i.e. GROQ_API_KEY or ANTHROPIC_API_KEY was set and POST /incidents/{id}/summary
was triggered). Do NOT hand-craft summaries; they must come from a real LLM run.
"""
import glob
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(ROOT, "cache")
DEMO_CACHE_DIR = os.path.join(ROOT, "data", "demo_cache")

os.makedirs(DEMO_CACHE_DIR, exist_ok=True)

pattern = os.path.join(CACHE_DIR, "INC-*.json")
files = sorted(glob.glob(pattern))

if not files:
    print(f"No cache files found in {CACHE_DIR}. Run the app with a real API key first.")
    sys.exit(1)

copied = 0
skipped = 0
for src_path in files:
    fname = os.path.basename(src_path)
    # Validate the file has _meta and response fields before copying
    try:
        with open(src_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  SKIP {fname}: could not parse: {e}")
        skipped += 1
        continue

    if "_meta" not in data or "response" not in data:
        print(f"  SKIP {fname}: missing _meta or response (not a real LLM cache file)")
        skipped += 1
        continue

    if data.get("response", {}).get("status") == "unavailable":
        print(f"  SKIP {fname}: unavailable status (failed LLM call, not demo-worthy)")
        skipped += 1
        continue

    dest_path = os.path.join(DEMO_CACHE_DIR, fname)
    shutil.copy2(src_path, dest_path)
    print(f"  COPIED {fname} -> data/demo_cache/{fname}")
    copied += 1

print(f"\nDone: {copied} files copied, {skipped} skipped.")
print(f"Demo cache is at: {DEMO_CACHE_DIR}")
