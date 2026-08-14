#!/usr/bin/env python3
"""Audit every externally sourced firmware dependency against OSV."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(("git", *args), cwd=cwd, check=True, text=True,
                          capture_output=True).stdout.strip()


def require_match(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if match is None:
        raise RuntimeError(f"missing {label}")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    idf_path = Path(os.environ.get("IDF_PATH", r"C:\esp\v6.0.2\esp-idf")).resolve()
    lock_path = root / "dependencies.lock"
    lock_bytes = lock_path.read_bytes()
    lock_text = lock_bytes.decode("utf-8")
    cjson_version = require_match(r"^\s{4}version:\s*['\"]?([^'\"\s]+)", lock_text, "cJSON version")
    if cjson_version != "1.7.19~2":
        raise RuntimeError(f"unexpected cJSON version: {cjson_version}")
    idf_version = git("describe", "--tags", "--exact-match", cwd=idf_path)
    if idf_version != "v6.0.2":
        raise RuntimeError(f"ESP-IDF v6.0.2 required; found {idf_version}")
    idf_commit = git("rev-parse", "HEAD", cwd=idf_path)
    component_manifest = root / "managed_components" / "espressif__cjson" / "idf_component.yml"
    if not component_manifest.is_file():
        raise RuntimeError("managed cJSON metadata missing; complete an ESP-IDF build first")
    cjson_commit = require_match(
        r"^\s*commit_sha:\s*([0-9a-f]{40})\s*$",
        component_manifest.read_text(encoding="utf-8"), "cJSON source commit")
    subjects = [
        {"name": "espressif/esp-idf", "version": idf_version, "commit": idf_commit,
         "osv_query": {"commit": idf_commit}},
        {"name": "espressif/idf-extra-components/cjson", "version": cjson_version,
         "commit": cjson_commit, "osv_query": {"commit": cjson_commit}},
        {"name": "DaveGamble/cJSON", "version": "1.7.19",
         "purl": "pkg:github/DaveGamble/cJSON@v1.7.19",
         "osv_query": {"package": {"purl": "pkg:github/DaveGamble/cJSON@v1.7.19"}}},
    ]
    request_body = json.dumps({"queries": [item["osv_query"] for item in subjects]},
                              separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        OSV_BATCH_URL, data=request_body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "power-meter-dependency-audit/1.0"})
    with urllib.request.urlopen(request, timeout=args.timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"OSV returned HTTP {response.status}")
        result = json.load(response)
    results = result.get("results")
    if not isinstance(results, list) or len(results) != len(subjects):
        raise RuntimeError("OSV returned an incomplete query batch")
    vulnerabilities: list[dict[str, object]] = []
    for subject, item in zip(subjects, results, strict=True):
        for vulnerability in item.get("vulns", []):
            if vulnerability.get("withdrawn"):
                continue
            vulnerabilities.append({
                "subject": subject["name"],
                "id": vulnerability.get("id"),
                "aliases": sorted(vulnerability.get("aliases", [])),
                "modified": vulnerability.get("modified"),
            })
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    document = {
        "schema": "pm-dependency-audit/1.0.0",
        "generated_at": generated,
        "result": "pass" if not vulnerabilities else "fail",
        "scanner": {"name": "OSV querybatch API", "endpoint": OSV_BATCH_URL},
        "dependencies_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "subjects": subjects,
        "vulnerabilities": vulnerabilities,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")
    print(json.dumps({"result": document["result"], "subjects": len(subjects),
                      "vulnerabilities": len(vulnerabilities), "output": str(args.output)}))
    return 0 if document["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
