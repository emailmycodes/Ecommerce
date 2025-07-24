#!/usr/bin/env python3

import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Union
from collections import defaultdict

# Configurable paths
INPUT_FILE = Path("snyk-results.json")
OUTPUT_FILE = Path("scripts/snyk-summary.txt")

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def load_snyk_results(file_path: Path) -> List[Dict[str, Any]]:
    """
    Load JSON content from the Snyk scan results file.
    Supports both single JSON and newline-delimited JSON format.
    """
    if not file_path.exists():
        logging.error(f"Snyk result file not found: {file_path}")
        return []

    try:
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            logging.warning("Snyk result file is empty.")
            return []

        try:
            data = json.loads(content)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # Attempt line-by-line parsing (for NDJSON format)
            parsed_projects = []
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed_projects.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return parsed_projects

    except Exception as e:
        logging.error(f"Failed to load Snyk results: {e}")
        return []


def extract_project_info(project: Dict[str, Any]) -> Dict[str, Union[str, int, Dict[str, int], bool]]:
    """
    Extract relevant details from a single Snyk project scan.
    """
    severity_counts = defaultdict(int)
    vulnerabilities = project.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "unknown").lower()
        severity_counts[severity] += 1

    return {
        "project_name": project.get("projectName", "Unknown Project"),
        "package_manager": project.get("packageManager", "Unknown"),
        "target_file": project.get("targetFile", "Unknown"),
        "dependency_count": project.get("dependencyCount", 0),
        "total_vulnerabilities": len(vulnerabilities),
        "severity_counts": dict(severity_counts),
        "ok": project.get("ok", False)
    }


def summarize_projects(projects_info: List[Dict[str, Any]]) -> str:
    """
    Create a formatted Markdown vulnerability summary for all scanned projects.
    """
    total_projects = len(projects_info)
    total_vulnerabilities = sum(p["total_vulnerabilities"] for p in projects_info)
    affected_projects = sum(1 for p in projects_info if p["total_vulnerabilities"] > 0)

    output: List[str] = [
        "# 🔍 Snyk Vulnerability Summary",
        "",
        "## Overall Summary",
        f"- **Total Projects Scanned:** {total_projects}",
        f"- **Projects with Vulnerabilities:** {affected_projects}",
        f"- **Total Vulnerabilities:** {total_vulnerabilities}",
        ""
    ]

    # Global severity breakdown
    global_severity: Dict[str, int] = defaultdict(int)
    for p in projects_info:
        for sev, count in p["severity_counts"].items():
            global_severity[sev] += count

    if total_vulnerabilities:
        output.append("### Severity Breakdown")
        for sev in ["critical", "high", "medium", "low"]:
            count = global_severity.get(sev, 0)
            if count > 0:
                output.append(f"- **{sev.capitalize()}:** {count}")
        output.append("")

    # Per project section
    for project in projects_info:
        output.extend([
            f"## 📦 Project: `{project['project_name']}`",
            f"- **Target File:** `{project['target_file']}`",
            f"- **Package Manager:** {project['package_manager']}",
            f"- **Dependencies:** {project['dependency_count']}",
            f"- **Total Vulnerabilities:** {project['total_vulnerabilities']}"
        ])
        if project["total_vulnerabilities"] > 0:
            output.append("- **Severity Counts:**")
            for sev in ["critical", "high", "medium", "low"]:
                count = project["severity_counts"].get(sev, 0)
                if count > 0:
                    output.append(f"  - {sev.capitalize()}: {count}")
        else:
            output.append("- ✅ No vulnerabilities found.")
        output.append("")

    return "\n".join(output)


def write_summary(content: str, output_path: Path) -> None:
    """
    Write the summary content to a file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    logging.info(f"Summary written to: {output_path}")


def main() -> None:
    """
    Main script function.
    """
    projects = load_snyk_results(INPUT_FILE)
    if not projects:
        logging.warning("No valid Snyk project data to summarize.")
        return

    projects_info = [extract_project_info(p) for p in projects]
    summary = summarize_projects(projects_info)
    write_summary(summary, OUTPUT_FILE)


if __name__ == "__main__":
    main()
