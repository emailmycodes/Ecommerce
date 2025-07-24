#!/usr/bin/env python3

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Union
from collections import defaultdict

INPUT_FILE = Path("snyk-results.json")
OUTPUT_FILE = Path("scripts/snyk-summary.txt")

def load_snyk_results(file_path: Path) -> List[Dict[str, Any]]:
    if not file_path.exists():
        return []

    try:
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            return []

        try:
            data = json.loads(content)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
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

    except Exception:
        return []

def extract_project_info(project: Dict[str, Any]) -> Dict[str, Union[str, int, Dict[str, int], bool]]:
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
    total_projects = len(projects_info)
    total_vulnerabilities = sum(p["total_vulnerabilities"] for p in projects_info)
    affected_projects = sum(1 for p in projects_info if p["total_vulnerabilities"] > 0)

    output: List[str] = [
        f"projects_scanned: {total_projects}",
        f"projects_with_issues: {affected_projects}",
        f"total_vulnerabilities: {total_vulnerabilities}"
    ]

    global_severity: Dict[str, int] = defaultdict(int)
    for p in projects_info:
        for sev, count in p["severity_counts"].items():
            global_severity[sev] += count

    if total_vulnerabilities:
        output.append("severity_breakdown:")
        for sev in ["critical", "high", "medium", "low"]:
            count = global_severity.get(sev, 0)
            if count > 0:
                output.append(f"  {sev}: {count}")

    output.append("projects:")
    for project in projects_info:
        output.append(f"  - name: {project['project_name']}")
        output.append(f"    target_file: {project['target_file']}")
        output.append(f"    package_manager: {project['package_manager']}")
        output.append(f"    dependencies: {project['dependency_count']}")
        output.append(f"    vulnerabilities: {project['total_vulnerabilities']}")
        if project["total_vulnerabilities"] > 0:
            output.append(f"    severity_counts:")
            for sev in ["critical", "high", "medium", "low"]:
                count = project["severity_counts"].get(sev, 0)
                if count > 0:
                    output.append(f"      {sev}: {count}")
        else:
            output.append(f"    severity_counts: {{}}")

    return "\n".join(output)

def write_summary(content: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")

def main() -> None:
    projects = load_snyk_results(INPUT_FILE)
    if not projects:
        return

    projects_info = [extract_project_info(p) for p in projects]
    summary = summarize_projects(projects_info)
    write_summary(summary, OUTPUT_FILE)

if __name__ == "__main__":
    main()
