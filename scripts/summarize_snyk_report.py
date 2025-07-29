
import os
import json
import logging
import requests
from pathlib import Path
from typing import List, Dict, Any, Union
from collections import defaultdict

# Configurable paths
INPUT_FILE = Path("snyk-results.json")
OUTPUT_FILE = Path("scripts/snyk-summary.txt")

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def load_snyk_results(file_path: Path) -> List[Dict[str, Any]]:
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


def get_latest_version_from_maven(group: str, artifact: str) -> str:
    try:
        url = f"https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}&rows=1&wt=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            docs = data.get("response", {}).get("docs", [])
            if docs:
                return docs[0].get("latestVersion", "Unknown")
    except Exception as e:
        logging.warning(f"Could not fetch version for {group}:{artifact} - {e}")
    return "Unknown"


def extract_project_info(project: Dict[str, Any]) -> Dict[str, Union[str, int, Dict[str, int], bool, List[str]]]:
    severity_counts = defaultdict(int)
    vulnerabilities = project.get("vulnerabilities", [])
    latest_versions = []

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "unknown").lower()
        severity_counts[severity] += 1

        pkg_info = vuln.get("from", [])
        if pkg_info and ":" in pkg_info[-1]:
            parts = pkg_info[-1].split(":")
            if len(parts) == 3:  # group:artifact:version
                group, artifact, _ = parts
                latest = get_latest_version_from_maven(group, artifact)
                latest_versions.append(f"{group}:{artifact} → {latest}")

    return {
        "project_name": project.get("projectName", "Unknown Project"),
        "package_manager": project.get("packageManager", "Unknown"),
        "target_file": project.get("targetFile", "Unknown"),
        "dependency_count": project.get("dependencyCount", 0),
        "total_vulnerabilities": len(vulnerabilities),
        "severity_counts": dict(severity_counts),
        "latest_versions": list(set(latest_versions)),
        "ok": project.get("ok", False)
    }


def summarize_projects(projects_info: List[Dict[str, Any]]) -> str:
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
            if project["latest_versions"]:
                output.append("- **Latest Available Versions:**")
                for item in project["latest_versions"]:
                    output.append(f"  - {item}")
        else:
            output.append("- ✅ No vulnerabilities found.")
        output.append("")

    return "\n".join(output)


def write_summary(content: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    logging.info(f"Summary written to: {output_path}")


def main() -> None:
    projects = load_snyk_results(INPUT_FILE)
    if not projects:
        logging.warning("No valid Snyk project data to summarize.")
        return

    projects_info = [extract_project_info(p) for p in projects]
    summary = summarize_projects(projects_info)
    write_summary(summary, OUTPUT_FILE)


if __name__ == "__main__":
    main()
