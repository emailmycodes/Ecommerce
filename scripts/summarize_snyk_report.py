import os
import json
import logging
from pathlib import Path
from typing import Dict, Any
from collections import defaultdict

# Configurable paths
INPUT_FILE = Path("snyk-results.json")
OUTPUT_FILE = Path("scripts/snyk-summary.txt")

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def load_snyk_results(file_path: Path) -> Dict[str, Any]:
    if not file_path.exists():
        logging.error(f"Snyk result file not found: {file_path}")
        return {}

    try:
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            logging.warning("Snyk result file is empty.")
            return {}

        return json.loads(content)
    except Exception as e:
        logging.error(f"Failed to load Snyk results: {e}")
        return {}

def extract_remediation_upgrades(remediation_section: Dict[str, Any]) -> str:
    """Extract remediation upgrade details for direct dependencies."""
    upgrades = remediation_section.get("upgrade", {})
    if not upgrades:
        return ""

    lines = ["Recommended Upgrades:"]
    for dep, upgrade_info in upgrades.items():
        upgrade_to = upgrade_info.get("upgradeTo", "")
        upgraded_vulns = upgrade_info.get("vulns", [])
        lines.append(f"- {dep} -> {upgrade_to}")
        # Optionally, list vulnerable sub-dependencies fixed by this upgrade if any:
        ups = upgrade_info.get("upgrades", [])
        if ups:
            for u in ups:
                lines.append(f"  - Upgrades {u}")
        if upgraded_vulns:
            lines.append(f"  - Fixes vulnerabilities: {', '.join(upgraded_vulns)}")
        lines.append("")
    return "\n".join(lines)

def extract_vulnerability_analysis(data: Dict[str, Any]) -> str:
    vulnerabilities = data.get("vulnerabilities", [])
    remediation = data.get("remediation", {})

    # Severity breakdown counts
    severity_counts = defaultdict(int)
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").lower()
        if severity:
            severity_counts[severity] += 1

    upgradable = len(remediation.get("upgrade", {}))
    unresolved = len(remediation.get("unresolved", []))

    # Packages with available fixes
    packages_fix_versions = defaultdict(set)
    for vuln in vulnerabilities:
        pkg_name = vuln.get("packageName") or vuln.get("package") or vuln.get("packageManager") or "unknown"
        fixed_versions = vuln.get("fixedIn", [])
        if isinstance(fixed_versions, list):
            for ver in fixed_versions:
                if ver:
                    packages_fix_versions[pkg_name].add(ver)

    pkg_fix_output = []
    for pkg, versions in sorted(packages_fix_versions.items()):
        ver_list = sorted(versions)
        if ver_list:
            pkg_fix_output.append(f"- {pkg}:")
            pkg_fix_output.append(f"  - Fixed in: {', '.join(ver_list)}")

    # Extract critical/high vulnerabilities with details
    crit_high_vulns = [
        vuln for vuln in vulnerabilities
        if vuln.get("severity", "").lower() in ("critical", "high")
    ]
    crit_high_output = []
    for vuln in crit_high_vulns:
        title = vuln.get("title", "Unknown vulnerability")
        cve_ids = vuln.get("identifiers", {}).get("CVE", [])
        cve_str = f" ({', '.join(cve_ids)})" if cve_ids else ""
        pkg_name = vuln.get("packageName", vuln.get("package", "unknown"))
        current_version = vuln.get("version") or "unknown"
        fixed_versions = vuln.get("fixedIn", [])
        fixed_versions_str = ", ".join(str(v) for v in fixed_versions) if fixed_versions else "N/A"
        upgradable_flag = vuln.get("isUpgradable", False)
        cvss_score = vuln.get("cvssScore", "N/A")

        crit_high_output.append(f"- {title}{cve_str}")
        crit_high_output.append(f"  - Package: {pkg_name}@{current_version}")
        crit_high_output.append(f"  - CVSS Score: {cvss_score}")
        crit_high_output.append(f"  - Fixed in: {fixed_versions_str}")
        crit_high_output.append(f"  - Upgradable: {'Yes' if upgradable_flag else 'No'}")

    lines = [
        "Vulnerability Analysis",
        "",
        "Severity Breakdown:",
        f"  Critical: {severity_counts.get('critical', 0)}",
        f"  High: {severity_counts.get('high', 0)}",
        f"  Medium: {severity_counts.get('medium', 0)}",
        f"  Low: {severity_counts.get('low', 0)}",
        "",
        "Remediation Status:",
        f"  Upgradable: {upgradable}",
        f"  Unresolved: {unresolved}",
        "",
        "Packages with Available Fixes:"
    ]
    lines.extend(pkg_fix_output)
    lines.append("")
    lines.append("Critical/High Severity Vulnerabilities:")
    lines.extend(crit_high_output)
    lines.append("")

    # Append remediation upgrade summary (direct dependency upgrades like spring-boot-starter-web)
    remediation_upgrades_text = extract_remediation_upgrades(remediation)
    if remediation_upgrades_text:
        lines.append(remediation_upgrades_text)

    return "\n".join(lines)

def write_summary(content: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    logging.info(f"Summary written to: {output_path}")

def main() -> None:
    projects = load_snyk_results(INPUT_FILE)
    if not projects:
        logging.warning("No valid Snyk project data to summarize.")
        return

    # Process multiple projects if input is a list
    if isinstance(projects, list):
        results_text = "\n\n".join([extract_vulnerability_analysis(p) for p in projects])
    else:
        results_text = extract_vulnerability_analysis(projects)

    write_summary(results_text, OUTPUT_FILE)

if __name__ == "__main__":
    main()
