import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List
from collections import defaultdict

# Configurable input/output paths
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

def extract_remediation_upgrades(remediation: Dict[str, Any]) -> str:
    upgrades = remediation.get("upgrade", {})
    if not upgrades:
        return ""

    lines = ["Recommended Upgrades:"]
    for dep, upgrade_info in upgrades.items():
        upgrade_to = upgrade_info.get("upgradeTo", "")
        upgraded_vulns = upgrade_info.get("vulns", [])
        ups = upgrade_info.get("upgrades", [])

        lines.append(f"- {dep} -> {upgrade_to}")
        if ups:
            for u in ups:
                lines.append(f"  - Upgrades {u}")
        if upgraded_vulns:
            lines.append(f"  - Fixes vulnerabilities: {', '.join(upgraded_vulns)}")
        lines.append("")
    return "\n".join(lines)

def extract_jwt_transitive_vulns(vulnerabilities: List[Dict[str, Any]], jwt_groupid: str = "io.jsonwebtoken") -> str:
    """Find vulnerabilities introduced transitively via JWT or similar."""
    found = []

    for vuln in vulnerabilities:
        from_chain = vuln.get("from", [])
        for p in from_chain:
            if p.startswith(jwt_groupid + ":"):
                # Record relevant info
                found.append({
                    "vuln_id": vuln.get("id"),
                    "title": vuln.get("title"),
                    "cves": vuln.get("identifiers", {}).get("CVE", []),
                    "path": " › ".join(from_chain),
                    "fixedIn": vuln.get("fixedIn", []),
                    "isUpgradable": vuln.get("isUpgradable", False),
                    "pkg": vuln.get("packageName", vuln.get("package")),
                    "version": vuln.get("version", "unknown")
                })
                break
    if not found:
        return ""

    lines = ["Transitive Vulnerabilities via JWT Libraries:"]
    for f in found:
        cve_str = ", ".join(f["cves"]) if f["cves"] else "N/A"
        fixed_versions = ", ".join(f["fixedIn"]) if f["fixedIn"] else "None"
        upgradable = "Yes" if f["isUpgradable"] else "No"

        lines.append(f"- JWT Dependency: {f['path']}")
        lines.append(f"  - Vulnerability: {f['title']} (CVEs: {cve_str})")
        lines.append(f"  - Current Package/Version: {f['pkg']}@{f['version']}")
        lines.append(f"  - Fixed Versions: {fixed_versions}")
        lines.append(f"  - Upgradable: {upgradable}")
        lines.append("")

    return "\n".join(lines)

def extract_vulnerability_analysis(data: Dict[str, Any]) -> str:
    vulnerabilities = data.get("vulnerabilities", [])
    remediation = data.get("remediation", {})

    # Severity counts
    severity_counts = defaultdict(int)
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "").lower()
        if sev:
            severity_counts[sev] += 1

    upgradable = len(remediation.get("upgrade", {}))
    unresolved = len(remediation.get("unresolved", []))

    # Packages with available fixes
    packages_fix_versions = defaultdict(set)
    for vuln in vulnerabilities:
        pkg_name = vuln.get("packageName") or vuln.get("package") or "unknown"
        fixed_versions = vuln.get("fixedIn", [])
        if isinstance(fixed_versions, list):
            for v in fixed_versions:
                if v:
                    packages_fix_versions[pkg_name].add(v)

    pkg_fix_lines = []
    for pkg, vers in sorted(packages_fix_versions.items()):
        ver_list = sorted(vers)
        if ver_list:
            pkg_fix_lines.append(f"- {pkg}:")
            pkg_fix_lines.append(f"  - Fixed in: {', '.join(ver_list)}")

    # Critical/high severity vulns
    crit_high_vulns = [
        v for v in vulnerabilities if v.get("severity", "").lower() in ("critical", "high")
    ]

    crit_high_lines = []
    for vuln in crit_high_vulns:
        title = vuln.get("title", "Unknown vulnerability")
        cves = vuln.get("identifiers", {}).get("CVE", [])
        cve_str = f" ({', '.join(cves)})" if cves else ""
        pkg_name = vuln.get("packageName", vuln.get("package", "unknown"))
        curr_ver = vuln.get("version", "unknown")
        cvss = vuln.get("cvssScore", "N/A")
        fixed_versions = vuln.get("fixedIn", [])
        fixed_str = ", ".join(str(v) for v in fixed_versions) if fixed_versions else "N/A"
        upgradable = "Yes" if vuln.get("isUpgradable", False) else "No"

        crit_high_lines.append(f"- {title}{cve_str}")
        crit_high_lines.append(f"  - Package: {pkg_name}@{curr_ver}")
        crit_high_lines.append(f"  - CVSS Score: {cvss}")
        crit_high_lines.append(f"  - Fixed in: {fixed_str}")
        crit_high_lines.append(f"  - Upgradable: {upgradable}")

    # Compose full output
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
    lines.extend(pkg_fix_lines)
    lines.append("")
    lines.append("Critical/High Severity Vulnerabilities:")
    lines.extend(crit_high_lines)
    lines.append("")

    # Add remediation upgrade info
    remediation_upgrades = extract_remediation_upgrades(remediation)
    if remediation_upgrades:
        lines.append(remediation_upgrades)
        lines.append("")

    # Add JWT transitive vulns if any
    jwt_vulns = extract_jwt_transitive_vulns(vulnerabilities)
    if jwt_vulns:
        lines.append(jwt_vulns)
        lines.append("")

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

    if isinstance(projects, list):
        summary_text = "\n\n".join([extract_vulnerability_analysis(p) for p in projects])
    else:
        summary_text = extract_vulnerability_analysis(projects)

    write_summary(summary_text, OUTPUT_FILE)

if __name__ == "__main__":
    main()
