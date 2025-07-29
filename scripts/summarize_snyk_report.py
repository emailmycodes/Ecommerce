import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Union, Set
from collections import defaultdict

# Configurable paths
INPUT_FILE = Path("snyk-results.json")
OUTPUT_FILE = Path("scripts/snyk-summary.txt")

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def load_snyk_results(file_path: Path) -> Dict[str, Any]:
    """Load Snyk results from JSON file."""
    if not file_path.exists():
        logging.error(f"Snyk result file not found: {file_path}")
        return {}

    try:
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            logging.warning("Snyk result file is empty.")
            return {}

        return json.loads(content)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON format: {e}")
        return {}
    except Exception as e:
        logging.error(f"Failed to load Snyk results: {e}")
        return {}


def extract_vulnerability_details(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract detailed vulnerability information."""
    severity_counts = defaultdict(int)
    vulnerability_details = []
    upgrade_paths = defaultdict(set)
    fixed_versions = defaultdict(set)
    
    for vuln in vulnerabilities:
        # Basic vulnerability info
        vuln_id = vuln.get("id", "Unknown")
        title = vuln.get("title", "Unknown vulnerability")
        severity = vuln.get("severity", "unknown").lower()
        cvss_score = vuln.get("cvssScore", 0)
        package_name = vuln.get("packageName", "Unknown package")
        current_version = vuln.get("version", "Unknown")
        is_upgradable = vuln.get("isUpgradable", False)
        is_patchable = vuln.get("isPatchable", False)
        
        # Count severity
        severity_counts[severity] += 1
        
        # Extract fixed versions
        fixed_in = vuln.get("fixedIn", [])
        if fixed_in:
            for version in fixed_in:
                fixed_versions[package_name].add(version)
        
        # Extract upgrade path
        upgrade_path = vuln.get("upgradePath", [])
        if upgrade_path and any(upgrade_path):  # Check if upgrade path exists and is not all False
            upgrade_info = " -> ".join([str(item) for item in upgrade_path if item])
            if upgrade_info:
                upgrade_paths[package_name].add(upgrade_info)
        
        # Store vulnerability details
        vulnerability_details.append({
            "id": vuln_id,
            "title": title,
            "severity": severity,
            "cvss_score": cvss_score,
            "package_name": package_name,
            "current_version": current_version,
            "fixed_in": fixed_in,
            "is_upgradable": is_upgradable,
            "is_patchable": is_patchable,
            "cve_ids": vuln.get("identifiers", {}).get("CVE", []),
            "upgrade_path": upgrade_path
        })
    
    return {
        "severity_counts": dict(severity_counts),
        "vulnerability_details": vulnerability_details,
        "upgrade_paths": {k: list(v) for k, v in upgrade_paths.items()},
        "fixed_versions": {k: sorted(list(v)) for k, v in fixed_versions.items()}
    }


def extract_project_info(project_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract comprehensive project information."""
    vulnerabilities = project_data.get("vulnerabilities", [])
    vuln_analysis = extract_vulnerability_details(vulnerabilities)
    
    # Extract remediation info
    remediation = project_data.get("remediation", {})
    unresolved_count = len(remediation.get("unresolved", []))
    upgradable_count = len(remediation.get("upgrade", {}))
    
    return {
        "project_name": project_data.get("projectName", "Unknown Project"),
        "package_manager": project_data.get("packageManager", "Unknown"),
        "target_file": project_data.get("displayTargetFile", project_data.get("targetFile", "Unknown")),
        "dependency_count": project_data.get("dependencyCount", 0),
        "total_vulnerabilities": len(vulnerabilities),
        "unique_count": project_data.get("uniqueCount", len(vulnerabilities)),
        "ok": project_data.get("ok", False),
        "unresolved_count": unresolved_count,
        "upgradable_count": upgradable_count,
        **vuln_analysis
    }


def generate_vulnerability_summary(project_info: Dict[str, Any]) -> List[str]:
    """Generate detailed vulnerability summary."""
    output = []
    
    if project_info["total_vulnerabilities"] == 0:
        output.append("- No vulnerabilities found.")
        return output
    
    # Severity breakdown
    output.append("- **Severity Breakdown:**")
    severity_order = ["critical", "high", "medium", "low"]
    for severity in severity_order:
        count = project_info["severity_counts"].get(severity, 0)
        if count > 0:
            output.append(f"  - {severity.capitalize()}: {count}")
    
    # Remediation status
    output.extend([
        f"- **Remediation Status:**",
        f"  - Upgradable: {project_info['upgradable_count']}",
        f"  - Unresolved: {project_info['unresolved_count']}"
    ])
    
    # Package-specific details
    if project_info["fixed_versions"]:
        output.append("- **Packages with Available Fixes:**")
        for package, versions in project_info["fixed_versions"].items():
            output.append(f"  - **{package}:**")
            output.append(f"    - Fixed in: {', '.join(versions)}")
    
    # Top vulnerabilities by severity
    critical_high_vulns = [
        v for v in project_info["vulnerability_details"] 
        if v["severity"] in ["critical", "high"]
    ]
    
    if critical_high_vulns:
        output.append("- **Critical/High Severity Vulnerabilities:**")
        for vuln in sorted(critical_high_vulns, key=lambda x: x["cvss_score"], reverse=True)[:5]:
            cve_info = f" ({', '.join(vuln['cve_ids'])})" if vuln['cve_ids'] else ""
            output.append(f"  - **{vuln['title']}**{cve_info}")
            output.append(f"    - Package: `{vuln['package_name']}@{vuln['current_version']}`")
            output.append(f"    - CVSS Score: {vuln['cvss_score']}")
            if vuln['fixed_in']:
                output.append(f"    - Fixed in: {', '.join(vuln['fixed_in'])}")
            if vuln['is_upgradable']:
                output.append(f"    - Upgradable")
            else:
                output.append(f"    - Not upgradable")
    
    return output


def generate_summary(project_info: Dict[str, Any]) -> str:
    """Generate comprehensive summary report."""
    total_vulns = project_info["total_vulnerabilities"]
    
    output = [
        "# Snyk Vulnerability Analysis Report",
        "",
        "## Executive Summary",
        f"- **Project:** `{project_info['project_name']}`",
        f"- **Target File:** `{project_info['target_file']}`",
        f"- **Package Manager:** {project_info['package_manager']}",
        f"- **Total Dependencies:** {project_info['dependency_count']}",
        f"- **Total Vulnerabilities:** {total_vulns}",
        f"- **Unique Vulnerabilities:** {project_info['unique_count']}",
        ""
    ]
    
    if total_vulns > 0:
        # Overall status
        output.extend([
            f"## Security Status: **NEEDS ATTENTION**",
            ""
        ])
        
        # Detailed vulnerability analysis
        output.extend([
            "## Vulnerability Analysis",
            ""
        ])
        output.extend(generate_vulnerability_summary(project_info))
        
        # Upgrade recommendations
        if project_info["upgrade_paths"]:
            output.extend([
                "",
                "## Recommended Upgrades",
                ""
            ])
            for package, paths in project_info["upgrade_paths"].items():
                output.append(f"### {package}")
                for path in paths:
                    output.append(f"- {path}")
                output.append("")
        
        # Action items
        output.extend([
            "## Action Items",
            "",
            f"1. **Immediate:** Address {project_info['severity_counts'].get('critical', 0)} critical vulnerabilities",
            f"2. **High Priority:** Fix {project_info['severity_counts'].get('high', 0)} high severity issues",
            f"3. **Upgrade:** {project_info['upgradable_count']} packages can be upgraded",
            f"4. **Review:** {project_info['unresolved_count']} vulnerabilities require manual review",
            ""
        ])
    else:
        output.extend([
            "## Security Status: **ALL CLEAR**",
            "",
            "No vulnerabilities detected in the current dependency tree.",
            ""
        ])
    
    output.extend([
        "---",
        f"*Report generated for {project_info['project_name']}*",
        f"*Scan completed: {project_info['dependency_count']} dependencies analyzed*"
    ])
    
    return "\n".join(output)


def write_summary(content: str, output_path: Path) -> None:
    """Write summary to output file."""
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        logging.info(f"Summary written to: {output_path}")
        logging.info(f"Summary file size: {len(content)} characters")
    except Exception as e:
        logging.error(f"Failed to write summary: {e}")


def main() -> None:
    """Main execution function."""
    logging.info("Starting Snyk vulnerability analysis...")
    
    # Load Snyk results
    project_data = load_snyk_results(INPUT_FILE)
    if not project_data:
        logging.warning("No valid Snyk project data to analyze.")
        return
    
    # Extract project information
    project_info = extract_project_info(project_data)
    
    # Generate and write summary
    summary = generate_summary(project_info)
    write_summary(summary, OUTPUT_FILE)
    
    # Log summary stats
    logging.info(f"Analysis complete:")
    logging.info(f"  - Total vulnerabilities: {project_info['total_vulnerabilities']}")
    logging.info(f"  - Critical: {project_info['severity_counts'].get('critical', 0)}")
    logging.info(f"  - High: {project_info['severity_counts'].get('high', 0)}")
    logging.info(f"  - Upgradable packages: {project_info['upgradable_count']}")


if __name__ == "__main__":
    main()