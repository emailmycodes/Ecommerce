#!/usr/bin/env python3

import json
import sys
import os
from datetime import datetime
from collections import defaultdict

def load_snyk_results(file_path):
    """Load and parse Snyk JSON results from a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        if not content:
            print("Warning: Input file is empty")
            return []

        try:
            data = json.loads(content)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            projects = []
            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    projects.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON on line {line_num}: {e}")
            return projects

    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

def extract_project_info(project):
    """Extract and structure vulnerability info from project JSON."""
    info = {
        'project_name': project.get('projectName', 'Unknown Project'),
        'package_manager': project.get('packageManager', 'Unknown'),
        'target_file': project.get('targetFile', 'Unknown'),
        'vulnerabilities': project.get('vulnerabilities', []),
        'dependency_count': project.get('dependencyCount', 0),
        'ok': project.get('ok', False),
        'policy': project.get('policy', ''),
        'path': project.get('path', '')
    }

    severity_counts = defaultdict(int)
    for vuln in info['vulnerabilities']:
        severity = vuln.get('severity', 'unknown').lower()
        severity_counts[severity] += 1

    info['severity_counts'] = dict(severity_counts)
    info['total_vulnerabilities'] = len(info['vulnerabilities'])
    return info

def generate_project_summary(project_info):
    """Generate a human-readable summary for a single project."""
    lines = [
        f"### Project: {project_info['project_name']}",
        f"- **Package Manager:** {project_info['package_manager']}",
        f"- **Target File:** {project_info['target_file']}",
        f"- **Dependencies:** {project_info['dependency_count']}",
        f"- **Total Vulnerabilities:** {project_info['total_vulnerabilities']}"
    ]

    lines.append("- **Status:** No vulnerabilities found" if project_info['ok'] else "- **Status:** Vulnerabilities detected")

    if project_info['total_vulnerabilities'] > 0:
        lines.append("- **Severity Breakdown:**")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = project_info['severity_counts'].get(severity, 0)
            if count > 0:
                lines.append(f"  - {severity.capitalize()}: {count}")

    lines.append("")
    return "\n".join(lines)

def generate_overall_summary(all_projects):
    """Generate an overall summary across all scanned projects."""
    total_projects = len(all_projects)
    total_vulnerabilities = sum(p['total_vulnerabilities'] for p in all_projects)
    projects_with_vulns = sum(1 for p in all_projects if p['total_vulnerabilities'] > 0)

    overall_severity = defaultdict(int)
    for project in all_projects:
        for severity, count in project['severity_counts'].items():
            overall_severity[severity] += count

    lines = [
        "## Overall Summary",
        f"- **Total Projects Scanned:** {total_projects}",
        f"- **Projects with Vulnerabilities:** {projects_with_vulns}",
        f"- **Projects Clean:** {total_projects - projects_with_vulns}",
        f"- **Total Vulnerabilities:** {total_vulnerabilities}",
        ""
    ]

    if total_vulnerabilities > 0:
        lines.append("### Vulnerability Distribution by Severity")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = overall_severity.get(severity, 0)
            if count > 0:
                lines.append(f"- **{severity.capitalize()}:** {count}")
        lines.append("")

        lines.append("### Risk Assessment")
        if overall_severity.get('critical', 0) > 0:
            lines.append("**CRITICAL RISK:** Immediate action required due to critical vulnerabilities")
        elif overall_severity.get('high', 0) > 0:
            lines.append("**HIGH RISK:** High severity vulnerabilities need prompt attention")
        elif overall_severity.get('medium', 0) > 0:
            lines.append("**MEDIUM RISK:** Medium severity vulnerabilities should be addressed")
        elif overall_severity.get('low', 0) > 0:
            lines.append("**LOW RISK:** Only low severity vulnerabilities found")
    else:
        lines.append("**EXCELLENT:** No vulnerabilities detected across all projects!")

    return "\n".join(lines)

def generate_recommendations(all_projects):
    """Provide recommendations based on the severity of vulnerabilities."""
    lines = ["## Recommendations"]
    total_vulns = sum(p['total_vulnerabilities'] for p in all_projects)

    if total_vulns == 0:
        lines += [
            "**No action required** - All projects are secure",
            "- Continue regular security scanning",
            "- Keep dependencies updated
