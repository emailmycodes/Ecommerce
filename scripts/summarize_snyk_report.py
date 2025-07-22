#!/usr/bin/env python3

import json
import sys
import os
from datetime import datetime, timezone
from collections import defaultdict

def load_snyk_results(file_path):
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
    lines = []

    lines.append(f"### Project: {project_info['project_name']}")
    lines.append(f"- **Package Manager:** {project_info['package_manager']}")
    lines.append(f"- **Target File:** {project_info['target_file']}")
    lines.append(f"- **Dependencies:** {project_info['dependency_count']}")
    lines.append(f"- **Total Vulnerabilities:** {project_info['total_vulnerabilities']}")

    if project_info['ok']:
        lines.append("- **Status:** No vulnerabilities found")
    else:
        lines.append("- **Status:** Vulnerabilities detected")

    if project_info['total_vulnerabilities'] > 0:
        lines.append("- **Severity Breakdown:**")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = project_info['severity_counts'].get(severity, 0)
            if count > 0:
                lines.append(f"  - {severity.capitalize()}: {count}")

    lines.append("")
    return "\n".join(lines)

def generate_overall_summary(all_projects):
    total_projects = len(all_projects)
    total_vulnerabilities = sum(p['total_vulnerabilities'] for p in all_projects)
    projects_with_vulns = sum(1 for p in all_projects if p['total_vulnerabilities'] > 0)

    overall_severity = defaultdict(int)
    for project in all_projects:
        for severity, count in project['severity_counts'].items():
            overall_severity[severity] += count

    lines = []
    lines.append("## Overall Summary")
    lines.append(f"- **Total Projects Scanned:** {total_projects}")
    lines.append(f"- **Projects with Vulnerabilities:** {projects_with_vulns}")
    lines.append(f"- **Projects Clean:** {total_projects - projects_with_vulns}")
    lines.append(f"- **Total Vulnerabilities:** {total_vulnerabilities}")
    lines.append("")

    if total_vulnerabilities > 0:
        lines.append("### Vulnerability Distribution by Severity")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = overall_severity.get(severity, 0)
            if count > 0:
                lines.append(f"- **{severity.capitalize()}:** {count}")
        lines.append("")

        lines.append("### Risk Assessment")
        if overall_severity.get('critical', 0) > 0:
            lines.append("**CRITICAL RISK:** Immediate action required")
        elif overall_severity.get('high', 0) > 0:
            lines.append("**HIGH RISK:** High priority fixes needed")
        elif overall_severity.get('medium', 0) > 0:
            lines.append("**MEDIUM RISK:** Monitor and patch")
        elif overall_severity.get('low', 0) > 0:
            lines.append("**LOW RISK:** Informational")

    else:
        lines.append("**EXCELLENT:** No vulnerabilities detected across all projects!")

    return "\n".join(lines)

def generate_recommendations(all_projects):
    lines = []
    lines.append("## Recommendations")

    total_vulns = sum(p['total_vulnerabilities'] for p in all_projects)

    if total_vulns == 0:
        lines.append("**No action required** - All projects are secure")
        lines.append("- Keep dependencies updated")
        lines.append("- Continue regular security scans")
    else:
        lines.append("### Immediate Actions")

        critical_projects = [p for p in all_projects if p['severity_counts'].get('critical', 0) > 0]
        if critical_projects:
            lines.append("1. **Address Critical Vulnerabilities:**")
            for p in critical_projects:
                lines.append(f"   - {p['project_name']}: {p['severity_counts']['critical']} critical issue(s)")

        high_projects = [p for p in all_projects if p['severity_counts'].get('high', 0) > 0]
        if high_projects:
            lines.append("2. **Review High Severity Issues:**")
            for p in high_projects:
                lines.append(f"   - {p['project_name']}: {p['severity_counts']['high']} high issue(s)")

        lines.append("")
        lines.append("### General Recommendations")
        lines.append("- Run `snyk fix` to apply known fixes")
        lines.append("- Upgrade dependencies where possible")
        lines.append("- Monitor new vulnerabilities regularly")
        lines.append("- Enforce policies for dependency security")

    return "\n".join(lines)

def create_summary_report(projects_data):
    lines = []

    lines.append("# Snyk Vulnerability Scan Summary")
    lines.append(f"**Generated on:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    if not projects_data:
        lines.append("## No Data Available")
        lines.append("No Snyk scan results found or the file was empty.")
        lines.append("Possible reasons:")
        lines.append("- No supported package files found")
        lines.append("- Authentication or permission issues")
        lines.append("- Empty or malformed input")
        return "\n".join(lines)

    all_projects = [extract_project_info(p) for p in projects_data]

    lines.append(generate_overall_summary(all_projects))
    lines.append("")

    lines.append("## Project Details")
    for project_info in all_projects:
        lines.append(generate_project_summary(project_info))

    lines.append(generate_recommendations(all_projects))
    lines.append("")
    lines.append("---")
    lines.append("*This report was generated automatically by Snyk vulnerability scanning*")

    return "\n".join(lines)

def create_fallback_summary(error_message):
    lines = []
    lines.append("# Snyk Vulnerability Scan Summary")
    lines.append(f"**Generated on:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Error")
    lines.append(f"Failed to generate summary: {error_message}")
    lines.append("")
    lines.append("## Troubleshooting Tips")
    lines.append("- Ensure valid Snyk token and permissions")
    lines.append("- Check for valid package files (e.g., pom.xml, package.json)")
    lines.append("- Review GitHub Actions logs or CLI output")
    return "\n".join(lines)

def main():
    try:
        if len(sys.argv) < 2:
            raise ValueError("Usage: python summarize_snyk_report.py <path/to/snyk-results.json>")

        input_file = sys.argv[1]
        print(f"🔍 Processing Snyk results from: {input_file}")

        os.makedirs('scripts', exist_ok=True)
        output_path = os.path.join('scripts', 'snyk-summary.txt')

        projects_data = load_snyk_results(input_file)
        print(f"📦 Loaded {len(projects_data)} project(s)")

        summary_content = create_summary_report(projects_data)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(summary_content)

        print(f"✅ Summary written to: {output_path}")
        if projects_data:
            total_vulns = sum(len(p.get('vulnerabilities', [])) for p in projects_data)
            print(f"📊 Total vulnerabilities found: {total_vulns}")

    except Exception as e:
        print(f"❌ Error: {e}")
        try:
            fallback = create_fallback_summary(str(e))
            os.makedirs('scripts', exist_ok=True)
            fallback_file = os.path.join('scripts', 'snyk-summary.txt')
            with open(fallback_file, 'w', encoding='utf-8') as f:
                f.write(fallback)
            print(f"⚠️  Fallback summary created at: {fallback_file}")
        except Exception as fallback_error:
            print(f"❌ Fallback failed: {fallback_error}")
            sys.exit(1)

if __name__ == "__main__":
    main()
