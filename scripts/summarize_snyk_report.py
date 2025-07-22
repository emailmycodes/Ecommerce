#!/usr/bin/env python3

import json
import sys
import os
from datetime import datetime
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
            if isinstance(data, list):
                return data
            else:
                return [data]
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
                    continue
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
    lines = []
    lines.append("## Recommendations")

    total_vulns = sum(p['total_vulnerabilities'] for p in all_projects)

    if total_vulns == 0:
        lines.append("**No action required** - All projects are secure")
        lines.append("- Continue regular security scanning")
        lines.append("- Keep dependencies updated")
    else:
        lines.append("### Immediate Actions")

        critical_projects = [p for p in all_projects if p['severity_counts'].get('critical', 0) > 0]
        if critical_projects:
            lines.append("1. **Address Critical Vulnerabilities:**")
            for project in critical_projects:
                crit_count = project['severity_counts'].get('critical', 0)
                lines.append(f"   - {project['project_name']}: {crit_count} critical issue(s)")

        high_projects = [p for p in all_projects if p['severity_counts'].get('high', 0) > 0]
        if high_projects:
            lines.append("2. **Review High Severity Issues:**")
            for project in high_projects:
                high_count = project['severity_counts'].get('high', 0)
                lines.append(f"   - {project['project_name']}: {high_count} high severity issue(s)")

        lines.append("")
        lines.append("### General Recommendations")
        lines.append("- Run `snyk fix` to automatically fix known vulnerabilities")
        lines.append("- Update dependencies to latest secure versions")
        lines.append("- Review and update security policies")
        lines.append("- Schedule regular security scans")

    return "\n".join(lines)

def create_summary_report(projects_data):
    lines = []

    lines.append("# Snyk Vulnerability Scan Summary")
    lines.append(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    if not projects_data:
        lines.append("## No Data Available")
        lines.append("No Snyk scan results were found or the results file was empty.")
        lines.append("This could be due to:")
        lines.append("- Authentication issues with Snyk")
        lines.append("- No supported package files found in the repository")
        lines.append("- Scan timeout or other technical issues")
        return "\n".join(lines)

    all_projects = []
    for project_data in projects_data:
        project_info = extract_project_info(project_data)
        all_projects.append(project_info)

    lines.append(generate_overall_summary(all_projects))
    lines.append("")

    if len(all_projects) > 1:
        lines.append("## Project Details")
        for project_info in all_projects:
            lines.append(generate_project_summary(project_info))
    else:
        lines.append("## Project Details")
        lines.append(generate_project_summary(all_projects[0]))

    lines.append(generate_recommendations(all_projects))

    lines.append("")
    lines.append("---")
    lines.append("*This report was generated automatically by Snyk vulnerability scanning*")

    return "\n".join(lines)

def create_fallback_summary(error_message):
    lines = []
    lines.append("# Snyk Vulnerability Scan Summary")
    lines.append(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Error Status")
    lines.append(f"**Summary generation failed:** {error_message}")
    lines.append("")
    lines.append("## Troubleshooting")
    lines.append("1. Check that Snyk authentication token is valid")
    lines.append("2. Verify the repository contains supported package files")
    lines.append("3. Review GitHub Actions workflow logs for detailed error messages")
    lines.append("4. Ensure the Snyk CLI has proper permissions")
    lines.append("")
    lines.append("## Next Steps")
    lines.append("- Review the workflow logs for specific error details")
    lines.append("- Manually run `snyk test` in your local environment")
    lines.append("- Contact your security team if issues persist")

    return "\n".join(lines)

def main():
    try:
        if len(sys.argv) < 2:
            raise ValueError("Usage: python summarize_snyk_report.py <path/to/snyk-results.json>")

        input_file = sys.argv[1]
        print(f"Processing Snyk results from: {input_file}")

        os.makedirs('scripts', exist_ok=True)

        projects_data = load_snyk_results(input_file)
        print(f"Loaded {len(projects_data)} project(s) from results file")

        summary_content = create_summary_report(projects_data)

        output_file = 'scripts/snyk-summary.txt'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(summary_content)

        print(f"Summary report generated successfully: {output_file}")

        if projects_data:
            total_vulns = sum(len(p.get('vulnerabilities', [])) for p in projects_data)
            print(f"Summary: {len(projects_data)} projects scanned, {total_vulns} vulnerabilities found")

    except Exception as e:
        print(f"Error: {e}")

        try:
            os.makedirs('scripts', exist_ok=True)
            fallback_content = create_fallback_summary(str(e))
            with open('scripts/snyk-summary.txt', 'w', encoding='utf-8') as f:
                f.write(fallback_content)
            print("Fallback summary created")
        except Exception as fallback_error:
            print(f"Failed to create fallback summary: {fallback_error}")
            sys.exit(1)

if __name__ == "__main__":
    main()
