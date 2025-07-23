import sys
import json

def summarize_snyk(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    vulnerabilities = []
    if isinstance(data, list):
        for project in data:
            vulnerabilities += project.get("vulnerabilities", [])
    else:
        vulnerabilities = data.get("vulnerabilities", [])

    summary_lines = []
    for vuln in vulnerabilities:
        pkg = vuln.get("package", "unknown")
        version = vuln.get("version", "unknown")
        severity = vuln.get("severity", "unknown")
        title = vuln.get("title", "No title")
        upgrade = vuln.get("upgradePath", [])
        upgrade_info = " -> ".join(upgrade) if upgrade else "No upgrade path"
        summary_lines.append(f"{title} ({severity}) in {pkg}@{version} | Upgrade: {upgrade_info}")

    return "\n".join(summary_lines)

if __name__ == "__main__":
    json_file = sys.argv[1]
    print(summarize_snyk(json_file))
