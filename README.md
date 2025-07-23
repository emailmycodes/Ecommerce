# 🔐 Automated Maven Vulnerability Scanner & Fixer using Snyk, GitHub Actions & Mistral AI

## 📌 Overview

This project automates the process of identifying and fixing vulnerabilities in a Maven-based Java project using a seamless integration of:

- 🛡️ **Snyk CLI** for scanning dependencies.
- 🤖 **Mistral AI** to fix only the affected dependencies in `pom.xml`.
- 🔁 **GitHub Actions** for end-to-end CI/CD automation.

The system ensures only **listed vulnerabilities are fixed**, keeping the rest of the code untouched and secure.

---

## 📂 Folder Structure

.
├── .github/workflows/
│ ├── snyk-scan.yml
│ ├── generate-summary.yml
│ └── fix-and-commit.yml
├── scripts/
│ ├── summarize_snyk_report.py
│ └── pom_fix_from_report.py
├── pom.xml
└── snyk-summary.txt (auto-generated)



---

## ⚙️ Technologies Used

| Component          | Description                                 |
|--------------------|---------------------------------------------|
| **Snyk CLI**       | Scans for known vulnerabilities in Maven    |
| **Python**         | Custom scripts for parsing & AI integration |
| **GitHub Actions** | Automates CI pipeline for scanning & fixing |
| **Mistral AI**     | Large Language Model to intelligently fix   |
| **Maven**          | Java build system using `pom.xml`           |

---

## 💡 How It Works

### 🔁 Workflow Stages:

1. **Snyk Scan Job**
   - Runs `snyk test` to identify vulnerabilities.
   - Outputs results as a JSON report.

2. **Summary Generator Job**
   - Python script (`summarize_snyk_report.py`) parses JSON.
   - Extracts only relevant and fixable vulnerabilities.
   - Generates `snyk-summary.txt`.

3. **AI Fix & Commit Job**
   - Python script (`pom_fix_from_report.py`) sends `pom.xml` and `snyk-summary.txt` to Mistral AI.
   - AI fixes only listed vulnerable dependencies.
   - Commits and pushes the fixed `pom.xml`.

---

## 🧠 AI Agent Involvement

This project uses a **Fixing AI Agent** powered by **Mistral LLM API**. It:

- Understands vulnerabilities and their impact.
- Suggests only precise dependency version upgrades.
- Does **not touch** unrelated or safe dependencies.

---

## 🔐 Security by Design

- **Controlled fixes:** Only vulnerabilities listed in `snyk-summary.txt` are passed to AI.
- **Immutable history:** All changes are committed as PRs for manual review.
- **Reproducibility:** Vulnerability summaries are stored before deletion.

---

## 📦 Requirements

### Environment Variables (GitHub Secrets)

| Secret Name       | Description                              |
|-------------------|------------------------------------------|
| `SNYK_TOKEN`       | Your Snyk API token                      |
| `MISTRAL_API_KEY`  | Mistral LLM API Key                      |
| `GITHUB_TOKEN`     | GitHub PAT with `contents: write` scope |
| `GITHUB_REPO`      | Format: `username/repo-name`             |

### Python Dependencies

Install required packages:
```bash
pip install requests PyGithub


🚀 How to Run Manually
Trigger the workflow from GitHub UI (workflow_dispatch).

The snyk-summary.txt will be generated and committed.

The fix job will create a PR with the corrected pom.xml.

🧪 Sample Usage
Before Fix: Snyk detects 5 vulnerabilities.

After Fix: Only the ones listed in snyk-summary.txt are corrected by AI.

Other non-listed or low-priority issues are untouched.

📈 Future Improvements
🔁 Schedule-based vulnerability scans.

📩 Slack/Email notification for PR creation.

🌐 Multi-file support (requirements.txt, package.json, etc.)




