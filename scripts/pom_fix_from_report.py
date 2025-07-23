import os
import sys
import requests
from github import Github

# Environment Variables
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_NAME = os.getenv("GITHUB_REPO", "HelloworldCSE/ecommerce")  # Default fallback
SNYK_SUMMARY_PATH = sys.argv[1] if len(sys.argv) > 1 else "scripts/snyk-summary.txt"
POM_FILE_PATH = "pom.xml"

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
HEADERS = {
    "Authorization": f"Bearer {MISTRAL_API_KEY}",
    "Content-Type": "application/json"
}


def read_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"❌ Failed to read {path}: {e}")
        sys.exit(1)


def get_mistral_fix(summary: str, pom: str) -> str:
    prompt = f"""
You are a Java and Maven expert. Based on the following Snyk vulnerability summary, fix the pom.xml to resolve those issues.

--- Snyk Vulnerability Summary ---
{summary}

--- Original pom.xml ---
{pom}

--- Fixed pom.xml (return ONLY the fixed pom.xml content, no comments or explanations):
"""
    payload = {
        "model": "mistral-small",
        "messages": [
            {"role": "system", "content": "You are a helpful AI that fixes Java pom.xml files using Snyk vulnerability summaries."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "top_p": 0.9,
        "max_tokens": 2048
    }

    try:
        res = requests.post(MISTRAL_API_URL, headers=HEADERS, json=payload)
        res.raise_for_status()
        return res.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"❌ Error from Mistral API: {e}")
        sys.exit(1)


def update_repo_with_fix(updated_pom: str, original_pom: str):
    if updated_pom.strip() == original_pom.strip():
        print("✅ No change detected in pom.xml. No commit required.")
        return

    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(REPO_NAME)

    branch_name = "mistral-snyk-fix"
    base_branch = repo.get_branch("main")

    # Create new branch
    try:
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_branch.commit.sha)
        print(f"🔧 Created branch: {branch_name}")
    except Exception as e:
        print(f"⚠️ Branch may already exist: {e}")

    # Get current pom.xml in new branch
    pom_file = repo.get_contents(POM_FILE_PATH, ref=branch_name)

    # Update pom.xml
    repo.update_file(
        path=POM_FILE_PATH,
        message="fix: update pom.xml based on Snyk vulnerability summary via Mistral",
        content=updated_pom,
        sha=pom_file.sha,
        branch=branch_name
    )
    print("✅ pom.xml updated on branch.")

    # Create PR
    repo.create_pull(
        title="fix: update pom.xml via Mistral AI based on Snyk Summary",
        body="This PR fixes vulnerabilities identified by Snyk using Mistral AI.",
        head=branch_name,
        base="main"
    )
    print("✅ Pull request created!")


if __name__ == "__main__":
    snyk_summary = read_file(SNYK_SUMMARY_PATH)
    pom_xml = read_file(POM_FILE_PATH)

    print("📦 Calling Mistral to get pom.xml fix based on Snyk report...")
    fixed_pom = get_mistral_fix(snyk_summary, pom_xml)

    print("🔍 Comparing and applying fix if needed...")
    update_repo_with_fix(fixed_pom, pom_xml)
