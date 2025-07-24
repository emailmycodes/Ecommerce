import os
import sys
import requests
from github import Github

# Environment variables
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_NAME = os.getenv("GITHUB_REPO")

# File paths
SNYK_SUMMARY_PATH = sys.argv[1] if len(sys.argv) > 1 else "scripts/snyk-summary.txt"
POM_FILE = "pom.xml"

# Mistral API config
MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
HEADERS = {
    "Authorization": f"Bearer {MISTRAL_API_KEY}",
    "Content-Type": "application/json"
}


def read_file(file_path):
    """Reads and returns the contents of a file."""
    with open(file_path, "r") as f:
        return f.read()


def get_fix_from_mistral(summary, pom_content):
    """
    Sends the Snyk summary and pom.xml content to Mistral AI and gets the fixed pom.xml.
    Only modifies dependencies explicitly mentioned in the summary.
    """
    prompt = f"""You are an expert in Java and Maven.
You are provided with:
1. A vulnerability summary from Snyk.
2. The contents of a `pom.xml` file.

Your task is:
- Only update dependencies that are explicitly mentioned in the vulnerability summary.
- Do not modify any other dependencies or content in the pom.xml under any circumstance.
- Do not add any comments, logs, whitespace changes, or extra lines.
- Return only the updated `pom.xml` content exactly as expected by Maven.

### Vulnerability Summary:
{summary}

### Original pom.xml:
{pom_content}

### Updated pom.xml (ONLY with relevant changes, no explanations or other edits):"""

    body = {
        "model": "mistral-small",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful AI that improves Java pom.xml files based strictly on Snyk vulnerability summaries."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2,
        "top_p": 0.9,
        "max_tokens": 2048
    }

    response = requests.post(MISTRAL_API_URL, headers=HEADERS, json=body)
    response.raise_for_status()
    result = response.json()
    return result["choices"][0]["message"]["content"].strip()


def create_branch_and_commit(new_pom, original_pom):
    """
    Creates a new branch, commits the updated pom.xml, and opens a pull request if there are changes.
    """
    if new_pom.strip() == original_pom.strip():
        print("No changes needed in pom.xml. Skipping commit and pull request.")
        return

    github = Github(GITHUB_TOKEN)
    repo = github.get_repo(REPO_NAME)

    branch = "mistral-snyk-fix"
    source = repo.get_branch("main")

    try:
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=source.commit.sha)
    except Exception as e:
        print(f"Branch might already exist: {e}")

    pom_file = repo.get_contents(POM_FILE, ref=branch)
    repo.update_file(
        POM_FILE,
        "fix: update pom.xml based on Snyk vulnerabilities",
        new_pom,
        pom_file.sha,
        branch=branch
    )

    repo.create_pull(
        title="fix: auto-update pom.xml via Mistral AI",
        body="This PR includes automatic fixes to `pom.xml` based on Snyk vulnerabilities using Mistral AI.",
        head=branch,
        base="main"
    )

    print("Pull request created successfully.")


if __name__ == "__main__":
    summary_text = read_file(SNYK_SUMMARY_PATH)
    original_pom = read_file(POM_FILE)
    fixed_pom = get_fix_from_mistral(summary_text, original_pom)
    create_branch_and_commit(fixed_pom, original_pom)
