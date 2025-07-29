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
PROMPT_TEMPLATE_PATH = "scripts/agent-prompt.txt"
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
    Ensures only affected dependencies are upgraded to latest secure versions.
    """
    prompt_template = read_file(PROMPT_TEMPLATE_PATH)
    prompt = prompt_template.replace("{{SNYK_SUMMARY}}", summary).replace("{{POM_CONTENT}}", pom_content)

    body = {
        "model": "mistral-small",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant that only upgrades Java Maven dependencies listed in a Snyk vulnerability summary to their secure latest versions, preserving structure and compatibility."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1,
        "top_p": 0.9,
        "max_tokens": 3100,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0
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
        "fix: update pom.xml based on Snyk vulnerabilities using Mistral",
        new_pom,
        pom_file.sha,
        branch=branch
    )

    repo.create_pull(
        title="fix: auto-update pom.xml via Mistral AI (Snyk fixes)",
        body="This PR includes secure dependency upgrades in `pom.xml` based on Snyk vulnerability summary, powered by Mistral AI.",
        head=branch,
        base="main"
    )

    print("✅ Pull request created successfully.")

if __name__ == "__main__":
    summary_text = read_file(SNYK_SUMMARY_PATH)
    original_pom = read_file(POM_FILE)
    fixed_pom = get_fix_from_mistral(summary_text, original_pom)
    create_branch_and_commit(fixed_pom, original_pom)
