import os
import sys
import requests

SNYK_SUMMARY_PATH = sys.argv[1]
POM_FILE_PATH = "pom.xml"
MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")

def read_file(path):
    with open(path, "r") as file:
        return file.read()

def write_file(path, content):
    with open(path, "w") as file:
        file.write(content)

def get_fix_from_mistral(summary, original_pom):
    payload = {
        "model": "mistral-small",
        "messages": [
            {
                "role": "system",
                "content": "You are an expert in Java and Maven. Fix the given pom.xml based on the provided Snyk vulnerability summary."
            },
            {
                "role": "user",
                "content": f"Snyk Summary:\n{summary}\n\nOriginal pom.xml:\n{original_pom}"
            }
        ],
        "temperature": 0.3
    }

    headers = {
        "Authorization": f"Bearer {MISTRAL_API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.post(MISTRAL_API_URL, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]

def main():
    summary_text = read_file(SNYK_SUMMARY_PATH)
    original_pom = read_file(POM_FILE_PATH)
    fixed_pom = get_fix_from_mistral(summary_text, original_pom)
    write_file("pom1.xml", fixed_pom)
    print("pom1.xml updated based on snyk-summary.txt")

if __name__ == "__main__":
    main()
