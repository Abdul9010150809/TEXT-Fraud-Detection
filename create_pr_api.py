"""
Create Pull Request using GitHub REST API
Usage: python create_pr_api.py <github_token>
"""
import requests
import json
import sys

def create_pr(token, repo_owner, repo_name, head, base, title, body):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls"
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }
    
    data = {
        "title": title,
        "body": body,
        "head": head,
        "base": base
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 201:
            pr_data = response.json()
            print(f"Successfully created PR #{pr_data['number']}")
            print(f"PR URL: {pr_data['html_url']}")
            return pr_data
        elif response.status_code == 422:
            print(f"Error: {response.status_code}")
            print(f"Response: {response.text}")
            # Maybe branch already exists or PR already exists
            # Let's try to get existing PR
            response = requests.get(url, headers=headers, params={"head": head, "state": "open"})
            if response.status_code == 200 and response.json():
                pr_data = response.json()[0]
                print(f"PR already exists: #{pr_data['number']}")
                print(f"PR URL: {pr_data['html_url']}")
                return pr_data
        else:
            print(f"Error: {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"Exception: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python create_pr_api.py <github_token>")
        sys.exit(1)
    
    token = sys.argv[1]
    
    body = """## Summary of Changes

### Frontend Fixes:
- Added proper Next.js configuration in next.config.ts with reactStrictMode, image optimization, and experimental features
- Fixed Tailwind CSS version consistency (v3.4.17)
- Added project metadata and useful scripts to root package.json

### Backend Fixes:
- Expanded backend requirements.txt with all required dependencies (FastAPI, Uvicorn, Pydantic, Motor, Redis, NLTK, etc.)
- Fixed import order in analyze.py (moved `re` import to top of file)

### Git Info:
- Branch: blackboxai/fix-errors
- All changes committed and pushed successfully
"""
    
    create_pr(token, "sohelshaik-143", "TEXT-Fraud-Detection", "blackboxai/fix-errors", "main", 
              "Fix errors and install dependencies", body)

