"""
Script to create a Pull Request on GitHub
Usage: python create_pr.py <github_token>
"""
import sys
from github import Github

def create_pr(token, repo_name, branch_name, base_branch):
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        
        # Get the branch
        branch = repo.get_branch(branch_name)
        
        # Create PR
        pr = repo.create_pull(
            title="Fix errors and install dependencies",
            body="""## Summary of Changes

### Frontend Fixes:
- Added proper Next.js configuration in next.config.ts with reactStrictMode, image optimization, and experimental features
- Fixed Tailwind CSS version consistency (v3.4.17 in both root and frontend package.json)
- Added project metadata and useful scripts to root package.json

### Backend Fixes:
- Expanded backend requirements.txt with all required dependencies (FastAPI, Uvicorn, Pydantic, Motor, Redis, NLTK, etc.)
- Fixed import order in analyze.py (moved `re` import to top of file)

### Git Info:
- Branch: blackboxai/fix-errors
- All changes committed and pushed successfully
""",
            base=base_branch,
            head=branch_name
        )
        
        print(f"Successfully created PR #{pr.number}")
        print(f"PR URL: {pr.html_url}")
        return pr
        
    except Exception as e:
        print(f"Error creating PR: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python create_pr.py <github_token>")
        sys.exit(1)
    
    token = sys.argv[1]
    create_pr(token, "sohelshaik-143/TEXT-Fraud-Detection", "blackboxai/fix-errors", "main")

