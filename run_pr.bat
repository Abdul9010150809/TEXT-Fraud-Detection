@echo off
"C:\Program Files\GitHub CLI\gh.exe" pr create --base main --head blackboxai/fix-errors --title "Fix errors and install dependencies" --body-file PR_BODY.md

