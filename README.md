brew install poetry asdf

asdf install
poetry install


1. Setup your ~/.aws/config with the profile  
2. Ensure you have an atlassian api token https://id.atlassian.com/manage-profile/security/api-tokens  
3. export `AWS_PROFILE=` for the above profile
4. `aws sso login` , then run the script from your CLI
5. Ensure python dependencies are installed , venv recommended https://docs.python.org/3/library/venv.html
6. Run script, something like poetry run python jira_vulnerabilities.py
