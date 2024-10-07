import requests
from os import getenv

github_token = getenv("GITHUB_TOKEN")
def search_function_in_github(repo_owner, repo_name, function_name, github_token=github_token):
    url = f"https://api.github.com/search/code?q={function_name}+repo:{repo_owner}/{repo_name}"

    headers = {}
    if github_token:
        headers['Authorization'] = f"token {github_token}"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        search_results = response.json()
        file_list = []

        for item in search_results.get('items', []):
            file_list.append(item['path'])

        return file_list[0]
    else:
        print(f"Failed to search code: {response.status_code}")
        return []

def fetch_commits(repo_owner, repo_name, github_token=github_token):
    access_token = github_token
    g = Github(access_token)

    repo_name = f"{repo_owner}/{repo_name}"
    repo = g.get_repo(repo_name)

    commits = repo.get_commits()
    commits_info = []

    for commit in commits:
        # print(f"Commit SHA: {commit.sha}")
        # print(f"Commit {commit.commit.message}")
        commit_detail = repo.get_commit(commit.sha)
        info = {"commit_sha": commit.sha, "commit_index": commit.commit.message, "commit_diff": ""}
        for file in commit_detail.files:
            # print(f"Diff:\n{file.patch}\n")
            info["commit_diff"] += f"Diff:\n{file.patch}\n"
        commits_info.append(info)

    with open("commits.json", "w") as f:
        print(json.dumps(commits_info, ensure_ascii=False), file=f)

if __name__ == "__main__":
    repo_owner = "aixcc-public"
    repo_name = "challenge-004-nginx-source"
    function_name = "ngx_http_validate_from"
    github_token = getenv("GITHUB_TOKEN")

    path = search_function_in_github(repo_owner, repo_name, function_name, github_token)
    print(path)
