# GPT for Out-of-bounds write
from openai import OpenAI
from os import getenv
from github import Github
import json

####################################################################################################
# To fetch all history commits of challenge-004-nginx-source.                                      #
# And store the commit infomation in commits.josn                                                  #
####################################################################################################
# access_token = getenv("GITHUB_TOKEN")
# g = Github(access_token)

# repo_name = "aixcc-public/challenge-004-nginx-source"
# repo = g.get_repo(repo_name)

# commits = repo.get_commits()
# commits_info = []

# for commit in commits:
#     # print(f"Commit SHA: {commit.sha}")
#     # print(f"Commit {commit.commit.message}")
#     commit_detail = repo.get_commit(commit.sha)
#     info = {"commit_sha": commit.sha, "commit_index": commit.commit.message, "commit_diff": ""}
#     for file in commit_detail.files:
#         # print(f"Diff:\n{file.patch}\n")
#         info["commit_diff"] += f"Diff:\n{file.patch}\n"
#     commits_info.append(info)

# with open("commits.json", "w") as f:
#   print(json.dumps(commits_info, ensure_ascii=False), file=f)

commits_history = {}
with open("commits.json", "r", encoding="utf-8") as file:
    commits_history = json.load(file)

# client = OpenAI(
#   api_key=getenv("OPENAI_API_KEY"),
# )

# response = client.chat.completions.create(
#     model="gpt-4o-mini",
#     messages=[
#         {"role": "system", "content": "You are a helpful assistant."},
#         {"role": "user", "content": "Tell me about the solar system."}
#     ]
# )

# print(response.choices[0].message.content)