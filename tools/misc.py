import json

def get_commit_diff(commit_sha):
    data = ""
    with open("commits.json", "r") as f:
        data = json.load(f)
        for d in data:
            if d["commit_sha"] == commit_sha: 
                return d["commit_diff"]
    return None