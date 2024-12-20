def get_commit_diff(commit_index):
    data = ""
    with open("commits.json", "r") as f:
        data = json.load(f)
        for d in data:
            if d["commit_index"] == f"Commit {commit_index}": 
                return d["commit_diff"]
    return None