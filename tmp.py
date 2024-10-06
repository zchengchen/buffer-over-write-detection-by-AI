import json
with open("analysis_result.json", "r") as f:
    js = json.load(f)
    for i in range(0, len(js)):
            if js[i]["commit_index"] == "Commit 165":
                    print(js[i]["analysis"])