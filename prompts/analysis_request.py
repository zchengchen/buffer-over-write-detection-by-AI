import json

def get_commit_diff(commit_index: str):
    data = ""
    with open("commits.json", "r") as f:
        data = json.load(f)
        for d in data:
            if d["commit_index"] == commit_index: 
                return d["commit_diff"]
    return ""

def request_analysis_prompt(commit_index: str):
    analysis_request_prompt = "Does the following commit diff introduce any suspicious change that may inducing any vulnerability?\n"
    analysis_request_prompt += get_commit_diff(commit_index)
    ## analysis_request_prompt += "Analysis code function by function and analyze commit information line by line.. At the same time, you just need to focus on C code changes. If there is, please answer YES on the last line, otherwise answer NO. Please note that YES and NO are case-sensitive.\n"
    analysis_request_prompt += """\nPlease let me know all suspicious changes. You should check the diff line by line, and analysis code function by function. 
At the same time, you just need to focus on C code changes. If you find any suspicious modifications, 
please please answer YES on the last line, otherwise answer NO. Do not repeat the function name.
"""
    return analysis_request_prompt

if __name__ == "__main__":
    print(request_analysis_prompt("Commit 165"))