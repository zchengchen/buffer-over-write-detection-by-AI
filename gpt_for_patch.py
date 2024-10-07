# python3 gpt_for_patch.py --commit_index 165 --func ngx_http_validate_from
from regex_tools import extract_c_function
from openai import OpenAI
from os import getenv
import json
from github_tools import search_function_in_github
import argparse
import re
import os

client = OpenAI(
  api_key=getenv("OPENAI_API_KEY"),
)

def send_message(message):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
          {"role": "user", "content": message}
        ]
    )
    return response.choices[0].message.content

parser = argparse.ArgumentParser()
    
parser.add_argument("--commit_index")
parser.add_argument("--func")

args = parser.parse_args()

repo_owner = "aixcc-public"
repo_name = "challenge-004-nginx-source"
path = search_function_in_github(repo_owner, repo_name, "ngx_http_validate_from")
patch_path = os.path.join("nginx-source", path)
latest_impl = extract_c_function(patch_path, args.func)

gpt_ask_header=f"""
The followings are vulnerability analysis, payload for proof of vulnerability and implementation of 
function vulnerable: {args.func}. \n
"""
analysis = "Vulnerability analysis:\n"
with open("analysis_result.json", "r") as f:
    commits = json.load(f)
    for commit in commits:
        if commit["commit_index"] == f"Commit {args.commit_index}":
            analysis += commit["analysis"]
            break
analysis += "\n"

payload = "Successful payload: \n"
with open('vuln_cpv1.bin', 'r', encoding='utf-8') as file:
    payload += file.read()
payload += "\n"

gpt_ask_tail = f"""
Please patch function {args.func} and at the same time keep this function work normally.
"""

flag = True
while flag:
    message = gpt_ask_header + analysis + payload + gpt_ask_tail
    response = send_message(message)
    pattern = r'```c\n(.*?)```'
    matches = re.findall(pattern, response, re.DOTALL)
    patched_func = r'{}'.format(matches[0])
    with open(patch_path, 'r') as file:
        patch_content = file.read()
    
