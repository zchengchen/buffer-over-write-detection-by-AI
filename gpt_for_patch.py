# python3 gpt_for_patch.py --commit_index 165 --func ngx_http_validate_from
from regex_tools import extract_c_function, get_function_impl_from_response
from openai import OpenAI
from os import getenv
import json
from github_tools import search_function_in_github
from build_tools import build, remove_patch_and_build
import subprocess
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
# path = search_function_in_github(repo_owner, repo_name, "ngx_http_validate_from")
path = "src/http/ngx_http_request.c"
original_path = os.path.join("nginx-source", path)
patch_path = os.path.join("nginx-cp/src/nginx", path)
latest_impl = extract_c_function(original_path, args.func)

gpt_ask_header=f"""
The followings are vulnerability analysis, payload for proof of vulnerability and implementation of 
vulnerable function: {args.func}. \n
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

impl_code = "Vulnerable implementation: \n"
impl_code += latest_impl
impl_code += "\n"

gpt_ask_tail = f"""
Please patch function {args.func} and at the same time keep this function work normally. In your code, do
not introduce any new header file. All the revisions should be included in the function body. Do not change 
the function's parameters and types of return value and keep the change inside the function body!
"""

flag = True
max_try_cnt = 10
try_cnt = 1
while flag:
    print(f"Try to generate patch #{try_cnt}")
    message = gpt_ask_header + analysis + payload + impl_code + gpt_ask_tail
    response = send_message(message)
    patched_func = get_function_impl_from_response(response, args.func)
    # print(patched_func)
    file_content = ""
    with open(original_path, 'r') as file:
        file_content = file.read()
    match = re.search(re.escape(latest_impl), file_content)
    if match:
        before_match = file_content[:match.start()]
        after_match = file_content[match.end():]
        new_file = before_match + "\n" + patched_func + after_match
        with open(patch_path, 'w') as file:
            file.write(new_file)
        with open("after_patch.c", "w") as file:
            file.write(new_file)
        command_result = build()
        command = "cd ./nginx-cp && ./run.sh run_pov ../vuln_cpv1.bin pov_harness && cd .."
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pattern = r'libfuzzer exit=0'
        matches = re.findall(pattern, result.stdout, re.DOTALL)
    if len(matches) != 0:
        flag = False
        print("Patch the vuln successfully!")
        print("Run functionality tests...")
        command = "cd ./nginx-cp && ./run.sh run_tests && cd .."
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pattern = r'fail'
        matches = re.findall(pattern, result.stdout, re.DOTALL)
        if len(matches) != 0:
            command = f"diff -u -w {original_path} {patch_path} > bad_patch.diff"
            subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print("Some of functionality tests failed, bad patch. Continue to try.")
        else:
            command = f"diff -u -w {original_path} {patch_path} > good_patch.diff"
            subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print("All functionality tests passed, good patch!")
    else:
        print("Failed...")
        if try_cnt >= max_try_cnt:
            print("Patch generation terminates.")
            flag = False
        try_cnt += 1
        remove_patch_and_build(path, args.func)
