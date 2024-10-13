import argparse
import json
import subprocess
import re
import os
from openai import OpenAI
from os import getenv
from github import Github
from github_tools import search_function_in_github
from regex_tools import extract_c_function
from regex_tools import get_function_impl_from_response
from build_tools import remove_patch_and_build
from build_tools import build
import time
import shutil

repo_owner = "aixcc-public"
repo_name = "challenge-004-nginx-source"

project_yaml_path = "nginx-cp/project.yaml"
pov_harness_impl_path = "nginx-cp/src/harnesses/pov_harness.cc"
mail_harness_impl_path = "nginx-cp/src/harnesses/mail_request_harness.cc"
smtp_harness_impl_path = "nginx-cp/src/harnesses/smtp_harness.cc"
gpt_ask_header="""Now you are a system named Cyber Reasoning System (CRS) to detect vulnerabilities from commits in Github Repo.
We need to find vulnerabilities as many as possible. Vulnerabilities will be assessed based on their ability 
to trigger a specified AddressSanitizer. We will give you “test harnesses” that exercise project in Github Repo
functionality with CRS provided data. To demonstrate proof of vulnerability, CRSs will submit a test case that 
demonstrates the identified vulnerability in the form of data passed to these harnesses.
"""
project_info = "The followings are available AddressSanitizers that could be triggered and test harnesses to test functionality.\n"
with open(project_yaml_path, "r") as f:
    text = ""
    text = f.read()
    project_info += text
project_info += "\n"

harness_code = "The followings are implementation of available harnesses.\n---pov_harness--\n"
with open(pov_harness_impl_path, "r") as f:
    text = ""
    text = f.read()
    harness_code += text
harness_code += "\n"

harness_code += "---mail_request_harness--\n"
with open(mail_harness_impl_path, "r") as f:
    text = ""
    text = f.read()
    harness_code += text
harness_code += "\n"

harness_code += "---smtp_harness--\n"
with open(smtp_harness_impl_path, "r") as f:
    text = ""
    text = f.read()
    harness_code += text
harness_code += "\n"

commit_diff_header = "The following is commit diff, which you need to find suspicious C code which may trigger AddressSanitizer.\n"

gpt_ask_content = gpt_ask_header + project_info + harness_code + commit_diff_header
def get_commit_diff(commit_index):
    data = ""
    with open("commits.json", "r") as f:
        data = json.load(f)
        for d in data:
            if d["commit_index"] == f"Commit {commit_index}": 
                return d["commit_diff"]
    return ""

gpt_ask_tail = """\nPlease let me know all suspicious changes. You should check the diff line by line, and analysis code function by function. 
At the same time, you just need to focus on C code changes. If you find any suspicious modifications, 
please follow the format 'TRUE func_name func_name' and return the names of the functions where the 
suspicious modifications belong in the final line. Do not repeat the function name.
"""
# gpt_ask += get_commit_diff(12)
# gpt_ask += gpt_ask_tail
# with open("ask.txt", "w") as f:
#     print(gpt_ask, file=f)

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

# cpv_commit = ["Commit 165","Commit 12", "Commit 153", "Commit 184", "Commit 45", "Commit 89", "Commit 35", "Commit 112", "Commit 123", "Commit 75", "Commit 172", "Commit 1", "Initial Commit", "Commit 102"]

commits_history = {}
with open("commits.json", "r", encoding="utf-8") as file:
    commits_history = json.load(file)

analysis_result = []
# for commit in commits_history:
#     commit_index = commit["commit_index"]
#     result = {"commit_index": commit["commit_index"], "commit_diff": commit["commit_diff"], "analysis": ""}
#     if commit_index == "Initial Commit":
#         break
#     # if commit_index != "Commit 12":
#     #     continue
#     if not (commit_index in cpv_commit):
#         continue
#     commit_diff = commit["commit_diff"]
#     with open("ask.txt", "w") as f:
#         print(gpt_ask_content + commit_diff + gpt_ask_tail, file=f)
#     result["analysis"] = send_message(gpt_ask_content + commit_diff + gpt_ask_tail)
#     with open("response.txt", "w") as f:
#         print(result["analysis"], file=f)
    
#     analysis_result.append(result)

# with open("analysis_result_v1.json", "w") as f:
#     print(json.dumps(analysis_result, ensure_ascii=False), file=f)

with open("analysis_result_v1.json", "r") as f:
    commit_analysis = json.load(f)

for commit in commit_analysis:
    text = commit["analysis"]
    commit_index = commit["commit_index"]
    index = re.search(r'\b\d{1,3}\b', commit_index).group()
    true_vulnerable_func = ""
    if commit_index != "Commit 102":
        continue
    pattern = r'TRUE( ngx_[a-zA-Z0-9_]+)+'
    match = re.search(r'TRUE( ngx_[a-zA-Z0-9_]+)+', text)
    vuln_funcs = re.findall(r'ngx_[a-zA-Z0-9_]+', match.group(0))
    payload_flag = False
    print(f"--- {commit_index} ---")
    print("[+] Payload Generation")
    for func in vuln_funcs:
        patch_flag = False
        while True:
            func_path = search_function_in_github(repo_owner, repo_name, func)
            # print(func_path)
            if len(func_path) == 0:
                time.sleep(60) # Too many requests to Github API
            else:
                break
        original_path = os.path.join("nginx-source", func_path)
        patch_path = os.path.join("nginx-cp/src/nginx", func_path)
        func_latest_impl = extract_c_function(original_path, func)
        payload_prompt = f"""
            We find that this commit definitively contains some vulnerabilities and function "{func}" 
            is highly suspicious. Please tell me how to obtain a proof of vulnerability. Vulnerabilities will be 
            assessed based on their ability to trigger a specified AddressSanitizer. 
            """
        payload_prompt += project_info
        payload_prompt += harness_code
        payload_prompt += "The following is vulnerability analysis:\n"
        payload_prompt += commit["analysis"]
        payload_prompt += "\n"
        payload_prompt += "The following is the implementation of suspicious function:\n"
        payload_prompt += func_latest_impl
        payload_prompt += "\n"
        payload_prompt += """
            You should read the analysis and suspicious function in commit details line by line first, 
            and according them to create a practical payload. You should provide proof of vulnerability 
            in HTTP request format, with host: localhost.
            """
        # Extract payload from response
        max_try = 10
        try_cnt = 0
        while try_cnt < max_try:
            print(f"Generating payload #{try_cnt + 1} for {func}...")
            response = send_message(payload_prompt)
            pattern = r'```http\n(.*?)```'
            matches = re.findall(pattern, response, re.DOTALL)
            if not matches:
                pattern = r'```plaintext\n(.*?)```'
                matches = re.findall(pattern, response, re.DOTALL)
            if not matches:
                pattern = r'```(.*?)```'
                matches = re.findall(pattern, response, re.DOTALL)
            with open(f"payloads/bic_{index}.bin", "r") as f:
                matches[0] = f.read()
            with open("tmp_payload.bin", "w") as f:
                print(matches[0], file=f)
            test_harnesses = ["pov_harness", "smtp_harness", "mail_request_harness"]
            for test_harness in test_harnesses:
                pattern = r'libfuzzer exit=1'
                command = f"cd ./nginx-cp && ./run.sh run_pov ../tmp_payload.bin {test_harness} && cd .."
                result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                matches = re.findall(pattern, result.stdout, re.DOTALL)
                if matches:
                    print(f"Payload is generated successfully and stored in payloads/bic_{index}.bin.")
                    shutil.move("tmp_payload.bin", f"payloads/bic_{index}.bin")
                    payload_flag = True
                    true_vulnerable_func = func
                    break
            if not payload_flag:
                print("Failed...")
                try_cnt += 1
            else:
                break
        if payload_flag:
            # Generate patch
            patch_flag = False
            for func in vuln_funcs:
                if patch_flag:
                    break
                max_try = 10
                try_cnt = 0
                patch_prompt = f"""
                    The followings are vulnerability analysis, payload for proof of vulnerability and implementation of 
                    vulnerable function(s).\n
                    """
                patch_prompt += "The following is vulnerability analysis:\n"
                patch_prompt += commit["analysis"]
                patch_prompt += "\n"
                patch_prompt += "The following is vulnerable function:\n"
                func_path = search_function_in_github(repo_owner, repo_name, func)
                original_path = os.path.join("nginx-source", func_path)
                func_latest_impl = extract_c_function(original_path, func)
                patch_prompt += func_latest_impl
                patch_prompt += "\nThe following is successfully payload:\n"
                with open(f"payloads/bic_{index}.bin", "r") as f:
                    patch_prompt += f.read()
                patch_prompt += "\n"
                true_vulnerable_func = "ngx_mail_smtp_noop"
                patch_prompt += f"""
                    Please patch these functions {true_vulnerable_func} and at the same time keep this function work normally. In your code, do
                    not introduce any new header file. All the revisions should be included in the function body. Do not change 
                    the function's parameters and types of return value and keep the change inside the function body.
                    """
                print("[+] Patch Generation")
                while try_cnt < max_try:
                    print(f"Generating patch #{try_cnt + 1} for {func}...")
                    response = send_message(patch_prompt)
                    pattern = r'```c\n(.*?)```'
                    matches = re.findall(pattern, response, re.DOTALL)
                    if len(matches) == 0:
                        pattern = r'```(.*?)```'
                        matches = re.findall(pattern, response, re.DOTALL)
                    if len(matches) == 0:
                        pattern = r'```plaintext\n(.*?)```'
                        matches = re.findall(pattern, response, re.DOTALL)
                    patched_func = matches[0]
                    with open(original_path, 'r') as file:
                        file_content = file.read()
                    match = re.search(re.escape(func_latest_impl), file_content)
                    if match:
                        before_match = file_content[:match.start()]
                        after_match = file_content[match.end():]
                        new_file = before_match + "\n" + patched_func + after_match
                    with open(patch_path, 'w') as file:
                        file.write(new_file)
                    flag = 1
                    command_result = build()
                    for test_harness in test_harnesses:
                        command = f"cd ./nginx-cp && ./run.sh run_pov ../payloads/bic_{index}.bin {test_harness} && cd .."
                        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        pattern = r'libfuzzer exit=0'
                        matches = re.findall(pattern, result.stdout, re.DOTALL)
                        flag = (flag and len(matches))
                    if flag:
                        print(f"Patch is generated successfully and sotred in patches/bic_{index}.diff")
                        command = f"diff -u -w {original_path} {patch_path} > patches/bic_{index}.diff"
                        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        patch_flag = True
                        break
                    else:
                        print("Failed... Unpatch and rebuild...")
                        remove_patch_and_build(func_path, func)
                        try_cnt += 1
            break
        else:
            print(f"Payload generation for {func} terminates.")

        
                
        

    