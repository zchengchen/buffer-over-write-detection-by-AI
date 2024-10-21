import argparse
import json
import subprocess
import re
import os
from openai import OpenAI

from tools.build_tools import remove_patch_and_build
from tools.build_tools import build
from tools.github_tools import search_function_in_github
from tools.regex_tools import extract_c_function
from tools.regex_tools import get_function_impl_from_response
from tools.regex_tools import extract_payload_from_response
from tools.regex_tools import is_commit_vuln
from tools.regex_tools import need_info
from tools.regex_tools import is_trigger
from tools.llm_tools import send_message

from prompts.analysis_request import request_analysis_prompt
from prompts.payload_request import request_payload_prompt

cpv_commit = ["Commit 165","Commit 12", "Commit 153", "Commit 184", "Commit 45", "Commit 89", "Commit 35", "Commit 112", "Commit 123", "Commit 75", "Commit 172", "Commit 1", "Initial Commit", "Commit 102"]
for i in range(190, 0, -1):
    commit_index = f"Commit {i}"
    history = []
    if commit_index in cpv_commit:
        analysis_prompt = request_analysis_prompt(commit_index)
        analysis_answer = send_message(analysis_prompt, None)
        history.append(analysis_prompt)
        history.append(analysis_answer)
        flag = True
        if is_commit_vuln(analysis_answer):
            print(f"-- {commit_index} --")
            cnt = 0
            while flag:
                print(f"--------try {cnt + 1}--------")
                payload_prompt = request_payload_prompt()
                payload_answer = send_message(payload_prompt, history)
                payload = extract_payload_from_response(payload_answer)
                if need_info(payload_answer):
                    print("need_info")
                    with open("needinfo", "a") as f:
                        f.write(payload_answer)
                if payload:
                    with open("tmp.bin", "w") as f:
                        f.write(payload)
                    command = f"cd ./nginx-cp && ./run.sh run_pov ../tmp.bin pov_harness && cd .."
                    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if is_trigger(result.stdout):
                        print("[+] payload generates successfully.")
                        flag = False
                    else:
                        print("Failed")
                    cnt += 1
                    if (cnt >= 10):
                        flag = False
                        print("terminate...")
                




