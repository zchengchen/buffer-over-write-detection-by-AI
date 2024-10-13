# python3 gpt_for_payload.py --commit_index 165 --func ngx_http_validate_from

from openai import OpenAI
from os import getenv
import subprocess
import argparse
import json
import re
import os

parser = argparse.ArgumentParser()
    
parser.add_argument("--commit_index")
parser.add_argument("--func")

args = parser.parse_args()

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

gpt_ask_header = f"""
We find that this commit definitively contains Out-of-Bounds Write vulnerability and function "{args.func}" 
is highly suspicious. Please tell me how to obtain a proof of vulnerability. The following is analysis: \n
"""
commit_detail = "\nThe following is commit history:\n"

gpt_analysis = ""
with open("analysis_result.json", "r") as file:
    commits = json.load(file)
    for commit in commits:
        if (commit["commit_index"] == ("Commit " + str(args.commit_index))):
            gpt_analysis = commit["analysis"]
            commit_detail += commit["commit_diff"] + "\n"
            break

gpt_ask_tail = """
You should read the analysis and suspicious function in commit details line by line first, 
and according them to create practical payloads. You should provide proof of vulnerability 
in HTTP request format, with host: localhost.
"""

flag = True
try_cnt = 1
max_try_cnt = 10
while flag:
    print(f"Try to generate payload #{try_cnt}")
    message = gpt_ask_header + gpt_analysis + commit_detail + gpt_ask_tail
    response = send_message(message)
    # print(response)
    pattern = r'```http\n(.*?)```'
    matches = re.findall(pattern, response, re.DOTALL)
    if not matches:
        pattern = r'```plaintext\n(.*?)```'
        matches = re.findall(pattern, response, re.DOTALL)
    if not matches:
        pattern = r'```(.*?)```'
        matches = re.findall(pattern, response, re.DOTALL)
    with open("vuln_cpv1.bin", "w") as f:
        print(matches[0], file=f)
    pattern = r'libfuzzer exit=1'
    command = "cd ./nginx-cp && ./run.sh run_pov ../vuln_cpv1.bin pov_harness && cd .."
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    matches = re.findall(pattern, result.stdout, re.DOTALL)
    if matches:
        flag = False
        print("Payload generates successfully in vuln_cpv1.bin!")
    else:
        print("Failed...")
        if try_cnt >= max_try_cnt:
            print("Payload generation terminates.")
            flag = False
        try_cnt += 1