import argparse
import json
import subprocess
import re
import os

parser = argparse.ArgumentParser(description="A tool to manage commands like 'history --enable'")
subparsers = parser.add_subparsers(dest='command', help='Available commands')
history_parser = subparsers.add_parser('history', help='Handle history command')
history_parser.add_argument('--enable', action='store_true', help='run the script using previous records in the analysis_result.json.')
history_parser.add_argument('--disable', action='store_true', help='run the script from scratch.')
args = parser.parse_args()

if args.command == "history" and args.enable:
    print("Analysis potential vlunerabilities from all commits of nginx-source...")
    command = "python3 gpt_for_vuln_detect.py"
    subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print("Anlysis finished and result are stored in analysis_result.json.")

analysis_result = []
with open("analysis_result.json", "r") as file:
    analysis_result = json.load(file)
vuln_commits = []
vuln_funcs = []
for each_analysis in analysis_result:
    pattern = r'FALSE'
    matches = re.findall(pattern, each_analysis["analysis"], re.DOTALL)
    if len(matches) == 0:
        vuln_commits.append(each_analysis)
for each_commit in vuln_commits:
    text = each_commit["analysis"]
    pattern = r'TRUE(?: \[(.*?)\])+'
    matches = re.findall(r'\[(.*?)\]', text)
    if len(matches) == 0:
        continue
    text = each_commit["commit_index"]
    numbers = re.findall(r'\d+', text)
    vuln_func = {"commit_index": numbers[0], "vuln_func": []}
    for match in matches:
        if match[0:3] == "ngx":
            vuln_func["vuln_func"].append(match)
    vuln_funcs.append(vuln_func)

for func_info in vuln_funcs:
    commit_index = func_info["commit_index"]
    if commit_index != str(165):
        continue
    for func_name in func_info["vuln_func"]:
        # if func_name != "ngx_http_validate_from":
        #     continue
        print(f"Commit {commit_index}: {func_name}")
        command = f"python3 gpt_for_payload.py --commit_index {commit_index} --func {func_name}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
        pattern = r'Payload generates successfully'
        matches = re.findall(pattern, result.stdout, re.DOTALL)
        if len(matches) != 0:
            command = f"python3 gpt_for_patch.py --commit_index {commit_index} --func {func_name}"
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(result.stdout)
            pattern = r'good patch'
            matches_goodpatch = re.findall(pattern, result.stdout, re.DOTALL)
            pattern = r'bad patch'
            matches_badpatch = re.findall(pattern, result.stdout, re.DOTALL)
            if len(matches_badpatch) != 0 or len(matches_goodpatch) != 0:
                file_content = ""
                with open("vuln_cpv1.bin", "r") as f:
                    file_content = f.read()
                with open(f"./payloads/commit_{commit_index}_{func_name}.diff", "w") as f:
                    f.write(file_content)
                with open("good_patch.diff", "r") as f:
                    file_content = f.read()
                with open(f"./patches/commit_{commit_index}_{func_name}.diff", "w") as f:
                    f.write(file_content)
            else:
                print(f"Patch {func_name} in Commit {commit_index} failed.")
        else:
            print(f"Payload generation for {func_name} in Commit {commit_index} failed.")
