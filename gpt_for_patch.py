# python3 gpt_for_patch.py --commit_index 165 --func ngx_http_validate_from
from regex_tools import extract_c_function
from github_tools import search_function_in_github
import argparse
import re
import os

parser = argparse.ArgumentParser()
    
parser.add_argument("--commit_index")
parser.add_argument("--func")

args = parser.parse_args()

repo_owner = "aixcc-public"
repo_name = "challenge-004-nginx-source"
path = search_function_in_github(repo_owner, repo_name, args.func)
latest_impl = extract_c_function(os.path.join("nginx-source", path), args.func)

