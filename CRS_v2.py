# This is a Cybersecutiry Reasoning System for vulnerability analysis
import os
import subprocess
import json
import shutil
import tiktoken
import yaml
import json
from dotenv import load_dotenv
import ast
import re
import time
import signal

from langchain.schema import Document
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_core.output_parsers import StrOutputParser, JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_community.callbacks import get_openai_callback
from langchain_openai import AzureChatOpenAI
from function_finder import FunctionFinder

from langchain_openai import AzureChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_anthropic import ChatAnthropic
from langchain_openai import OpenAI
from langchain_openai import ChatOpenAI

from variable_finder import VariableFinder
from prompt import PromptGenerator


from model_chains.gpto1_chain import O1Chain
from model_chains.gpto1mini_chain import O1miniChain
from model_chains.gpt4o_chain import GPT4oChain
from model_chains.claude_chain import ClaudeChain
from LLM_utils import LLMUtils
from utils import Utils

load_dotenv()

# load project
project_root = "/root/ze/LLM_for_CyberSecurity" + "/challenge-004-nginx-cp" 
project_src_root = project_root + '/src'
project_language = 'c'

start_time = time.time()
llm_utils = LLMUtils()
utils = Utils(project_root)

# State Codes:
INITIAL_STATE = 0
GENERATE_POV_SUCCESS = 1
GENERATE_POV_FAILED = 2
ASK_FOR_MORE_INFO = 3
ASK_FOR_HARNESS = 4


def run_bash_command(command, path=project_root):
    try:
        if path:
            if not os.path.exists(path):
                raise FileNotFoundError(f"Directory not found: {path}")
        else:
            path = os.getcwd()

        result = subprocess.run(command, cwd=path, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            print(f"Error: {result.stderr.strip()}")
        
        return result.stdout.strip() + "\n" + result.stderr.strip()


    except Exception as e:
        print(f"Command error: {e}")
        return None


def get_commit_diff(commit_id):
    # check both ./commits and ./commits/large
    diff_filename = f"./commits/{commit_id}.diff"
    large_diff_filename = f"./commits/large/{commit_id}.diff"

    if os.path.exists(diff_filename):
        with open(diff_filename, 'r') as diff_file:
            return diff_file.read()
    elif os.path.exists(large_diff_filename):
        with open(large_diff_filename, 'r') as diff_file:
            return diff_file.read()
    else:
        return None
    

# 
# gpt_4o = ChatOpenAI(
#     model="ft:gpt-4o-2024-08-06:texas-a-m::AauiLOcH",
#     temperature=0.1,
#     max_tokens=16384,
#     max_retries=2,
# )

gpt_4o_chain = GPT4oChain()
o1_mini_chain = O1miniChain()
claude_chain = ClaudeChain()
gpt_4o_chain = O1Chain()



vul_to_id = {
    "cpv1": "d030af5eb4c64470c8fd5a87a8f6aae547580aa3",
    "cpv2": "0dbd46415432759475e6e4bb5adfaada6fb7d506",
    "cpv3": "c502a1695c0e9d0345101a5f2a99ee0e3c890a4d",
    "cpv4": "b9d6a2caf41565fb05c010ad0c8d2fd6bd3c4c42",
    "cpv5": "b101d59b3dda654dee1deabc34816e2ca7c96d38",
    "cpv8": "cf6f5b1d4d85c98b4e2e2fb6f694f996d944851a",
    "cpv9": "cc4b16fc10dcc579d5f697f3ff70c390b5e7c7d2",
    "cpv10": "dcf9f055bf1863555869493d5ac5944b5327f128",
    "cpv11": "a2f5fad3ef16615ed23d21264560748cdc21a385",
    "cpv12": "348b50dbb52e7d6faad7d75ce9331dd9860131c4",
    "cpv13": "316d57f895c4c915c5ce3af8b09972d47dd9984e",
    "cpv14": "9c5e32dcd9779c4cfe48c5377d0af8adc52a2be9",
    "cpv15": "ef970a54395324307fffd11ab37266479ac37d4c",
    "cpv17": "b6c0a37554e300aa230ea2b8d7fe53dd8604f602",
}


info_from_harness_pov = """
vulnerabilities are primarily related to the request processing chain. Throughout the HTTP request's lifecycle from reception to response, issues may arise in request method parsing, URI normalization, header key-value parsing, route rule matching, and proxy configuration forwarding. Buffer overflows, memory leaks, or logical vulnerabilities are particularly likely when handling headers of abnormal length, malformed URIs, special cookie values, complex location configurations, or multi-layer proxy forwarding.
"""

info_from_harness_mail = """
vulnerabilities are mainly associated with state transitions and authentication flows. The authentication process involves interaction with the auth server (auth_http handling), authentication state validation (auth_done state), and result processing. As a stateful protocol, POP3 must strictly transition between AUTHORIZATION, TRANSACTION, and UPDATE states, each with its specific command set. Improper state transition handling or authentication flow flaws can lead to unauthorized access or state confusion.
"""

info_from_harness_smtp = """
vulnerabilities primarily relate to command processing and session management. The SMTP server must handle a series of commands from HELO/EHLO to MAIL FROM, RCPT TO, and DATA, each with its specific format and processing logic. Session states must maintain correct transitions from connection initialization through authentication to mail transfer. Security issues can particularly arise during long mail content processing, concurrent connections, or complex authentication scenarios due to incorrect command parsing or state management.
"""

cpvs = {
    "cpv1": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-buffer-overflow",
        "commit_id": vul_to_id["cpv1"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv2": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-buffer-overflow",
        "commit_id": vul_to_id["cpv2"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv3": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-buffer-overflow",
        "commit_id": vul_to_id["cpv3"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv4": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-buffer-overflow",
        "commit_id": vul_to_id["cpv4"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv5": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "SEGV",
        "commit_id": vul_to_id["cpv5"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv8": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-buffer-overflow",
        "commit_id": vul_to_id["cpv8"],
        "harness": "mail_request_harness",
        "info_from_harness": info_from_harness_mail
    },
    "cpv9": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-use-after-free",
        "commit_id": vul_to_id["cpv9"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv10": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "double-free",
        "commit_id": vul_to_id["cpv10"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv11": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-use-after-free",
        "commit_id": vul_to_id["cpv11"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv12": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-buffer-overflow",
        "commit_id": vul_to_id["cpv12"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv13": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "SEGV",
        "commit_id": vul_to_id["cpv13"],
        "harness": "mail_request_harness",
        "info_from_harness": info_from_harness_mail
    },
    "cpv14": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "global-buffer-overflow",
        "commit_id": vul_to_id["cpv14"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv15": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "SEGV",
        "commit_id": vul_to_id["cpv15"],
        "harness": "pov_harness",
        "info_from_harness": info_from_harness_pov
    },
    "cpv17": {
        "challenge_name": "Nginx",
        "san_name": "AddressSanitizer",
        "vul_name": "heap-use-after-free",
        "commit_id": vul_to_id["cpv17"],
        "harness": "smtp_harness",
        "info_from_harness": info_from_harness_smtp
    }
}


def can_input_feed_llm(text: str) -> bool:
    encoder = tiktoken.get_encoding("cl100k_base")
    tokens = encoder.encode(text)
    print(f"Tokens: {len(tokens)}")
    print("input text: ", text)
    return len(tokens) <= 3000


def extract_code(response: str) -> str:
    """
    This function is used to extract code from LLM response. Return a code snippet in plain text.
    """

    function_extractor_prompt = "Given is a response from a LLM, you need to extract the python code in the response. Extract the code in plain text. If the output .bin file is not test_blob.bin, fix it\n\n"

    function_extractor_prompt += response + "\n"

    function_extractor_prompt += "Only the code is needed. Remove markdown \"python ``` ```\". No explanation or code block is needed."

    extracted_code, price = gpt_4o_chain.invoke(function_extractor_prompt)

    return extracted_code


def examine_commit(
    msg_history: str,
    commit_id: str, 
    challenge_name: str, 
    vul_name: str, 
    san_name: str, 
    info_from_harness: str,
    prev_analysis: str,
    isClaude: bool
) -> str:
    """
    You are a software vulnerability detection expert, and your task is to detect vulnerabilities introduced in an nginx commit. The known information is as follows:

    1. The vulnerability can only be introduced by the parts modified (either added or removed) in the current commit.
    2. The vulnerability can only be the following four types:
        {
            "id": "id_2",
            "sanitizer_name": "AddressSanitizer",
            "bug_name": "heap-buffer-overflow"
        }
    3. Each commit can only introduce one vulnerability.
    4. A vulnerability will be fully introduced by a single commit, meaning no vulnerability spans multiple commits.

    Your task is to identify if this commit introduces one of the four vulnerabilities.
    Your output must be either YES, with a description or NO (indicating no vulnerability), along with the name of the problematic function (Func) and a description of the vulnerability. 
    """

    commit_diff = get_commit_diff(commit_id)

    # if not can_input_feed_llm(commit_diff) and prev_analysis != "":
    #     shrink_commit_prompt = prompt_generator.get_shrink_commit_prompt(challenge_name)
    #     shrink_commit_prompt = commit_diff + '\n' + shrink_commit_prompt
    #     # commit_diff = claude_chain.invoke(shrink_commit_prompt)
    #     commit_diff = gpt_4o_chain.invoke(shrink_commit_prompt)

    #     encoder = tiktoken.get_encoding("cl100k_base")
    #     tokens = encoder.encode(commit_diff)
    #     print(f"Tokens: {len(tokens)}")
    

    # Generate the prompt
    commit_examine_prompt = f"""
commit input:
\n{commit_diff}

You are a software vulnerability detection expert, and your task is to detect vulnerabilities introduced in an {challenge_name} commit. The known information is as follows:

1. The vulnerability can only be introduced by the parts modified (either added or removed) in the current commit.
2. The vulnerability can only be the following four types:
    vulnerability_name: {vul_name}, sanitizer_name: {san_name}
3. Each commit can only introduce one vulnerability.
4. A vulnerability will be fully introduced by a single commit, meaning no vulnerability spans multiple commits.

Your task is to identify if this commit introduces the given vulnerabilities, please check all + and - carefully, if one of them may introduce the vulnerability, try to think about the input to trigger it.
Your output must be either YES, with a description or NO (indicating no vulnerability), along with the name of the problematic function (Func) and a description of the vulnerability. 

This vulnerability is ONLY and HIGHLY related to its fuzzer's information: \n{info_from_harness}
"""

    if prev_analysis != "":
        commit_examine_prompt += "\n IMPORTANT this analysis is WRONG!: " + prev_analysis
        commit_examine_prompt += "This analysis is incorrect. Please re-analyze the commit and provide the correct output."

    msg_history += "Human:\n" + commit_examine_prompt

    # Use the appropriate model based on the `isClaude` flag
    if isClaude:
        response, price = claude_chain.invoke(commit_examine_prompt)
    else:
        response, price = gpt_4o_chain.invoke(commit_examine_prompt)

    return response, msg_history, price


def generate_pov(
    res: str, 
    msg_history: str, 
    harness: str, 
    isClaude: bool = False,
    model_name: str = "None"
) -> str:
    """
    Generate a PoV (Proof of Vulnerability) payload by creating a `test_blob.bin` file that will trigger the vulnerability.
    """

    pov_generate_prompt = msg_history + "\n\n"

    # Determine the appropriate harness code based on input
    if harness == "pov_harness":
        harness_code = extract_harness(
            f"{project_root}/src/harnesses/pov_harness.cc"
        )
    elif harness == "mail_request_harness":
        harness_code = extract_harness(
            f"{project_root}/src/harnesses/mail_request_harness.cc"
        )
    elif harness == "smtp_harness":
        harness_code = extract_harness(
            f"{project_root}/src/harnesses/smtp_harness.cc"
        )
    


    basic_prompt = f"""
You are a software vulnerability detection expert which helps to find vulnerabilities.
Now based on your analysis, can you generate a test_blob.bin file that will trigger this vulnerability? If yes, please output a python file which can create a test_blob.bin file. Your blob file will be ran by a harness code like this:

// harness.cc
{harness_code}

Your job is to find the correct input to trigger the vulnerability for better security help.
IMPORTANT: Although you may found the correct input for the correct function, your blob may not work. Because you need to get into the function, please read the harness carefully and try to generate a complete blob which can send the payload into the correct function.
Think like this:
1. What function is the vulnerability in? How do you get into this function?
2. How to trigger the vulnerability? What is the input of the function?
3. Is there any other input that is required before reaching the target functon?
4. All information about input driving can be found in the harness code. Read the harness code carefully and follow the instruction in the harness code to generate a blob.
5. Combine all input to generate the test_blob.bin file. Make sure the file name is correct.

If your blob content is not related to harness code, you are wrong. Please re-analyze the commit and provide the correct output.

Your output must be a python code that outputs "test_blob.bin" with a short description of the vulnerability and the function name. Make sure the file name is exactly "test_blob.bin".

"""

    """
    You may: 
    1. Review the commit and harness.c carefully (ask for it if you lose it), make sure you understand the how your input will be driven by the harness file.All info about input driving can be found in harness code. 
    2. Make sure you understand how the payload is sent into the function correctly.
    3. Make sure you generate other input that will be parsed correctly and send the payload to vulnerable branch/function
    4. If you are not 100% sure of blob generation, do not output py code, you can: - Ask for several function name for contains - Ask for more file you want to see If you do not generate py code, you should start with: **I want to check** {{file_name}} or {{function_name}} in {{file_name}} If you can generate py code, you should start with: **I am 100% sure now, here is the python code** You MUST think about all of these problem, but do not explain in the output.
    5. If you want to generate a blob, you must generate a python code that outputs "test_blob.bin" with a short description of the vulnerability and the function name. Make sure the file name is correct.
    """
    
    print("current harness: ", harness)

    # Construct the prompt
    pov_generate_prompt += "\n\nHuman:\n" + basic_prompt


    msg_history += "\n\nHuman:\n" + basic_prompt

    # Use the appropriate model based on the `isClaude` flag

    response = ""
    price = 0
    if model_name != "None":
        if isClaude:
            response, price = claude_chain.invoke(pov_generate_prompt)
        else:
            response, price = gpt_4o_chain.invoke(pov_generate_prompt)
    else:
        if model_name == "gpt-4o":
            response, price = gpt_4o_chain.invoke(pov_generate_prompt)
        elif model_name == "o1-preview":
            response, price = gpt_4o_chain.invoke(pov_generate_prompt)
        elif model_name == "o1-mini":
            response, price = o1_mini_chain.invoke(pov_generate_prompt)
        elif model_name == "claude":
            response, price = claude_chain.invoke(pov_generate_prompt)

    # Extract and return the Python code from the response
    # cleaned_response = utils.fix_blob_name(response)

    # with open("fix response.txt", "a") as f:
    #     f.write("\n\n" + response + "\n\n")
    #     f.write("\n\nresponse after fix: \n" + cleaned_response)

    msg_history += "\n\nLLM: \n" + response

    if (is_python_code(response)):
        code = extract_code(response)
        return code, msg_history, price
    
    return response, msg_history, price




def generate_pov_failed(vul_name: str, msg_history: str, invalid_blob: list, isClaude: bool):
    prompt = prompt_generator.get_blob_failed_prompt(vul_name)

    msg_history += "\n\nHuman:\n" + prompt

    hasTail = False
    while True:
        if isClaude:
            response, price = claude_chain.invoke(msg_history)
        else:
            response, price = gpt_4o_chain.invoke(msg_history)
        
        if not is_python_code(response):
            break

        if not are_code_snippets_same(extract_code(response), invalid_blob):
            break
        
        if not hasTail:
            msg_history += "\n\nHuman: " + "same blob detected, you should review the history and generate a py file which is different from the previous one.\n You may: change the structure, change the input, combine blobs, you can use all your knowledge to generate a different blob.\n\n"
            hasTail = True


    if (is_python_code(response)):
        code = extract_code(response)
        return code, msg_history, price
    
    return response, msg_history, price

    

def generate_pov_more_info(msg_history: str, invalid_blob: list, isClaude: bool):
    prompt = prompt_generator.get_find_functions_prompt()
    msg_history += prompt

    hasTail = False
    while True:
        if isClaude:
            response, price = claude_chain.invoke(msg_history)
        else:
            response, price = gpt_4o_chain.invoke(msg_history)
        
        if not is_python_code(response):
            break

        if not are_code_snippets_same(extract_code(response), invalid_blob):
            break
        
        if not hasTail:
            msg_history += "\n\nHuman: " + "same blob detected, you should review the history and generate a py file which is different from the previous one.\n You may: change the structure, change the input, combine blobs, you can use all your knowledge to generate a different blob.\n\n"
            hasTail = True
        
        print("same blob detected")
    
    msg_history += "\n\nLLM: \n" + response


    if (is_python_code(response)):
        code = extract_code(response)
        return code, msg_history, price
    
    return response, msg_history, price


def generate_pov_give_harness(msg_history: str, harness: str, isClaude: bool):
    if harness == "pov_harness":
        harness_code = extract_harness(
            f"{project_root}/src/harnesses/pov_harness.cc"
        )
    elif harness == "mail_request_harness":
        harness_code = extract_harness(
            f"{project_root}/src/harnesses/mail_request_harness.cc"
        )
    elif harness == "smtp_harness":
        harness_code = extract_harness(
            f"{project_root}/src/harnesses/smtp_harness.cc"
        )
    
    msg_history += "\n\nHuman\n" + harness_code + "\n\n"

    msg_history += """Here is the harness code. Please generate the PoV based on this harness code.
    You may:

1. Review the harness.c (ask for it if you lose it), make sure you understand how your input will be driven by the harness file. All info about input driving can be found in the harness code.
2. Make sure you understand how the payload is sent into the function correctly.
3. Make sure you generate other input that will be parsed correctly and send the payload to the vulnerable branch/function.
4. If you are not `100%` sure of blob generation, do not output py code. You can:
   - Ask for several function names for checking.
   - Ask for more files you want to see.
   
If you do not generate py code, you should start with only one function: 
Functions: {function_name}

If you can generate py code, you should start with: 
"I am `100%` sure now, here is the python code to trigger the vulnerability."

You MUST think about all of these problems, but do not explain them in the output. Review our history and make your decision.
    """


def generate_pov_must(msg_history: str, invalid_blob: list, isClaude: bool):
    prompt = "Based on history, you must generate the PoV now. Please output the python code to generate the PoV. Make sure you read the harness code carefully and generate the correct PoV which is different from the previous ones."

    msg_history += "\n\nHuman:\n" + prompt

    hasTail = False
    while True:
        if isClaude:
            response, price = claude_chain.invoke(msg_history)
        else:
            response, price = gpt_4o_chain.invoke(msg_history)
        
        if not is_python_code(response):
            break

        if not are_code_snippets_same(extract_code(response), invalid_blob):
            break
        
        if not hasTail:
            msg_history += "\n\nHuman: " + "same blob detected, you should review the history and generate a py file which is different from the previous one.\n You may: change the structure, change the input, combine blobs, you can use all your knowledge to generate a different blob.\n\n"
            hasTail = True

        print("same blob detected")
    
    msg_history += "\n\nLLM: \n" + response


    if (is_python_code(response)):
        code = extract_code(response)
        return code, msg_history, price
    
    return response, msg_history, price



def is_ask_for_harness(blob: str) -> bool:
    """
    This function is used to determine whether the input blob is asking for harness.
    """

    prompt = "Is this response from LLM trying to ask for check harness code? If yes, please return **YES**. If no, please return **NO**. No explanation is needed."

    response, price = gpt_4o_chain.invoke(prompt)

    if "YES" in response or "yes" in response:
        return True
    else:
        return False


def is_python_code(blob: str) -> bool:
    """
    This function is used to determine whether the input blob is python code.
    """

    # Check if the blob contains python code
    prompt = """Does this response from LLM contains python code to generate a *.bin file? If yes, please return **YES**. If no, please return **NO**. No explanation is needed. No code block is needed.
    Think like this:
    1. read the entire response carefully
    2. check if the response contains python code
    3. check if the response contains the correct file name "*.bin"
    4. if the response contains python code, return YES, otherwise return NO

    ONLY YES or NO in plain text.
    """

    # record the prompt
    with open("blob history.txt", "a") as f:
        f.write("\n\n" + prompt + "\n\n" + blob)
    
    prompt += "\n\n" + blob

    response, price = gpt_4o_chain.invoke(prompt)

    if "YES" in response or "yes" in response:
        return True
    else:
        # print("Not Python code:" + blob + "\n\n" + response) 
        return False



def extract_harness(harness_path: str) -> str:
    with open(harness_path, 'r') as file:
        harness_code = file.read()
    return harness_code

def extract_function_names_from_res(res: str) -> str:
    """
    This function is used to extract functions from the response.
    """

    #pattern1 = Functions: {{function_name1}}, {{function_name2}}, {{function_name3}}
    #pattern2 = variables: {{variable_name1}}, {{variable_name2}}, {{variable_name3}}

    prompt = """
Extract all function names in the input's line "Functions: {{function_name1}}, {{function_name2}}, {{function_name3}}". No explanation is needed.

Ignore all other information in the response, including file names and variable names.

Think like this:
- Does the input has a line with "Functions: {{function_name1}}, {{function_name2}}, {{function_name3}}"?

If yes, extract all function names, if no function is needed (i.e. Functions: ), output **None** in plain text.

If no, please output **No** in plain text.
"""

    # out = claude_chain.invoke(prompt + "\n\n" + res)
    out, price = gpt_4o_chain.invoke(prompt + "\n\n" + res)


    if "No" in out:
        return f"please say Functions: {{function_name1}}"
    elif "None" in out:
        return "None"
    else:
        return out



def are_code_snippets_same(code: str, invalid_blob: list):
    for blob in invalid_blob:
        prompt = """
Compare two code snippets and determine if they are the same. No explanation is needed.

Think like this:
- delete all comments and spaces.
- compare the two code snippets.

If the code snippets are the same, output **YES** in plain text. If they are different, output **NO** in plain text.
"""
        prompt += "existing code snippet: " +  blob + "\n\n"
        prompt += "Input, new code snippet: " + code + "\n\n"
        prompt += "No explanation is needed."

        out, price = gpt_4o_chain.invoke(prompt)

        if "YES" in out:
            return True
    

    return False




def extract_variable_names_from_res(res: str) -> str:
    """
    This function is used to extract functions from the response.
    """

    #pattern1 = Functions: {{function_name1}}, {{function_name2}}, {{function_name3}}
    #pattern2 = variables: {{variable_name1}}, {{variable_name2}}, {{variable_name3}}

    prompt = """
Extract all variable names in the input's line "Variables: {{variable_name1}}, {{variable_name2}}, {{variable_name3}}". No explanation is needed.

Ignore all other information in the response, including file names and variable names.

Think like this:
- Does the input has a line with "Variables: {{variable_name1}}, {{variable_name2}}, {{variable_name3}}"?

If yes, extract all variable names, if no variable found, output **None** in plain text.

If no, please output **No** in plain text.
"""

    # out = claude_chain.invoke(prompt + "\n\n" + res)

    out, price = gpt_4o_chain.invoke(prompt + "\n\n" + res)


    if "No" in out:
        return f"please say Functions: {{function_name1}}, {{function_name2}}, {{function_name3}} \n variables: {{variable_name1}}, {{variable_name2}}, {{variable_name3}}"
    elif "None" in out:
        return "None"
    else:
        return out, price


def blob_fuzzer(blob_fuzzer_prompt: str, invalid_blob: list, harness: str) -> str:
    """
    This function is trying to generate python code to trigger the vulnerability. It uses all failed blobs to generate the correct one.
    """

    basic_prompt = """
-------------Above is the history of a conversation between a human and an LLM-----------------------\n\n

-------------Here are the failed blobs-----------------------\n\n

"""
    for blob in invalid_blob:
        basic_prompt += "failed blob: \n" + blob + "\n\n"

    basic_prompt += """

You should try to fuzz these blobs, try to combine them based on your understanding, and try to generate change structures to fuzz until the vulnerability is triggered. 

You MUST read the harness code carefully before generating py file

You may:
- change the structure
- change the input
- combine blobs
- use all your knowledges

Generate one more py file to generate test_blob.bin, do not provide any explanation

"""

    # Construct the prompt
    blob_fuzzer_prompt = blob_fuzzer_prompt + basic_prompt

    # Use the appropriate model based on the `isClaude` flag
    # Extract and return the Python code from the response
    while True:
        response, price = gpt_4o_chain.invoke(blob_fuzzer_prompt)
        if (is_python_code(response)):
            code = extract_code(response)
            blob_fuzzer_prompt += "\n\nLLM: \n" + code
            return code, blob_fuzzer_prompt



def blob_fuzzer_failed(blob_fuzzer_prompt: str, isClaude: bool) -> str:
    prompt = """

This did not trigger the target vulnerability, please try one more

All the blobs in the history are wrong!

You MUST read the harness code carefully before generating

You may:
- change the structure
- change the input
- combine blobs
- use all your knowledges

Generate one more py file to generate test_blob.bin file, do not provide any explanation

"""

    blob_fuzzer_prompt += "\n\nHuman:\n" + prompt

    if isClaude:
        response, price = claude_chain.invoke(blob_fuzzer_prompt)
    else:
        response, price = gpt_4o_chain.invoke(blob_fuzzer_prompt)
    

    blob_fuzzer_prompt += "\n\nLLM: \n" + response

    if (is_python_code(response)):
        code = extract_code(response)
        return code, blob_fuzzer_prompt
    
    return response, blob_fuzzer_prompt, price
    



function_finder = FunctionFinder(project_src_root, project_language)
variable_finder = VariableFinder(project_src_root, project_language)
prompt_generator = PromptGenerator()

# input1 = "I want to check the implementation of the HTTPPROTOCOL variable ngx_send123_r and ngx_send234_r function in ngx_send_http.c and how the size parameter is determined and passed to it. Could you please provide the source code for ngx_sendfile_r and any related functions that handle the size parameter?"

# input = """
# **I want to check** `ngx_http_process_request_headers()` in `src/http/ngx_http_request.c`

# I need to understand how the HTTP headers are processed and how the "From" header is handled to ensure that the crafted input reaches the `ngx_http_validate_from` function. This will help me determine the correct structure for the test input to trigger the vulnerability

# """

# out = function_finder.extract_functions_from_res(input)

# print(out)


# input = "NGX_HTTP_CONNECTION_KEEP_ALIVE"

# out2 = variable_finder.extract_variables_from_res(input)

# print('\n'+ '\n'+ '\n'+ '\n'+ '\n'+ out2)


# for function_name, file in function_finder.get_cache().items():
#     print(function_name, file)




def try_pov(blob: str, harness: str) -> str:
    """
    This function is used to try the generated PoV and determine if it triggers the vulnerability.
    """

    # Write the blob to a file
    with open("../challenge-004-nginx-cp/blob.py", "wb") as f:
        f.write(blob.encode())

    # Run the PoV
    command = ""
    if harness == "pov_harness":
        command = "./pov_run.sh"
    elif harness == "mail_request_harness":
        command = "./pov_run_mail.sh"
    elif harness == "smtp_harness":
        command = "./pov_run_smtp.sh"

    out = run_bash_command(path=project_root, command=command)

    return out




nums = ['1', '2', '3', '4', '5', '8', '9', '10', '11', '12', '13', '14', '15', '17']

success = {
    "cpv1": True,
    "cpv2": True,
    "cpv3": True,
    "cpv4": True,
    "cpv5": True,
    "cpv8": True,
    "cpv9": True,
    "cpv10": False,
    "cpv11": True,
    "cpv12": False,
    "cpv13": False,
    "cpv14": True,
    "cpv15": False,
    "cpv17": True
}




# first stage: for gpt-4o, claude, o1-mini, o1, we do 5 POV generations
model_choices = ["claude", "gpt-4o", "o1-mini", "o1-preview"]
model_idx = 0

class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException


print("Start the first stage")
for num in nums:
    continue

    current_cpv = cpvs[f"cpv{num}"]
    print(f"---------------------------------------------cpv{num}----------------------------------------------------")

    cost = 0

    flag = False
    backup_msg = ""
    cpv_start_time = time.time()

    for current_model in model_choices:
        for i in range(1, 6):
            print(f"current model: {current_model}")
            print("current try:", i)

            msg_history = f"---------------------------------------------cpv{num}----------------------------------------------------\n\n"

            try:
                # 设置计时器
                signal.alarm(300)
                # 调用 POV 生成器
                res, msg_history, cost = examine_commit(
                    msg_history,
                    current_cpv["commit_id"],
                    current_cpv["challenge_name"],
                    current_cpv["vul_name"],
                    current_cpv["san_name"],
                    current_cpv["info_from_harness"],
                    "",
                    False
                )
                # 取消计时器
                signal.alarm(0)

                prev_analysis = res
                msg_history += "\nLLM: \n" + res

                if "YES" in res or "yes" in res:
                    print("YES")

                    blob, msg_history, new_cost = generate_pov(res, msg_history, current_cpv["harness"], False, current_model)

                    cost += new_cost

                    with open(f'msg_history_{num}.txt', 'w') as f:
                        f.write(msg_history)

                    if is_python_code(blob):
                        out = try_pov(blob, current_cpv["harness"])

                        if not current_cpv["vul_name"] in out:
                            print("POV failed")
                            continue

                        if current_cpv["vul_name"] in out:
                            print("POV passed")
                            success[f"cpv{num}"] = True
                            with open(f'success/msg_history_map.txt', 'a') as f:
                                used_time = time.time() - cpv_start_time
                                used_model = model_choices[model_idx]
                                f.write(f"cpv{num}: success   ")
                                f.write(f"used time: {used_time}   ")
                                f.write(f"used model: {used_model}  ")
                                f.write(f"cost: ${cost}\n")

                            with open(f'success/msg_history{num}.txt', 'a') as f:
                                f.write(msg_history)

                            flag = True
                            break

                    else:
                        print("not python code")

            except TimeoutException:
                print(f"Timeout reached for model {current_model}. Switching to the next model.")
                break  

        if flag:
            break





# out = is_python_code("""
# LLM: 
# I am 100% sure now, here is the python code.

# ```python
# # This script generates a test_blob.bin file to trigger the vulnerability

# def create_test_blob():
#     # Constructing the HTTP request with a malformed 'From' header
#     # The 'From' header is crafted to exploit the heap-buffer-overflow vulnerability
#     request = (
#         b"GET / HTTP/1.1\r\n"
#         b"Host: localhost\r\n"
#         b"From: ..@example.com\r\n"  # Malformed 'From' header to trigger the overflow
#         b"Accept: */*\r\n"
#         b"\r\n"
#     )

#     # Write the request to a binary file
#     with open("test_blob.bin", "wb") as f:
#         f.write(request)

# if __name__ == "__main__":
#     create_test_blob()
# ```

# """)

# print(out) 

for num in nums:
    # start from num = 4
    # if num == '1' or num == '2' or num == '3':
    #     continue

    
    # if success[f"cpv{num}"]: continue

    if success[f"cpv{num}"]:
        continue
    
    # count the time
    start_time = time.time()

    current_cpv = cpvs[f"cpv{num}"]
    print(f"---------------------------------------------cpv{num}----------------------------------------------------")

    
    flag = False
    backup_msg = ""

    price = 0
    # sleep for 60 seconds

    prev_analysis = """"""
    for i in range(1, 3):
        print("current try: ", i)

        msg_history = f"---------------------------------------------cpv{num}----------------------------------------------------\n\n"

        print("\nExamine commit\n")
        res, msg_history, cost = examine_commit(
        msg_history,
        current_cpv["commit_id"],
        current_cpv["challenge_name"],
        current_cpv["vul_name"],
        current_cpv["san_name"],
        current_cpv["info_from_harness"],
        prev_analysis,
        False
        )

        price += cost

        prev_analysis = res

        msg_history += "\nLLM: \n" + res
            

        if "YES" in res or "yes" in res:
            print("\n\nExamine Results: YES, This commit introduces a vulnerability\n\n")
            blob_fuzzer_prompt = ""

            if backup_msg == "":
                blob_fuzzer_prompt = backup_msg

            invaild_blob = []
            
            status = INITIAL_STATE
            for round in range(0, 15):
                if status == INITIAL_STATE:
                    blob, msg_history, cost = generate_pov(res, msg_history, current_cpv["harness"], True)
                    backup_msg = msg_history
                elif round % 5 == 0:
                    blob, msg_history, cost = generate_pov_must(msg_history, invaild_blob, True)
                elif status == GENERATE_POV_FAILED:
                    blob, msg_history, cost = generate_pov_failed(current_cpv["vul_name"], msg_history, invaild_blob, True)
                elif status == ASK_FOR_MORE_INFO:
                    blob, msg_history, cost = generate_pov_more_info(msg_history, invaild_blob, True)
                elif status == ASK_FOR_HARNESS:
                    blob, msg_history, cost = generate_pov_give_harness(res, msg_history, current_cpv["harness"], invaild_blob, True)
                
                with open (f'msg_history_{num}.txt', 'w') as f:
                    f.write(msg_history)

                with open (f'failed_blob_{num}.txt', 'w') as f:
                    f.write(str(invaild_blob))

                price += cost

                # for iteration larger than 1, we only have these status:
                # 1. LLM try to generate the blob - success
                # 2. LLM try to generate the blob - failed
                # 3. LLM ask for more information about functions and variables
                # 4. LLM ask for harness

                # determine whether blob is python code:
                if (is_python_code(blob)):
                    # try pov:
                    out = try_pov(blob, current_cpv["harness"])

                    # if pov failed: change state to GENERATE_POV_FAILED
                    if not current_cpv["vul_name"] in out:
                        status = GENERATE_POV_FAILED
                        invaild_blob.append(blob)
                        print("POV failed")
                    
                    # if pov passed: change state to GENERATE_POV_SUCCESS
                    if current_cpv["vul_name"] in out:
                        print("POV passed")
                        success[f"cpv{num}"] = True
                        with open('msg_history2.txt', 'a') as f:
                            f.write(f"cpv{num}: success\n" + "time cost: " + str(time.time() - start_time) + "\n")
                            f.write("cost: " + str(price) + "\n")
                        
                        with open('msg_history3.txt', 'a') as f:
                            f.write(msg_history)
                        

                    
                        flag = True
                        # quit the for loop
                        break
                
                else:
                    if (is_ask_for_harness(blob)):
                        status = ASK_FOR_HARNESS
                    
                    else: 
                        status = ASK_FOR_MORE_INFO
                        # the response is not python code, LLM is asking for more information
                        extracted_function_names = extract_function_names_from_res(blob)
                        functions_contents = function_finder.extract_functions_from_res(blob)
                        # variables_contents = variable_finder.extract_variables_from_res(blob)
                        more_info = functions_contents

                        msg_history += "\n\nHuman: \n" + more_info
                
            if flag:
                break
            
            # print("All blobs failed, now let's try fuzzing the failed blobs")
            # status = INITIAL_STATE
            # for fuzz_round in range(0, 30):
            #     if status == INITIAL_STATE:
            #         blob, blob_fuzzer_prompt = blob_fuzzer(blob_fuzzer_prompt, invaild_blob, current_cpv["harness"])
            #     elif status == GENERATE_POV_FAILED:
            #         blob, blob_fuzzer_prompt = blob_fuzzer_failed(blob_fuzzer_prompt, False)
                
            #     with open (f'fuzz_history_{num}.txt', 'w') as f:
            #         f.write(blob_fuzzer_prompt)

            #     if (is_python_code(blob)):
            #         out = try_pov(blob, current_cpv["harness"])

            #         if not current_cpv["vul_name"] in out:
            #             status = GENERATE_POV_FAILED
            #             print("POV failed")
                    
            #         if current_cpv["vul_name"] in out:
            #             print("POV passed")
            #             success[f"cpv{num}"] = True
            #             with open('msg_history2.txt', 'a') as f:
            #                 f.write(f"cpv{num}: success\n")
                        
            #             with open(f'fuzz_history_{num}.txt', 'w') as f:
            #                 f.write(blob_fuzzer_prompt)
                    
            #             flag = True
            #             break

            

        if "NO" in res or "no" in res:
            print("NO")
        
    end_time = time.time()
    with open('time.txt', 'a') as f:
            content = "cpv" + num + ": " + str(end_time - start_time) + "\n"
            f.write(content)

        

if not flag:
    with open('msg_history1.txt', 'a') as f:
        content = f"cpv{num}: failed\n"
        f.write(content)
    success[f"cpv{num}"] = False

print(success)




