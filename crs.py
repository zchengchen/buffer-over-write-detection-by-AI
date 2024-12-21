import argparse
import json
import subprocess
import re
import os
from enum import Enum

from prompts.prompt_generator import *

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

class LLMOutState(Enum):
    INITIAL_STATE = 0
    TRIGGER_SUCCESS = 1
    TRIGGER_FAILED = 2
    NEED_FUNC_INFO = 3
    NEED_HARNESS_CODE = 4

repo_owner = "aixcc-public"
repo_name = "challenge-004-nginx-source"

project_yaml_path = "nginx-cp/project.yaml"
pov_harness_impl_path = "nginx-cp/src/harnesses/pov_harness.cc"
mail_harness_impl_path = "nginx-cp/src/harnesses/mail_request_harness.cc"
smtp_harness_impl_path = "nginx-cp/src/harnesses/smtp_harness.cc"

prompt_generator = PromptGenerator()
# print(prompt_generator.commit_analysis_template("1 prev_analysis").format(commit_diff="1"))



print(basic_prompt)