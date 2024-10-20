import subprocess
import os

def build():
    command = "cd ./nginx-cp && ./run.sh build && cd .."
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

def remove_patch_and_build():
    command = "cd ./nginx-cp && make cpsrc-clean && make cpsrc-prepare && ./run.sh build && cd .."
    subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)