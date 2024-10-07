import subprocess
import os

def build():
    command = "cd ./nginx-cp && ./run.sh build && cd .."
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

def remove_patch_and_build(path, func_name):
    original_path = os.path.join("nginx-source", path)
    unpatch_path = os.path.join("nginx-cp/src/nginx", path)
    data = ""
    with open(original_path, 'r') as file_original:
        data = file_original.read()
    with open(unpatch_path, 'w') as file_unpatch:
        file_unpatch.write(data)
    build()

