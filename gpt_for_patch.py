import argparse

parser = argparse.ArgumentParser()
    
parser.add_argument("--commit_index")
parser.add_argument("--func")

args = parser.parse_args()

print(f"commit_index, {args.commit_index}!")
print(f"func_name: {args.func}")

