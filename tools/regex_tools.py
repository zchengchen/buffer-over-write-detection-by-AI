import re
def extract_c_function(file_path, function_name):
    pattern = rf"\b[\w\s\*]+\s+\**{function_name}\s*\([^)]*\)\s*\{{"
    with open(file_path, 'r') as f:
        content = f.read()
    match = re.search(pattern, content)
    if not match:
        return None
    
    start_pos = match.start()
    brace_count = 0
    inside_function = False
    function_code = ""
    
    for i in range(start_pos, len(content)):
        char = content[i]
        function_code += char
        
        if char == '{':
            if not inside_function:
                inside_function = True
            brace_count += 1
        elif char == '}':
            brace_count -= 1
        if inside_function and brace_count == 0:
            break
    
    return function_code

def get_function_impl_from_response(response, function_name):
    pattern = rf"```c\b[\w\s\*]+\s+\**{function_name}\s*\([^)]*\)\s*\{{```"
    content = response
    match = re.search(pattern, content)
    if not match:
        return None
    
    start_pos = match.start()
    brace_count = 0
    inside_function = False
    function_code = ""
    
    for i in range(start_pos, len(content)):
        char = content[i]
        function_code += char
        
        if char == '{':
            if not inside_function:
                inside_function = True
            brace_count += 1
        elif char == '}':
            brace_count -= 1
        if inside_function and brace_count == 0:
            break
    
    return function_code

def extract_payload_from_response(response):
    pattern = r'```http\n(.*?)```'
    matches = re.findall(pattern, response, re.DOTALL)
    if len(matches) == 0:
        pattern = r'```plaintext\n(.*?)```'
        matches = re.findall(pattern, response, re.DOTALL)
    if len(matches) == 0:
        pattern = r'```(.*?)```'
        matches = re.findall(pattern, response, re.DOTALL)
    if len(matches) == 0:
        print("[-] Failed to extract payload from response.")
        return None
    return matches[0]

def is_commit_vuln(response):
    if re.search(r'\bYES\b', response):
        return True
    else:
        return False

def need_info(response):
    if re.search(r'\bNEEDINFO\b', response):
        return True
    else:
        return False

def is_trigger(output):
    pattern = r'libfuzzer exit=1'
    if re.search(pattern, output):
        return True
    else:
        return False

if __name__ == "__main__":
    file_path = "nginx-cp/src/nginx/src/http/ngx_http_request.c"
    function_name = "ngx_http_validate_from"
    function_implementation = extract_c_function(file_path, function_name)

    if function_implementation:
        print(f"Function '{function_name}' implementation:\n{function_implementation}")
    else:
        print(f"Function '{function_name}' not found.")