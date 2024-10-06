import re

# HTTP 请求示例，包括 From 头部
http_request = """plaintext
GET / HTTP/1.1
Host: localhost
From: user..user..user..user..user..user..user..user..user..user..user..user..user..user..user..user..user..user..user..user@domain.tld


"""

# 正则表达式模式，匹配HTTP请求的不同部分
http_pattern = re.compile(
    r'^(?P<method>[A-Z]+)\s(?P<path>\/\S*)\s(?P<protocol>HTTP\/\d\.\d)\r?\n'  # 请求行 (method, path, protocol)
    r'(?P<headers>(?:[a-zA-Z\-]+:\s?.*\r?\n)*)\r?\n?'  # 请求头部
    r'(?P<body>.*)?$',  # 可选的请求体
    re.DOTALL  # 允许 `.` 匹配换行符
)

# 匹配HTTP请求
match = http_pattern.match(http_request)

if match:
    # 提取请求行中的方法、路径和协议
    method = match.group('method')
    path = match.group('path')
    protocol = match.group('protocol')
    
    # 提取头部信息
    headers = match.group('headers')
    
    # 提取请求体
    body = match.group('body')
    
    # 从 headers 中匹配 From 头部字段
    from_match = re.search(r'From:\s?(?P<from>.+)\r?\n', headers)
    
    print(f"Method: {method}")
    print(f"Path: {path}")
    print(f"Protocol: {protocol}")
    print(f"Headers:\n{headers}")
    
    # 如果 From 字段存在，输出它
    if from_match:
        from_header = from_match.group('from')
        print(f"From: {from_header}")
    
    print(f"Body: {body}")
else:
    print("未能匹配到有效的HTTP请求")
