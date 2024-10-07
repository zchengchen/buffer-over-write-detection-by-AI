# python3 tmp.py --commit_index 165 --func ngx_http_validate_from
from regex_tools import extract_c_function
from openai import OpenAI
from os import getenv
import json
from github_tools import search_function_in_github
import argparse
import re
import os

repo_owner = "aixcc-public"
repo_name = "challenge-004-nginx-source"
path = search_function_in_github(repo_owner, repo_name, "ngx_http_validate_from")
patch_path = os.path.join("nginx-source", path)
vulnerable_func = extract_c_function(patch_path, "ngx_http_validate_from")
# 读取 C 文件内容
with open(patch_path, 'r', encoding='utf-8') as file:
    file_content = file.read()

# 定义函数名和新的函数实现
function_name = 'ngx_http_validate_from'  # 要替换的函数名
new_function_body = r"""ngx_int_t
ngx_http_validate_from(ngx_str_t *from, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *f, *u, ch;
    size_t   i;

    enum {
        sw_begin = 0,
        sw_username,
        sw_username_dot,
        sw_domain,
        sw_tld
    } state;

    f = from->data;

    state = sw_begin;

    if (alloc) {
        // Ensure memory allocation is properly sized
        u = ngx_palloc(pool, from->len + 1); // Allocate an extra byte for null termination
        if (u == NULL) {
            return NGX_ERROR;
        }
    } else {
        u = from->data;
    }

    for (i = 0; i < from->len; i++) {
        ch = f[i];

        switch (state) {

        case sw_begin:
            if (isalnum(ch) || ch == '-' || ch == '_') {
                state = sw_username;
            } else if (ch == '.') {
                state = sw_username_dot;
            } else {
                return NGX_DECLINED;
            }
            *u++ = ch;
            break;

        case sw_username_dot:
            if (isalnum(ch) || ch == '-' || ch == '_') {
                *u++ = ch;
                state = sw_username;
            } else if (ch == '.') {
                if (u - from->data < 2) {
                    // Prevent buffer underflow when decrementing `u`
                    return NGX_DECLINED;
                }
                state = sw_username_dot;
                u -= 2;
                for ( ;; ) {
                    if (*u == '.') {
                        u++;
                        break;
                    }

                    u--;
                    if (u < from->data) { // Ensure u does not go out of bounds
                        return NGX_DECLINED;
                    }
                }
            } else {
                return NGX_DECLINED;
            }
            break;

        case sw_username:
            if (ch == '@') {
                state = sw_domain;
            } else if (ch == '.') {
                state = sw_username_dot;
            } else if (!isalnum(ch) && ch != '-' && ch != '_' && ch != '+') {
                return NGX_DECLINED;
            }
            *u++ = ch;
            break;

        case sw_domain:
            if (ch == '.') {
                state = sw_tld;
            } else if (!isalnum(ch) && ch != '-') {
                return NGX_DECLINED;
            }
            *u++ = ch;
            break;

        case sw_tld:
            if (!isalpha(ch)) {
                return NGX_DECLINED;
            }
            *u++ = ch;
            break;

        default:
            return NGX_DECLINED;
        }

        // Prevent buffer overflow by checking if we're exceeding allocated memory
        if (alloc && (size_t)(u - from->data) >= from->len) {
            return NGX_DECLINED;
        }
    }

    if (state == sw_tld) {
        *u = '\0';  // Safely null-terminate the string

        if (alloc) {
            from->data = u - from->len;  // Ensure `from->data` points to the start of the allocated buffer
        }
        return NGX_OK;
    } else {
        return NGX_DECLINED;
    }
}"""

match = re.search(re.escape(vulnerable_func), file_content)
if match:
    # 匹配前的部分
    before_match = file_content[:match.start()]
    
    # 匹配后的部分
    after_match = file_content[match.end():]

    # print("Before match:")
    # print(before_match)
    
    # print("\nAfter match:")
    # print(after_match)

    new_file = before_match + "\n" + new_function_body + after_match
    with open("new_file.c", "w") as f:
        print(new_file, file=f)
else:
    print(f"String '{target_string}' not found in the file.")
