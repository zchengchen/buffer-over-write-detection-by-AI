from langchain.prompts import PromptTemplate
import textwrap

class PromptGenerator:
    def commit_analysis_template(self, prev_analysis) -> PromptTemplate:
        # 使用 dedent 去除多余缩进
        template = textwrap.dedent("""\
        Commit diff information:
        {commit_diff}

        You are a software vulnerability detection expert, and your task is to detect vulnerabilities introduced in an Nginx project. The known information is as follows:

        1. The vulnerability can only be introduced by the parts modified (either added or removed) in the current commit.
        2. The vulnerability can only be triggered by the following sanitzers:
            sanitizers:
                id_1: "AddressSanitizer: SEGV"
                id_2: "AddressSanitizer: heap-buffer-overflow"
                id_3: "AddressSanitizer: attempting double-free"
                id_4: "AddressSanitizer: heap-use-after-free"
                id_5: "AddressSanitizer: global-buffer-overflow"
        3. Each commit can only introduce one vulnerability.
        4. A vulnerability will be fully introduced by a single commit, meaning no vulnerability spans multiple commits.

        Your task is to identify if this commit introduces the given vulnerabilities, please check all + and - carefully, if one of them may introduce the vulnerability, try to think about the input to trigger it.
        Your output must be either YES, with a description or NO (indicating no vulnerability), along with the name of the problematic function (Func) and a description of the vulnerability. 

        This vulnerability is ONLY and HIGHLY related to its fuzzer's information: 
        1. harness_pov.cc
            vulnerabilities are primarily related to the request processing chain. Throughout the HTTP request's lifecycle from reception to response, issues may arise in request method parsing, URI normalization, header key-value parsing, route rule matching, and proxy configuration forwarding. Buffer overflows, memory leaks, or logical vulnerabilities are particularly likely when handling headers of abnormal length, malformed URIs, special cookie values, complex location configurations, or multi-layer proxy forwarding.
        2. mail_request_harness.c
            vulnerabilities are mainly associated with state transitions and authentication flows. The authentication process involves interaction with the auth server (auth_http handling), authentication state validation (auth_done state), and result processing. As a stateful protocol, POP3 must strictly transition between AUTHORIZATION, TRANSACTION, and UPDATE states, each with its specific command set. Improper state transition handling or authentication flow flaws can lead to unauthorized access or state confusion.
        3. smtp_harness.c
            vulnerabilities primarily relate to command processing and session management. The SMTP server must handle a series of commands from HELO/EHLO to MAIL FROM, RCPT TO, and DATA, each with its specific format and processing logic. Session states must maintain correct transitions from connection initialization through authentication to mail transfer. Security issues can particularly arise during long mail content processing, concurrent connections, or complex authentication scenarios due to incorrect command parsing or state management.

        """)
        
        if prev_analysis != "":
            additional_text = textwrap.dedent(f"""
            IMPORTANT this analysis is WRONG!: {prev_analysis}
            This analysis is incorrect. Please re-analyze the commit and provide the correct output.
            """)
            template += additional_text

        return PromptTemplate(input_variables=["commit_diff", "prev_analysis"], template=template)
