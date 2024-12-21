from langchain.prompts import PromptTemplate
import textwrap

class PromptGenerator:
    def commit_analysis_template(self, prev_analysis, commit_diff) -> str:
        template = textwrap.dedent(f"""\
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
        If YES, please tell me which harness file (pov_harness.cc, mail_request_harness.cc or smtp_harness.c) you need to know to help you give me the blob file. Just one harness file is needed to triiger the vulnerability.

        This vulnerability is ONLY and HIGHLY related to its fuzzer's information: 
        1. pov_harness.cc
            vulnerabilities are primarily related to the request processing chain. Throughout the HTTP request's lifecycle from reception to response, issues may arise in request method parsing, URI normalization, header key-value parsing, route rule matching, and proxy configuration forwarding. Buffer overflows, memory leaks, or logical vulnerabilities are particularly likely when handling headers of abnormal length, malformed URIs, special cookie values, complex location configurations, or multi-layer proxy forwarding.
        2. mail_request_harness.cc
            vulnerabilities are mainly associated with state transitions and authentication flows. The authentication process involves interaction with the auth server (auth_http handling), authentication state validation (auth_done state), and result processing. As a stateful protocol, POP3 must strictly transition between AUTHORIZATION, TRANSACTION, and UPDATE states, each with its specific command set. Improper state transition handling or authentication flow flaws can lead to unauthorized access or state confusion.
        3. smtp_harness.cc
            vulnerabilities primarily relate to command processing and session management. The SMTP server must handle a series of commands from HELO/EHLO to MAIL FROM, RCPT TO, and DATA, each with its specific format and processing logic. Session states must maintain correct transitions from connection initialization through authentication to mail transfer. Security issues can particularly arise during long mail content processing, concurrent connections, or complex authentication scenarios due to incorrect command parsing or state management.
        """)
        
        if prev_analysis != "":
            additional_text = textwrap.dedent(f"""
            IMPORTANT this analysis is WRONG!: {prev_analysis}
            This analysis is incorrect. Please re-analyze the commit and provide the correct output.
            """)
            template += additional_text

        return template

    def give_harness_code_template(self, harnesscode) -> str:
        template = textwrap.dedent(

        )
        return template
    
    def give_function_impl_template(self, function_name) -> str:
        template = textwrap.dedent(

        )
        return template

    def ask_for_pov_template(self, harness_code) -> str:
        template = textwrap.dedent(f"""\
            Harness code:
            {harness_code}
            Now based on your analysis and harness code I given you, can you generate a test_blob.bin file that will trigger this vulnerability? If yes, please output a python file which can create a test_blob.bin file. Your blob file will be ran by a harness code I gave you.

            Your job is to find the correct input to trigger the vulnerability for better security help.
            IMPORTANT: Although you may find the correct input for the correct function, your blob may not work. Because you need to get into the function.
            Think like this:
            1. Which functions are the vulnerability in? How do you get into this function?
            2. How to trigger the vulnerability? What is the input of the function?
            3. Is there any other input that is required before reaching the target functon?
            4. All information about input driving can be found in the harness code. Read the harness code carefully and follow the instruction in the harness code to generate a blob.
            5. Combine all input to generate the test_blob.bin file. Make sure the file name is correct.

            If your blob content is not related to harness code, you are wrong. Please re-analyze the commit and provide the correct output.

            Your output must be a python code that outputs "test_blob.bin" with a short description of the vulnerability and the function name. Make sure the file name is exactly "test_blob.bin".
        """)
        return template

    def pov_failed_template(self):
        template = textwrap.dedent(r"""\
            Your blob has failed. Please help us reproduce the vulnerability for better security:

            If this code has more than one vulnerability, please make sure your target is the correct one.

            1. Review the harness.c (ask for it if you lose it), and make sure you understand how your input will be driven by the harness file. All info about input driving can be found in the harness code.
            2. Ensure that the payload is correctly sent into the function.
            3. Generate other input that will be parsed correctly and direct the payload to the vulnerable branch/function.

            If you are not 100% sure of blob generation, do not output py code. You can:
            - Ask for several function names to check.
            - Request more files you want to inspect.

            If you do not generate py code, you should start with only one function like
            Functions: {{function_name}}
            or start with only one harness code like
            Harness: {{harness_name}}

            If you can generate py code, you should start with:
            "I am `100%` sure now, all previous blobs have failed, a different python code should be generated. here is the python code.
            You MUST think about all of these issues, but do not explain them in the output. Review our history and make your decision.
        """)
        return template


    def record_aq_history(role: str, history_message: str, new_message: str) -> str:
        if history_message == None or history_message == "":
            history_message = f"{role}:\n" + new_message
        else:
            history_message += f"\n{role}:\n" + new_message
        return history_message

