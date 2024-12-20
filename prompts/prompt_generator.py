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
        2. The vulnerability can only be the following four types:
            vulnerability_name: {vul_name}, sanitizer_name: {san_name}
        3. Each commit can only introduce one vulnerability.
        4. A vulnerability will be fully introduced by a single commit, meaning no vulnerability spans multiple commits.

        Your task is to identify if this commit introduces the given vulnerabilities, please check all + and - carefully, if one of them may introduce the vulnerability, try to think about the input to trigger it.
        Your output must be either YES, with a description or NO (indicating no vulnerability), along with the name of the problematic function (Func) and a description of the vulnerability. 

        This vulnerability is ONLY and HIGHLY related to its fuzzer's information: 
        {info_from_harness}
        """)
        
        if prev_analysis != "":
            additional_text = textwrap.dedent(f"""
            IMPORTANT this analysis is WRONG!: {prev_analysis}
            This analysis is incorrect. Please re-analyze the commit and provide the correct output.
            """)
            template += additional_text

        return PromptTemplate(input_variables=["commit_diff", "vul_name", "san_name", "info_from_harness", "prev_analysis"], template=template)
