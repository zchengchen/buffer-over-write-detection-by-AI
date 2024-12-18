from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import StrOutputParser

class ClaudeChain:
    def __init__(self, model_name="claude-3-5-sonnet-latest"):
        load_dotenv()

        self.claude = ChatAnthropic(
            model=model_name,
            temperature=0.1,
            max_tokens=8192,
            max_retries=2,
        )

        self.claude_chain = self.claude | StrOutputParser()

    def invoke(self, prompt: str) -> str:
        llm_out = self.claude_chain.invoke(prompt)
        return llm_out

if __name__ == "__main__":
    claude_chain = ClaudeChain()
    print(claude_chain.invoke("hello"))