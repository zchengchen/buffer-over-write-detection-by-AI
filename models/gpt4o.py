from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser

class GPT4oChain:
    def __init__(self, model_name="chatgpt-4o-latest"):
        load_dotenv()

        self.gpt_4o = ChatOpenAI(
            model=model_name,
            temperature=0.1,
            max_tokens=16384,
            max_retries=2,
        )

        self.gpt_4o_chain = self.gpt_4o | StrOutputParser()

    def invoke(self, prompt: str) -> str:
        llm_out = self.gpt_4o_chain.invoke(prompt)
        return llm_out

if __name__ == "__main__":
    gpt4o_chain = GPT4oChain()
    print(gpt4o_chain.invoke("hello"))